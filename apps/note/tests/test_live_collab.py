"""
Tests for M4 named collaborators on live notes: the restrict/invite/rekey
services (atomicity, epoch discipline) and the endpoint gating matrix
(restricted docs need a session + a collaborator row; owner actions need the
owner role; link-mode docs are unchanged).
"""

import json
from unittest.mock import patch

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import Client, TestCase
from django.urls import reverse

from apps.auth.tests.factories import create_user_with_password
from apps.note import services
from apps.note.models import LiveNote, LiveNoteCollaborator, LiveNoteUpdate

from .factories import (
    VALID_CONTENT_B64,
    VALID_EPHEMERAL_KEY_B64,
    VALID_IV_B64,
    make_live_collaborator,
    make_live_note,
    make_live_update,
    make_restricted_live_note,
)

AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}


def _wrap(user_id=None):
    payload = {
        "wrapped_key": VALID_CONTENT_B64,
        "wrap_iv": VALID_IV_B64,
        "ephemeral_public_key": VALID_EPHEMERAL_KEY_B64,
    }
    if user_id is not None:
        payload["user_id"] = user_id
    return payload


class RestrictServiceTests(TestCase):
    def setUp(self):
        self.owner = create_user_with_password("owner secret")
        self.note = make_live_note(created_by=self.owner)

    def test_restrict_creates_owner_grant_and_flips_mode(self):
        services.restrict_live_note(self.note.pk, owner_user=self.owner, wrap=_wrap())
        self.note.refresh_from_db()
        self.assertEqual(self.note.access_mode, LiveNote.ACCESS_RESTRICTED)
        owner_row = services.get_live_collaborator(self.note, self.owner.user_id)
        self.assertEqual(owner_row.role, LiveNoteCollaborator.ROLE_OWNER)

    def test_only_creator_may_restrict(self):
        stranger = create_user_with_password("stranger secret")
        with self.assertRaises(ValidationError) as ctx:
            services.restrict_live_note(self.note.pk, owner_user=stranger, wrap=_wrap())
        self.assertEqual(ctx.exception.code, "not_owner")

    def test_double_restrict_rejected(self):
        services.restrict_live_note(self.note.pk, owner_user=self.owner, wrap=_wrap())
        with self.assertRaises(ValidationError) as ctx:
            services.restrict_live_note(
                self.note.pk, owner_user=self.owner, wrap=_wrap()
            )
        self.assertEqual(ctx.exception.code, "already_restricted")


class InviteServiceTests(TestCase):
    def setUp(self):
        self.owner = create_user_with_password("owner secret")
        self.note = make_restricted_live_note(self.owner)
        self.invitee = create_user_with_password("invitee secret")

    def test_add_collaborator(self):
        services.add_live_collaborator(
            self.note.pk,
            owner_user=self.owner,
            invitee_user_id=self.invitee.user_id,
            wrap=_wrap(),
        )
        row = services.get_live_collaborator(self.note, self.invitee.user_id)
        self.assertEqual(row.role, LiveNoteCollaborator.ROLE_EDITOR)
        self.assertEqual(row.key_epoch, self.note.key_epoch)

    def test_non_owner_cannot_invite(self):
        editor = create_user_with_password("editor secret")
        make_live_collaborator(self.note, editor)
        with self.assertRaises(ValidationError) as ctx:
            services.add_live_collaborator(
                self.note.pk,
                owner_user=editor,
                invitee_user_id=self.invitee.user_id,
                wrap=_wrap(),
            )
        self.assertEqual(ctx.exception.code, "not_owner")

    def test_collaborator_limit(self):
        with self.settings():
            from unittest.mock import patch

            with patch("apps.note.services.MAX_COLLABORATORS_PER_NOTE", 1):
                # Owner already occupies the single slot.
                with self.assertRaises(ValidationError) as ctx:
                    services.add_live_collaborator(
                        self.note.pk,
                        owner_user=self.owner,
                        invitee_user_id=self.invitee.user_id,
                        wrap=_wrap(),
                    )
        self.assertEqual(ctx.exception.code, "collab_limit")


class RekeyServiceTests(TestCase):
    def setUp(self):
        self.owner = create_user_with_password("owner secret")
        self.note = make_restricted_live_note(self.owner)
        self.editor = create_user_with_password("editor secret")
        make_live_collaborator(self.note, self.editor)

    def test_revoke_rotates_key_prunes_tail_and_rewraps(self):
        make_live_update(self.note)
        newest = make_live_update(self.note)

        new_epoch = services.rekey_live_note(
            self.note.pk,
            owner_user=self.owner,
            snapshot="bmV3c25hcA==",
            snapshot_iv=VALID_IV_B64,
            covers_seq=newest.pk,
            key_epoch=1,
            remove_user_id=self.editor.user_id,
            wraps=[_wrap(self.owner.user_id)],
        )

        self.assertEqual(new_epoch, 1)
        self.note.refresh_from_db()
        self.assertEqual(self.note.key_epoch, 1)
        self.assertEqual(self.note.snapshot, "bmV3c25hcA==")
        self.assertEqual(self.note.snapshot_seq, newest.pk)
        # Entire old-key tail gone; revoked collaborator gone; owner re-wrapped.
        self.assertEqual(LiveNoteUpdate.objects.filter(note=self.note).count(), 0)
        self.assertIsNone(
            services.get_live_collaborator(self.note, self.editor.user_id)
        )
        owner_row = services.get_live_collaborator(self.note, self.owner.user_id)
        self.assertEqual(owner_row.key_epoch, 1)

    def test_covers_seq_must_equal_newest_tail_id(self):
        first = make_live_update(self.note)
        make_live_update(self.note)  # a newer row the snapshot would miss
        with self.assertRaises(ValidationError) as ctx:
            services.rekey_live_note(
                self.note.pk,
                owner_user=self.owner,
                snapshot="bmV3c25hcA==",
                snapshot_iv=VALID_IV_B64,
                covers_seq=first.pk,  # not the newest -> mixed-key log
                key_epoch=1,
                remove_user_id=self.editor.user_id,
                wraps=[_wrap(self.owner.user_id)],
            )
        self.assertEqual(ctx.exception.code, "rekey_stale")
        self.note.refresh_from_db()
        self.assertEqual(self.note.key_epoch, 0)  # unchanged

    def test_epoch_must_be_exactly_next(self):
        with self.assertRaises(ValidationError) as ctx:
            services.rekey_live_note(
                self.note.pk,
                owner_user=self.owner,
                snapshot="bmV3c25hcA==",
                snapshot_iv=VALID_IV_B64,
                covers_seq=self.note.snapshot_seq,
                key_epoch=5,  # not current + 1
                remove_user_id=self.editor.user_id,
                wraps=[_wrap(self.owner.user_id)],
            )
        self.assertEqual(ctx.exception.code, "rekey_epoch")

    def test_wraps_must_cover_exactly_the_survivors(self):
        # Missing the owner's wrap after removing the editor.
        with self.assertRaises(ValidationError) as ctx:
            services.rekey_live_note(
                self.note.pk,
                owner_user=self.owner,
                snapshot="bmV3c25hcA==",
                snapshot_iv=VALID_IV_B64,
                covers_seq=self.note.snapshot_seq,
                key_epoch=1,
                remove_user_id=self.editor.user_id,
                wraps=[],
            )
        self.assertEqual(ctx.exception.code, "wraps_mismatch")


class AccessChangeBroadcastTests(TestCase):
    """Narrowing access must reach the sockets already inside the group.

    The consumer's gate runs once, at connect, so restrict and rekey publish a
    ``live.access`` event that makes every open socket re-check itself (the
    handler's own behaviour is covered in test_consumers). Here: that the two
    narrowing paths publish it, that the widening ones don't, and that it
    lands after the commit rather than inside the transaction.
    """

    def setUp(self):
        self.owner = create_user_with_password("owner secret")
        self.editor = create_user_with_password("editor secret")

    def test_restrict_broadcasts_after_commit(self):
        note = make_live_note(created_by=self.owner)

        with patch.object(services, "broadcast_live_access_change") as broadcast:
            with self.captureOnCommitCallbacks(execute=True):
                services.restrict_live_note(
                    note.pk, owner_user=self.owner, wrap=_wrap()
                )
                # Still inside the transaction: consumers re-read the gate
                # from the database, so publishing here would race them
                # against a grant that is not visible yet.
                broadcast.assert_not_called()

        broadcast.assert_called_once_with(note.pk)

    def test_rekey_broadcasts_after_commit(self):
        note = make_restricted_live_note(self.owner)
        make_live_collaborator(note, self.editor)
        newest = make_live_update(note)

        with patch.object(services, "broadcast_live_access_change") as broadcast:
            with self.captureOnCommitCallbacks(execute=True):
                services.rekey_live_note(
                    note.pk,
                    owner_user=self.owner,
                    snapshot="bmV3c25hcA==",
                    snapshot_iv=VALID_IV_B64,
                    covers_seq=newest.pk,
                    key_epoch=1,
                    remove_user_id=self.editor.user_id,
                    wraps=[_wrap(self.owner.user_id)],
                )
                broadcast.assert_not_called()

        broadcast.assert_called_once_with(note.pk)

    def test_widening_access_broadcasts_nothing(self):
        """Inviting and unrestricting strand nobody, so evict nobody."""
        note = make_restricted_live_note(self.owner)

        with patch.object(services, "broadcast_live_access_change") as broadcast:
            with self.captureOnCommitCallbacks(execute=True):
                services.add_live_collaborator(
                    note.pk,
                    owner_user=self.owner,
                    invitee_user_id=self.editor.user_id,
                    wrap=_wrap(),
                )
                services.unrestrict_live_note(note.pk, owner_user=self.owner)

        broadcast.assert_not_called()

    def test_broadcast_failure_does_not_break_the_revocation(self):
        """A channel-layer outage must never fail the access change itself."""
        note = make_live_note(created_by=self.owner)

        with patch.object(
            services, "get_channel_layer", side_effect=RuntimeError("redis down")
        ):
            with self.captureOnCommitCallbacks(execute=True):
                services.restrict_live_note(
                    note.pk, owner_user=self.owner, wrap=_wrap()
                )

        note.refresh_from_db()
        self.assertEqual(note.access_mode, LiveNote.ACCESS_RESTRICTED)


class AppendEpochTests(TestCase):
    def test_append_rejects_stale_epoch(self):
        owner = create_user_with_password("owner secret")
        note = make_restricted_live_note(owner)
        note.key_epoch = 2
        note.save(update_fields=["key_epoch"])

        with self.assertRaises(ValidationError) as ctx:
            services.append_live_update(
                note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64, key_epoch=1
            )
        self.assertEqual(ctx.exception.code, "stale_epoch")

    def test_link_note_append_ignores_epoch_default(self):
        note = make_live_note()  # link mode, epoch 0
        row, pending, _prev = services.append_live_update(
            note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
        )
        self.assertEqual(pending, 1)
        self.assertEqual(row.note_id, note.pk)


class LiveGatingViewTests(TestCase):
    """The restricted-access gating matrix on the live JSON endpoints."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.owner = create_user_with_password("owner secret")
        self.editor = create_user_with_password("editor secret")
        self.note = make_restricted_live_note(self.owner)
        make_live_collaborator(self.note, self.editor)

    def _auth(self, user):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = user.user_id
        session.save()

    def test_state_requires_session_on_restricted_note(self):
        response = self.client.get(
            reverse("note:live_state", args=[self.note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 401)

    def test_state_403_style_404_for_non_collaborator(self):
        stranger = create_user_with_password("stranger secret")
        self._auth(stranger)
        response = self.client.get(
            reverse("note:live_state", args=[self.note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 404)

    def test_collaborator_can_read_state(self):
        self._auth(self.editor)
        response = self.client.get(
            reverse("note:live_state", args=[self.note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["key_epoch"], 0)

    def test_link_note_state_stays_anonymous(self):
        link_note = make_live_note()
        response = self.client.get(
            reverse("note:live_state", args=[link_note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 200)

    def test_key_endpoint_returns_wrap_for_collaborator(self):
        self._auth(self.editor)
        response = self.client.get(
            reverse("note:live_key", args=[self.note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["wrapped_key"], VALID_CONTENT_B64)
        self.assertEqual(body["key_epoch"], 0)

    def test_key_endpoint_404_for_non_collaborator(self):
        stranger = create_user_with_password("stranger secret")
        self._auth(stranger)
        response = self.client.get(
            reverse("note:live_key", args=[self.note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 404)

    def test_collaborators_list_is_owner_only(self):
        self._auth(self.editor)
        response = self.client.get(
            reverse("note:live_collaborators", args=[self.note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 403)

        self._auth(self.owner)
        response = self.client.get(
            reverse("note:live_collaborators", args=[self.note.pk]), **AJAX
        )
        self.assertEqual(response.status_code, 200)
        user_ids = {c["user_id"] for c in response.json()["collaborators"]}
        self.assertEqual(user_ids, {self.owner.user_id, self.editor.user_id})


class LiveRestrictViewTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.owner = create_user_with_password("owner secret")
        self.note = make_live_note(created_by=self.owner)

    def _auth(self, user):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = user.user_id
        session.save()

    def _post(self, url, payload):
        return self.client.post(
            url, json.dumps(payload), content_type="application/json", **AJAX
        )

    def test_owner_can_restrict_then_link_note_becomes_gated(self):
        self._auth(self.owner)
        response = self._post(
            reverse("note:live_access", args=[self.note.pk]),
            {"restrict": True, **_wrap()},
        )
        self.assertEqual(response.status_code, 200)
        self.note.refresh_from_db()
        self.assertEqual(self.note.access_mode, LiveNote.ACCESS_RESTRICTED)

        # A now-restricted note refuses anonymous state reads.
        anon = Client()
        state = anon.get(reverse("note:live_state", args=[self.note.pk]), **AJAX)
        self.assertEqual(state.status_code, 401)

    def test_non_creator_cannot_restrict(self):
        stranger = create_user_with_password("stranger secret")
        self._auth(stranger)
        response = self._post(
            reverse("note:live_access", args=[self.note.pk]),
            {"restrict": True, **_wrap()},
        )
        self.assertEqual(response.status_code, 403)
