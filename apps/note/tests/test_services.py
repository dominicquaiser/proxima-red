"""Tests for the note app service layer."""

import json
from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.note import services
from apps.note.constants import (
    DEFAULT_EXPIRY,
    EXPIRY_MAP,
    MAX_VAULT_NOTES_PER_USER,
    VAULT_TRASH_RETENTION_DAYS,
)
from apps.note.models import LiveNote, LiveNoteUpdate, SharedNote, VaultIndex, VaultNote

from .factories import (
    VALID_CONTENT_B64,
    VALID_IV_B64,
    make_live_collaborator,
    make_live_note,
    make_live_update,
    make_note,
    make_restricted_live_note,
    make_vault_index,
    make_vault_note,
)


class CreateNoteTests(TestCase):
    """services.create_note: expiry mapping and persistence for both modes."""

    def test_creates_encrypted_note(self):
        note = services.create_note(
            content=VALID_CONTENT_B64, iv=VALID_IV_B64, is_encrypted=True
        )

        self.assertTrue(SharedNote.objects.filter(pk=note.pk).exists())
        self.assertTrue(note.is_encrypted)
        self.assertEqual(note.content, VALID_CONTENT_B64)

    def test_creates_plain_text_note(self):
        note = services.create_note(content="# Plain markdown", is_encrypted=False)

        self.assertFalse(note.is_encrypted)
        self.assertEqual(note.iv, "")

    def test_expiry_key_maps_to_expires_at(self):
        before = timezone.now()
        note = services.create_note(
            content=VALID_CONTENT_B64, iv=VALID_IV_B64, expiry_key="1week"
        )
        after = timezone.now()

        self.assertGreaterEqual(note.expires_at, before + EXPIRY_MAP["1week"])
        self.assertLessEqual(note.expires_at, after + EXPIRY_MAP["1week"])

    def test_unknown_expiry_key_falls_back_to_default(self):
        note = services.create_note(
            content=VALID_CONTENT_B64, iv=VALID_IV_B64, expiry_key="42years"
        )

        expected = timezone.now() + EXPIRY_MAP[DEFAULT_EXPIRY]
        self.assertLess(abs((note.expires_at - expected).total_seconds()), 5)

    def test_invalid_payload_is_rejected_before_save(self):
        with self.assertRaises(ValidationError):
            services.create_note(content="not base64!", iv=VALID_IV_B64)

        self.assertEqual(SharedNote.objects.count(), 0)


class ExpiredNoteCleanupTests(TestCase):
    """services.expired_notes / delete_expired_notes."""

    def test_delete_expired_notes_removes_only_expired_rows(self):
        expired = make_note(expires_at=timezone.now() - timedelta(minutes=1))
        active = make_note(expires_at=timezone.now() + timedelta(days=1))

        deleted = services.delete_expired_notes()

        self.assertEqual(deleted, 1)
        self.assertFalse(SharedNote.objects.filter(pk=expired.pk).exists())
        self.assertTrue(SharedNote.objects.filter(pk=active.pk).exists())

    def test_delete_expired_notes_batched_removes_all(self):
        for _ in range(5):
            make_note(expires_at=timezone.now() - timedelta(minutes=1))

        deleted = services.delete_expired_notes(batch_size=2)

        self.assertEqual(deleted, 5)
        self.assertEqual(SharedNote.objects.count(), 0)

    def test_boundary_row_counts_as_expired(self):
        """A note expiring exactly at the cutoff is included (expires_at__lte)."""
        now = timezone.now()
        note = make_note(expires_at=now)

        self.assertIn(note, services.expired_notes(now=now))


class RegisterNoteAccessTests(TestCase):
    """services.register_note_access."""

    def test_increments_access_count(self):
        note = make_note()

        services.register_note_access(note.pk)
        services.register_note_access(note.pk)

        note.refresh_from_db()
        self.assertEqual(note.access_count, 2)

    def test_unknown_pk_is_a_noop(self):
        services.register_note_access("00000000-0000-0000-0000-000000000000")


class CreateLiveNoteTests(TestCase):
    """services.create_live_note: expiry mapping and seeded persistence."""

    def test_creates_seeded_live_note(self):
        note = services.create_live_note(
            snapshot=VALID_CONTENT_B64, snapshot_iv=VALID_IV_B64
        )

        self.assertTrue(LiveNote.objects.filter(pk=note.pk).exists())
        self.assertEqual(note.snapshot_seq, 0)
        self.assertIsNone(note.created_by)
        self.assertEqual(note.updates.count(), 0)

    def test_expiry_key_maps_to_expires_at(self):
        before = timezone.now()
        note = services.create_live_note(
            snapshot=VALID_CONTENT_B64, snapshot_iv=VALID_IV_B64, expiry_key="1week"
        )
        after = timezone.now()

        self.assertGreaterEqual(note.expires_at, before + EXPIRY_MAP["1week"])
        self.assertLessEqual(note.expires_at, after + EXPIRY_MAP["1week"])

    def test_unknown_expiry_key_falls_back_to_default(self):
        note = services.create_live_note(
            snapshot=VALID_CONTENT_B64, snapshot_iv=VALID_IV_B64, expiry_key="42years"
        )

        expected = timezone.now() + EXPIRY_MAP[DEFAULT_EXPIRY]
        self.assertLess(abs((note.expires_at - expected).total_seconds()), 5)

    def test_invalid_snapshot_is_rejected_before_save(self):
        with self.assertRaises(ValidationError):
            services.create_live_note(snapshot="not base64!", snapshot_iv=VALID_IV_B64)

        self.assertEqual(LiveNote.objects.count(), 0)

    def test_created_by_is_recorded(self):
        user = create_user_with_password("password-123")
        note = services.create_live_note(
            snapshot=VALID_CONTENT_B64, snapshot_iv=VALID_IV_B64, created_by=user
        )
        self.assertEqual(note.created_by, user)


class LiveNoteStateTests(TestCase):
    """services.live_note_state: the joining client's bootstrap payload."""

    def test_state_of_freshly_seeded_note(self):
        note = make_live_note()

        state = services.live_note_state(note)

        self.assertEqual(state["snapshot"], note.snapshot)
        self.assertEqual(state["snapshot_iv"], note.snapshot_iv)
        self.assertEqual(state["updates"], [])
        self.assertEqual(state["seq"], 0)
        self.assertEqual(state["pending"], 0)
        self.assertEqual(state["expires_at"], note.expires_at.isoformat())

    def test_state_includes_tail_ascending_with_cursor(self):
        note = make_live_note()
        first = make_live_update(note)
        second = make_live_update(note)

        state = services.live_note_state(note)

        self.assertEqual([u["seq"] for u in state["updates"]], [first.pk, second.pk])
        self.assertEqual(state["updates"][0]["payload"], first.payload)
        self.assertEqual(state["updates"][0]["iv"], first.iv)
        self.assertEqual(state["seq"], second.pk)
        self.assertEqual(state["pending"], 2)


class LiveUpdatesSinceTests(TestCase):
    """services.live_updates_since: poll cursor math and the resync branch."""

    def setUp(self):
        self.note = make_live_note()

    def test_returns_rows_after_cursor(self):
        first = make_live_update(self.note)
        second = make_live_update(self.note)
        third = make_live_update(self.note)

        result = services.live_updates_since(self.note, first.pk)

        self.assertEqual([u["seq"] for u in result["updates"]], [second.pk, third.pk])
        self.assertEqual(result["seq"], third.pk)
        self.assertEqual(result["pending"], 3)
        self.assertNotIn("snapshot", result)

    def test_no_new_rows_keeps_cursor(self):
        row = make_live_update(self.note)

        result = services.live_updates_since(self.note, row.pk)

        self.assertEqual(result["updates"], [])
        self.assertEqual(result["seq"], row.pk)
        self.assertEqual(result["pending"], 1)

    def test_cursor_before_snapshot_seq_triggers_resync(self):
        """A pruned-history cursor gets the snapshot plus the entire tail."""
        stale_cursor = make_live_update(self.note).pk
        newest = make_live_update(self.note)
        services.save_live_snapshot(
            self.note.pk,
            snapshot="Y29tcGFjdGVk",
            snapshot_iv=VALID_IV_B64,
            covers_seq=newest.pk,
        )
        self.note.refresh_from_db()
        tail_row = make_live_update(self.note)

        result = services.live_updates_since(self.note, stale_cursor)

        self.assertEqual(result["snapshot"], "Y29tcGFjdGVk")
        self.assertEqual(result["snapshot_iv"], VALID_IV_B64)
        self.assertEqual([u["seq"] for u in result["updates"]], [tail_row.pk])
        self.assertEqual(result["seq"], tail_row.pk)
        self.assertEqual(result["pending"], 1)

    def test_resync_with_empty_tail_returns_snapshot_seq(self):
        newest = make_live_update(self.note)
        services.save_live_snapshot(
            self.note.pk,
            snapshot="Y29tcGFjdGVk",
            snapshot_iv=VALID_IV_B64,
            covers_seq=newest.pk,
        )
        self.note.refresh_from_db()

        result = services.live_updates_since(self.note, 0)

        self.assertIn("snapshot", result)
        self.assertEqual(result["updates"], [])
        self.assertEqual(result["seq"], newest.pk)
        self.assertEqual(result["pending"], 0)


class AppendLiveUpdateTests(TestCase):
    """services.append_live_update: locked appends and the tail caps."""

    def setUp(self):
        self.note = make_live_note()

    def test_appends_and_reports_pending(self):
        row, pending, _prev_seq = services.append_live_update(
            self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
        )

        self.assertEqual(pending, 1)
        self.assertEqual(row.note, self.note)
        _, pending, _prev_seq = services.append_live_update(
            self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
        )
        self.assertEqual(pending, 2)

    def test_prev_seq_is_snapshot_seq_for_an_empty_tail(self):
        self.note.snapshot_seq = 41
        self.note.save(update_fields=["snapshot_seq"])

        _, _, prev_seq = services.append_live_update(
            self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
        )

        self.assertEqual(prev_seq, 41)

    def test_prev_seq_chains_gaplessly_across_appends(self):
        first, _, _ = services.append_live_update(
            self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
        )
        second, _, second_prev = services.append_live_update(
            self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
        )
        third, _, third_prev = services.append_live_update(
            self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
        )

        # Row N's prev_seq is row N-1's seq: the client-side gap check
        # (prev_seq ahead of the cursor -> refetch) relies on this chain
        # having no holes.
        self.assertEqual(second_prev, first.pk)
        self.assertEqual(third_prev, second.pk)
        self.assertLess(second.pk, third.pk)

    def test_row_count_cap_raises_pending_tail_full(self):
        make_live_update(self.note)
        make_live_update(self.note)

        with patch("apps.note.services.MAX_LIVE_PENDING_UPDATES", 2):
            with self.assertRaises(ValidationError) as ctx:
                services.append_live_update(
                    self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
                )

        self.assertEqual(ctx.exception.code, "pending_tail_full")
        self.assertEqual(self.note.updates.count(), 2)

    def test_byte_cap_raises_pending_tail_full(self):
        make_live_update(self.note)

        cap = len(VALID_CONTENT_B64) + 1
        with patch("apps.note.services.MAX_LIVE_PENDING_LENGTH", cap):
            with self.assertRaises(ValidationError) as ctx:
                services.append_live_update(
                    self.note.pk, payload=VALID_CONTENT_B64, iv=VALID_IV_B64
                )

        self.assertEqual(ctx.exception.code, "pending_tail_full")

    def test_unknown_note_raises_does_not_exist(self):
        with self.assertRaises(LiveNote.DoesNotExist):
            services.append_live_update(
                "00000000-0000-0000-0000-000000000000",
                payload=VALID_CONTENT_B64,
                iv=VALID_IV_B64,
            )

    def test_invalid_payload_is_rejected_before_save(self):
        with self.assertRaises(ValidationError):
            services.append_live_update(
                self.note.pk, payload="not base64!", iv=VALID_IV_B64
            )
        self.assertEqual(self.note.updates.count(), 0)


class SaveLiveSnapshotTests(TestCase):
    """services.save_live_snapshot: compaction guards and pruning."""

    def setUp(self):
        self.note = make_live_note()

    def test_compaction_prunes_covered_rows_only(self):
        first = make_live_update(self.note)
        second = make_live_update(self.note)
        third = make_live_update(self.note)

        deleted = services.save_live_snapshot(
            self.note.pk,
            snapshot="Y29tcGFjdGVk",
            snapshot_iv=VALID_IV_B64,
            covers_seq=second.pk,
        )

        self.assertEqual(deleted, 2)
        self.note.refresh_from_db()
        self.assertEqual(self.note.snapshot, "Y29tcGFjdGVk")
        self.assertEqual(self.note.snapshot_seq, second.pk)
        remaining = list(self.note.updates.values_list("pk", flat=True))
        self.assertEqual(remaining, [third.pk])
        self.assertFalse(LiveNoteUpdate.objects.filter(pk=first.pk).exists())

    def test_stale_covers_seq_is_rejected(self):
        """A compaction losing the race changes nothing (first writer wins)."""
        newest = make_live_update(self.note)
        services.save_live_snapshot(
            self.note.pk,
            snapshot="Y29tcGFjdGVk",
            snapshot_iv=VALID_IV_B64,
            covers_seq=newest.pk,
        )

        with self.assertRaises(ValidationError) as ctx:
            services.save_live_snapshot(
                self.note.pk,
                snapshot=VALID_CONTENT_B64,
                snapshot_iv=VALID_IV_B64,
                covers_seq=newest.pk,
            )

        self.assertEqual(ctx.exception.code, "stale_snapshot")
        self.note.refresh_from_db()
        self.assertEqual(self.note.snapshot, "Y29tcGFjdGVk")

    def test_covers_seq_beyond_newest_row_is_rejected(self):
        newest = make_live_update(self.note)

        with self.assertRaises(ValidationError) as ctx:
            services.save_live_snapshot(
                self.note.pk,
                snapshot=VALID_CONTENT_B64,
                snapshot_iv=VALID_IV_B64,
                covers_seq=newest.pk + 1,
            )

        self.assertEqual(ctx.exception.code, "covers_unknown_updates")
        self.note.refresh_from_db()
        self.assertEqual(self.note.snapshot_seq, 0)

    def test_empty_tail_rejects_any_new_covers_seq(self):
        with self.assertRaises(ValidationError) as ctx:
            services.save_live_snapshot(
                self.note.pk,
                snapshot=VALID_CONTENT_B64,
                snapshot_iv=VALID_IV_B64,
                covers_seq=1,
            )
        self.assertEqual(ctx.exception.code, "covers_unknown_updates")

    def test_invalid_snapshot_rolls_back(self):
        newest = make_live_update(self.note)

        with self.assertRaises(ValidationError):
            services.save_live_snapshot(
                self.note.pk,
                snapshot="not base64!",
                snapshot_iv=VALID_IV_B64,
                covers_seq=newest.pk,
            )

        self.note.refresh_from_db()
        self.assertEqual(self.note.snapshot_seq, 0)
        self.assertEqual(self.note.updates.count(), 1)

    def test_stale_key_epoch_cannot_replace_the_snapshot(self):
        """A client on a pre-rekey key must not overwrite the document.

        The append path rejects a stale epoch because the row would be
        unreadable; here the stakes are higher, since a snapshot *replaces*
        the document and prunes the tail with it.
        """
        rekeyed = make_live_note(key_epoch=3)
        newest = make_live_update(rekeyed)

        with self.assertRaises(ValidationError) as ctx:
            services.save_live_snapshot(
                rekeyed.pk,
                snapshot="b2xka2V5c25hcHNob3Q=",
                snapshot_iv=VALID_IV_B64,
                covers_seq=newest.pk,
                key_epoch=0,
            )

        self.assertEqual(ctx.exception.code, "stale_epoch")
        rekeyed.refresh_from_db()
        self.assertEqual(rekeyed.snapshot, VALID_CONTENT_B64)
        self.assertEqual(rekeyed.snapshot_seq, 0)
        self.assertEqual(rekeyed.updates.count(), 1)

    def test_stale_epoch_is_reported_before_a_lost_race(self):
        """stale_epoch outranks stale_snapshot: the client must recover, not retry."""
        rekeyed = make_live_note(key_epoch=2)
        newest = make_live_update(rekeyed)
        services.save_live_snapshot(
            rekeyed.pk,
            snapshot="Y29tcGFjdGVk",
            snapshot_iv=VALID_IV_B64,
            covers_seq=newest.pk,
            key_epoch=2,
        )

        with self.assertRaises(ValidationError) as ctx:
            services.save_live_snapshot(
                rekeyed.pk,
                snapshot=VALID_CONTENT_B64,
                snapshot_iv=VALID_IV_B64,
                covers_seq=newest.pk,
                key_epoch=0,
            )

        self.assertEqual(ctx.exception.code, "stale_epoch")

    def test_current_key_epoch_compacts_normally(self):
        rekeyed = make_live_note(key_epoch=5)
        newest = make_live_update(rekeyed)

        deleted = services.save_live_snapshot(
            rekeyed.pk,
            snapshot="Y29tcGFjdGVk",
            snapshot_iv=VALID_IV_B64,
            covers_seq=newest.pk,
            key_epoch=5,
        )

        self.assertEqual(deleted, 1)
        rekeyed.refresh_from_db()
        self.assertEqual(rekeyed.snapshot, "Y29tcGFjdGVk")
        self.assertEqual(rekeyed.key_epoch, 5)


class ExpiredLiveNoteCleanupTests(TestCase):
    """services.expired_live_notes / delete_expired_live_notes."""

    def test_delete_expired_removes_only_expired_rows(self):
        expired = make_live_note(expires_at=timezone.now() - timedelta(minutes=1))
        active = make_live_note(expires_at=timezone.now() + timedelta(days=1))

        deleted = services.delete_expired_live_notes()

        self.assertEqual(deleted, 1)
        self.assertFalse(LiveNote.objects.filter(pk=expired.pk).exists())
        self.assertTrue(LiveNote.objects.filter(pk=active.pk).exists())

    def test_update_rows_cascade_without_inflating_the_count(self):
        expired = make_live_note(expires_at=timezone.now() - timedelta(minutes=1))
        make_live_update(expired)
        make_live_update(expired)

        deleted = services.delete_expired_live_notes(batch_size=10)

        self.assertEqual(deleted, 1)
        self.assertEqual(LiveNoteUpdate.objects.count(), 0)

    def test_batched_delete_removes_all(self):
        for _ in range(5):
            make_live_note(expires_at=timezone.now() - timedelta(minutes=1))

        deleted = services.delete_expired_live_notes(batch_size=2)

        self.assertEqual(deleted, 5)
        self.assertEqual(LiveNote.objects.count(), 0)

    def test_boundary_row_counts_as_expired(self):
        now = timezone.now()
        note = make_live_note(expires_at=now)

        self.assertIn(note, services.expired_live_notes(now=now))


class VaultIndexServiceTests(TestCase):
    """services.get_vault_index / save_vault_index / serialize_vault_index."""

    def setUp(self):
        self.user = create_user_with_password("password-123")

    def test_get_without_index_returns_none(self):
        self.assertIsNone(services.get_vault_index(self.user))

    def test_save_creates_then_updates(self):
        services.save_vault_index(self.user, VALID_CONTENT_B64, VALID_IV_B64)
        self.assertEqual(VaultIndex.objects.count(), 1)

        services.save_vault_index(self.user, "bmV3aW5kZXg=", VALID_IV_B64)
        self.assertEqual(VaultIndex.objects.count(), 1)
        self.assertEqual(
            services.get_vault_index(self.user),
            {"encrypted_data": "bmV3aW5kZXg=", "iv": VALID_IV_B64},
        )

    def test_save_validates_payload(self):
        with self.assertRaises(ValidationError):
            services.save_vault_index(self.user, "not base64!!", VALID_IV_B64)
        self.assertFalse(VaultIndex.objects.exists())

    def test_serialize_includes_updated_at_on_request(self):
        index = make_vault_index(self.user)
        payload = services.serialize_vault_index(index, include_updated_at=True)
        self.assertEqual(payload["updated_at"], index.updated_at.isoformat())


class VaultNoteServiceTests(TestCase):
    """The owner-scoped vault note CRUD services."""

    def setUp(self):
        self.user = create_user_with_password("password-123")
        self.other = create_user_with_password("other-password")

    def test_create_vault_note(self):
        note = services.create_vault_note(
            self.user, content=VALID_CONTENT_B64, iv=VALID_IV_B64
        )
        self.assertTrue(VaultNote.objects.filter(pk=note.pk, user=self.user).exists())

    def test_create_enforces_quota(self):
        for _ in range(MAX_VAULT_NOTES_PER_USER):
            make_vault_note(self.user)
        with self.assertRaises(ValidationError) as ctx:
            services.create_vault_note(
                self.user, content=VALID_CONTENT_B64, iv=VALID_IV_B64
            )
        self.assertEqual(ctx.exception.code, "note_quota")

    def test_quota_is_per_user(self):
        for _ in range(MAX_VAULT_NOTES_PER_USER):
            make_vault_note(self.other)
        note = services.create_vault_note(
            self.user, content=VALID_CONTENT_B64, iv=VALID_IV_B64
        )
        self.assertIsNotNone(note.pk)

    def test_get_is_owner_scoped(self):
        note = make_vault_note(self.other)
        self.assertIsNone(services.get_vault_note(self.user, note.pk))
        self.assertEqual(services.get_vault_note(self.other, note.pk), note)

    def test_get_tolerates_malformed_uuid(self):
        self.assertIsNone(services.get_vault_note(self.user, "not-a-uuid"))

    def test_update_is_owner_scoped(self):
        note = make_vault_note(self.other)
        result = services.update_vault_note(
            self.user, note.pk, content="c3RvbGVu", iv=VALID_IV_B64
        )
        self.assertIsNone(result)
        note.refresh_from_db()
        self.assertEqual(note.content, VALID_CONTENT_B64)

    def test_delete_is_owner_scoped_and_idempotent(self):
        note = make_vault_note(self.other)
        self.assertFalse(services.delete_vault_note(self.user, note.pk))
        self.assertTrue(services.delete_vault_note(self.other, note.pk))
        self.assertFalse(services.delete_vault_note(self.other, note.pk))

    def test_list_orders_and_scopes(self):
        make_vault_note(self.other)
        first = make_vault_note(self.user)
        second = make_vault_note(self.user)

        listed = services.list_vault_notes(self.user)
        self.assertEqual(
            [entry["id"] for entry in listed], [str(second.id), str(first.id)]
        )
        self.assertNotIn("content", listed[0])

        with_content = services.list_vault_notes(self.user, include_content=True)
        self.assertEqual(with_content[0]["content"], VALID_CONTENT_B64)

    def test_serialize_exposes_trash_state(self):
        note = make_vault_note(self.user)
        self.assertIsNone(services.serialize_vault_note(note)["trashed_at"])

        services.set_vault_notes_trashed(self.user, [note.pk], trashed=True)
        note.refresh_from_db()
        self.assertEqual(
            services.serialize_vault_note(note)["trashed_at"],
            note.trashed_at.isoformat(),
        )


class SetVaultNotesTrashedTests(TestCase):
    """services.set_vault_notes_trashed: the bulk Trash flag."""

    def setUp(self):
        self.user = create_user_with_password("password-123")
        self.other = create_user_with_password("other-password")

    def test_sets_and_clears_the_flag_in_bulk(self):
        first = make_vault_note(self.user)
        second = make_vault_note(self.user)

        updated = services.set_vault_notes_trashed(
            self.user, [first.pk, second.pk], trashed=True
        )

        self.assertEqual(updated, 2)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNotNone(first.trashed_at)
        self.assertIsNotNone(second.trashed_at)

        services.set_vault_notes_trashed(self.user, [first.pk], trashed=False)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertIsNone(first.trashed_at)
        self.assertIsNotNone(second.trashed_at)

    def test_does_not_bump_updated_at(self):
        note = make_vault_note(self.user)
        before = note.updated_at

        services.set_vault_notes_trashed(self.user, [note.pk], trashed=True)

        note.refresh_from_db()
        self.assertEqual(note.updated_at, before)

    def test_is_owner_scoped(self):
        note = make_vault_note(self.other)

        updated = services.set_vault_notes_trashed(self.user, [note.pk], trashed=True)

        self.assertEqual(updated, 0)
        note.refresh_from_db()
        self.assertIsNone(note.trashed_at)

    def test_tolerates_malformed_and_unknown_ids(self):
        note = make_vault_note(self.user)

        updated = services.set_vault_notes_trashed(
            self.user,
            ["not-a-uuid", "11111111-1111-1111-1111-111111111111", note.pk],
            trashed=True,
        )

        self.assertEqual(updated, 1)

    def test_empty_id_list_is_a_noop(self):
        updated = services.set_vault_notes_trashed(self.user, [], trashed=True)
        self.assertEqual(updated, 0)


class ExpiredTrashedVaultNoteTests(TestCase):
    """The retention sweep over trashed vault notes."""

    def setUp(self):
        self.user = create_user_with_password("password-123")
        self.now = timezone.now()
        self.window = timedelta(days=VAULT_TRASH_RETENTION_DAYS)

    def test_active_notes_never_expire(self):
        make_vault_note(self.user)
        self.assertEqual(services.expired_trashed_vault_notes(now=self.now).count(), 0)

    def test_recently_trashed_notes_are_kept(self):
        make_vault_note(
            self.user, trashed_at=self.now - self.window + timedelta(hours=1)
        )
        self.assertEqual(services.expired_trashed_vault_notes(now=self.now).count(), 0)

    def test_a_note_exactly_at_the_cutoff_is_due(self):
        note = make_vault_note(self.user, trashed_at=self.now - self.window)
        self.assertEqual(
            list(services.expired_trashed_vault_notes(now=self.now)), [note]
        )

    def test_delete_removes_only_due_notes(self):
        due = make_vault_note(self.user, trashed_at=self.now - self.window)
        recent = make_vault_note(self.user, trashed_at=self.now)
        active = make_vault_note(self.user)

        deleted = services.delete_expired_trashed_vault_notes(now=self.now)

        self.assertEqual(deleted, 1)
        self.assertFalse(VaultNote.objects.filter(pk=due.pk).exists())
        self.assertTrue(VaultNote.objects.filter(pk=recent.pk).exists())
        self.assertTrue(VaultNote.objects.filter(pk=active.pk).exists())

    def test_delete_in_batches(self):
        for _ in range(3):
            make_vault_note(self.user, trashed_at=self.now - self.window)

        deleted = services.delete_expired_trashed_vault_notes(
            now=self.now, batch_size=2
        )

        self.assertEqual(deleted, 3)
        self.assertEqual(VaultNote.objects.count(), 0)


class MigrateVaultDataTests(TestCase):
    """services.migrate_vault_data: the transactional re-encryption batch."""

    def setUp(self):
        self.user = create_user_with_password("password-123")

    def test_migrates_notes_and_index(self):
        note = make_vault_note(self.user)
        make_vault_index(self.user)

        migrated = services.migrate_vault_data(
            self.user,
            notes=[{"id": str(note.id), "content": "bmV3", "iv": VALID_IV_B64}],
            index_payload={"encrypted_data": "bmV3aW5kZXg=", "iv": VALID_IV_B64},
        )

        self.assertEqual(migrated, 1)
        note.refresh_from_db()
        self.assertEqual(note.content, "bmV3")
        self.assertEqual(
            VaultIndex.objects.get(user=self.user).encrypted_data, "bmV3aW5kZXg="
        )

    def test_unknown_id_rolls_back_batch(self):
        note = make_vault_note(self.user)
        with self.assertRaises(ValidationError):
            services.migrate_vault_data(
                self.user,
                notes=[
                    {"id": str(note.id), "content": "bmV3", "iv": VALID_IV_B64},
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "content": "eA==",
                        "iv": VALID_IV_B64,
                    },
                ],
            )
        note.refresh_from_db()
        self.assertEqual(note.content, VALID_CONTENT_B64)

    def test_invalid_payload_rolls_back_batch(self):
        note = make_vault_note(self.user)
        with self.assertRaises(ValidationError):
            services.migrate_vault_data(
                self.user,
                notes=[
                    {"id": str(note.id), "content": "not base64!!", "iv": VALID_IV_B64}
                ],
            )
        note.refresh_from_db()
        self.assertEqual(note.content, VALID_CONTENT_B64)


class BuildNoteVaultExportTests(TestCase):
    """services.build_note_vault_export for the GDPR account export."""

    def setUp(self):
        self.user = create_user_with_password("password-123")

    def test_empty_vault(self):
        export = services.build_note_vault_export(self.user)
        self.assertIsNone(export["index"])
        self.assertEqual(export["notes"], [])

    def test_includes_index_and_note_ciphertext(self):
        note = make_vault_note(self.user)
        make_vault_index(self.user)

        export = services.build_note_vault_export(self.user)

        self.assertEqual(export["index"]["encrypted_data"], VALID_CONTENT_B64)
        self.assertIn("updated_at", export["index"])
        self.assertEqual(export["notes"][0]["id"], str(note.id))
        self.assertEqual(export["notes"][0]["content"], VALID_CONTENT_B64)


class BuildNoteExportTests(TestCase):
    """services.build_note_export: the note tool's non-vault GDPR sections."""

    def setUp(self):
        self.user = create_user_with_password("password-123")

    def test_empty_account(self):
        export = services.build_note_export(self.user)
        self.assertEqual(export["shared_notes"], [])
        self.assertEqual(export["live_notes"], [])
        self.assertEqual(export["live_note_collaborations"], [])

    def test_includes_shared_notes_with_ciphertext(self):
        note = make_note(created_by=self.user)
        export = services.build_note_export(self.user)

        self.assertEqual(len(export["shared_notes"]), 1)
        row = export["shared_notes"][0]
        self.assertEqual(row["id"], str(note.id))
        self.assertEqual(row["content"], VALID_CONTENT_B64)
        self.assertTrue(row["is_encrypted"])

    def test_live_note_carries_its_pending_tail_as_well_as_the_snapshot(self):
        """Snapshot alone is the document as of the last compaction.

        Shipping it without the tail would hand the user a knowingly stale
        copy of their own document.
        """
        note = make_live_note(created_by=self.user)
        first = make_live_update(note)
        second = make_live_update(note)

        export = services.build_note_export(self.user)

        row = export["live_notes"][0]
        self.assertEqual(row["id"], str(note.id))
        self.assertEqual(row["snapshot"], VALID_CONTENT_B64)
        self.assertEqual(
            [u["seq"] for u in row["pending_updates"]], [first.pk, second.pk]
        )

    def test_collaboration_grants_include_this_users_own_wrap(self):
        owner = create_user_with_password("owner secret")
        note = make_restricted_live_note(owner)
        make_live_collaborator(note, self.user)

        export = services.build_note_export(self.user)

        self.assertEqual(len(export["live_note_collaborations"]), 1)
        grant = export["live_note_collaborations"][0]
        self.assertEqual(grant["note_id"], str(note.id))
        self.assertEqual(grant["role"], "editor")
        self.assertEqual(grant["wrapped_key"], VALID_CONTENT_B64)

    def test_other_collaborators_ids_are_not_disclosed_to_the_owner(self):
        """Art. 15(4): an export must not hand over other people's data.

        The owner can see collaborator ids live in the management panel, but a
        downloadable file is a different distribution surface.
        """
        someone_else = create_user_with_password("editor secret")
        note = make_restricted_live_note(self.user)
        make_live_collaborator(note, someone_else)

        export = services.build_note_export(self.user)

        serialized = json.dumps(export)
        self.assertNotIn(someone_else.user_id, serialized)
        # The owner's own grant on that note is still theirs to have.
        self.assertEqual(len(export["live_note_collaborations"]), 1)

    def test_anonymous_and_foreign_rows_are_excluded(self):
        make_note()  # anonymous
        make_live_note()  # anonymous
        other = create_user_with_password("other secret")
        make_note(created_by=other)

        export = services.build_note_export(self.user)

        self.assertEqual(export["shared_notes"], [])
        self.assertEqual(export["live_notes"], [])
