"""
Tests for the live-note (editable share link) views.

The JSON sync endpoints live on collision-free literal paths that match on
every host (like the vault APIs), so they are exercised on the default test
host. Only the live HTML page is host-gated to the note subdomain, mirroring
how ``/<uuid>/`` retrieves are split between the tools.
"""

import json
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.note.constants import (
    ERROR_LIVE_STALE_SNAPSHOT,
    ERROR_LIVE_TAIL_FULL,
    RATE_LIMIT_LIVE_SNAPSHOT,
)
from apps.note.models import LiveNote, LiveNoteUpdate

from .factories import (
    VALID_CONTENT_B64,
    VALID_IV_B64,
    make_live_note,
    make_live_update,
    make_restricted_live_note,
)

AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}
NOTE_HOST = {"HTTP_HOST": "note.proxima.red"}
PASS_HOST = {"HTTP_HOST": "pass.proxima.red"}
MAIN_HOST = {"HTTP_HOST": "proxima.red"}

MULTI_HOST_SETTINGS = dict(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    NOTE_SITE_URL="https://note.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "note.proxima.red", "testserver"],
)


class LiveViewTestCase(TestCase):
    """Shared plumbing: fresh rate-limit buckets and a JSON post helper."""

    def setUp(self):
        self.client = Client()
        cache.clear()  # reset rate-limit counters between tests

    def _post_json(self, url, payload, **extra):
        return self.client.post(
            url, json.dumps(payload), content_type="application/json", **AJAX, **extra
        )

    def _authenticate(self):
        user = create_user_with_password("password-123")
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = user.user_id
        session.save()
        return user


class CreateLiveNoteViewTests(LiveViewTestCase):
    """POST /live/: JSON-bodied anonymous creation."""

    def test_creates_live_note_with_expiry(self):
        response = self._post_json(
            reverse("note:live_create"),
            {
                "snapshot": VALID_CONTENT_B64,
                "snapshot_iv": VALID_IV_B64,
                "expiry_time": "1hour",
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        note = LiveNote.objects.get(pk=payload["note_id"])
        self.assertEqual(note.snapshot, VALID_CONTENT_B64)
        self.assertEqual(note.snapshot_seq, 0)
        self.assertIsNone(note.created_by)
        self.assertLessEqual(
            note.expires_at, timezone.now() + timedelta(hours=1, minutes=1)
        )
        self.assertEqual(payload["expires_at"], note.expires_at.isoformat())

    def test_authenticated_creator_is_recorded(self):
        user = self._authenticate()

        response = self._post_json(
            reverse("note:live_create"),
            {"snapshot": VALID_CONTENT_B64, "snapshot_iv": VALID_IV_B64},
        )

        note = LiveNote.objects.get(pk=response.json()["note_id"])
        self.assertEqual(note.created_by, user)

    def test_missing_fields_rejected(self):
        response = self._post_json(
            reverse("note:live_create"), {"snapshot": VALID_CONTENT_B64}
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(LiveNote.objects.count(), 0)

    def test_invalid_json_body_rejected(self):
        response = self.client.post(
            reverse("note:live_create"),
            "not json",
            content_type="application/json",
            **AJAX,
        )
        self.assertEqual(response.status_code, 400)

    def test_non_base64_snapshot_rejected(self):
        response = self._post_json(
            reverse("note:live_create"),
            {"snapshot": "not base64!", "snapshot_iv": VALID_IV_B64},
        )
        self.assertEqual(response.status_code, 400)

    def test_get_not_allowed(self):
        response = self.client.get(reverse("note:live_create"))
        self.assertEqual(response.status_code, 405)


@override_settings(**MULTI_HOST_SETTINGS)
class LiveNotePageViewTests(LiveViewTestCase):
    """GET /live/<uuid>/: host-gated HTML shell."""

    def test_renders_shell_on_note_host(self):
        note = make_live_note()

        response = self.client.get(reverse("note:live", args=[note.id]), **NOTE_HOST)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "note/live.html")
        self.assertContains(response, "data-state-url")
        self.assertContains(response, "data-updates-url")
        self.assertContains(response, "data-snapshot-url")
        self.assertContains(response, str(note.id))
        # The shell embeds no ciphertext (vault posture): the client fetches
        # the state over JSON once it holds the fragment key.
        self.assertNotContains(response, VALID_CONTENT_B64)

    def test_increments_access_count(self):
        note = make_live_note()

        self.client.get(reverse("note:live", args=[note.id]), **NOTE_HOST)
        self.client.get(reverse("note:live", args=[note.id]), **NOTE_HOST)

        note.refresh_from_db()
        self.assertEqual(note.access_count, 2)

    def test_404_on_pass_and_main_hosts(self):
        """Live links belong to the note tool; other hosts must not serve them."""
        note = make_live_note()
        url = reverse("note:live", args=[note.id])

        self.assertEqual(self.client.get(url, **PASS_HOST).status_code, 404)
        self.assertEqual(self.client.get(url, **MAIN_HOST).status_code, 404)

    def test_expired_note_is_deleted_and_shows_expired_page(self):
        note = make_live_note(expires_at=timezone.now() - timedelta(minutes=1))

        response = self.client.get(reverse("note:live", args=[note.id]), **NOTE_HOST)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "note/expired.html")
        self.assertFalse(LiveNote.objects.filter(pk=note.pk).exists())

    def test_unknown_id_is_404(self):
        response = self.client.get(
            reverse("note:live", args=["00000000-0000-0000-0000-000000000000"]),
            **NOTE_HOST,
        )
        self.assertEqual(response.status_code, 404)

    def test_restricted_note_redirects_unauthenticated_to_signin(self):
        owner = create_user_with_password("owner secret")
        note = make_restricted_live_note(owner)
        response = self.client.get(reverse("note:live", args=[note.id]), **NOTE_HOST)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)
        self.assertIn("tool=note", response.url)

    def test_restricted_note_404s_authenticated_non_collaborator(self):
        owner = create_user_with_password("owner secret")
        stranger = create_user_with_password("stranger secret")
        note = make_restricted_live_note(owner)
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = stranger.user_id
        session.save()
        response = self.client.get(reverse("note:live", args=[note.id]), **NOTE_HOST)
        self.assertEqual(response.status_code, 404)

    def test_owner_sees_management_flag_and_collab_urls(self):
        owner = create_user_with_password("owner secret")
        note = make_restricted_live_note(owner)
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = owner.user_id
        session.save()
        response = self.client.get(reverse("note:live", args=[note.id]), **NOTE_HOST)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'data-is-owner="1"')
        self.assertContains(response, "data-collaborators-url")
        self.assertContains(response, "data-rekey-url")
        # The unlock modal (for vault-key recovery) is rendered for the owner.
        self.assertContains(response, "unlock-modal")


class LiveNoteStateViewTests(LiveViewTestCase):
    """GET /live/<uuid>/state/: the joining client's bootstrap."""

    def test_returns_snapshot_and_tail(self):
        note = make_live_note()
        first = make_live_update(note)
        second = make_live_update(note)

        response = self.client.get(reverse("note:live_state", args=[note.id]), **AJAX)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["snapshot"], note.snapshot)
        self.assertEqual(payload["snapshot_iv"], note.snapshot_iv)
        self.assertEqual([u["seq"] for u in payload["updates"]], [first.pk, second.pk])
        self.assertEqual(payload["seq"], second.pk)
        self.assertEqual(payload["pending"], 2)
        self.assertEqual(payload["expires_at"], note.expires_at.isoformat())

    def test_unknown_id_is_json_404(self):
        response = self.client.get(
            reverse("note:live_state", args=["00000000-0000-0000-0000-000000000000"]),
            **AJAX,
        )
        self.assertEqual(response.status_code, 404)
        self.assertFalse(response.json()["success"])

    def test_expired_note_is_deleted_and_404(self):
        note = make_live_note(expires_at=timezone.now() - timedelta(minutes=1))

        response = self.client.get(reverse("note:live_state", args=[note.id]), **AJAX)

        self.assertEqual(response.status_code, 404)
        self.assertFalse(LiveNote.objects.filter(pk=note.pk).exists())


class LiveNoteUpdatesViewTests(LiveViewTestCase):
    """GET/POST /live/<uuid>/updates/: the polling sync loop."""

    def setUp(self):
        super().setUp()
        self.note = make_live_note()
        self.url = reverse("note:live_updates", args=[self.note.id])

    def test_get_returns_rows_after_cursor(self):
        first = make_live_update(self.note)
        second = make_live_update(self.note)

        response = self.client.get(self.url, {"since": first.pk}, **AJAX)

        payload = response.json()
        self.assertEqual([u["seq"] for u in payload["updates"]], [second.pk])
        self.assertEqual(payload["seq"], second.pk)
        self.assertEqual(payload["pending"], 2)
        self.assertNotIn("snapshot", payload)

    def test_get_requires_valid_since(self):
        self.assertEqual(self.client.get(self.url, **AJAX).status_code, 400)
        self.assertEqual(
            self.client.get(self.url, {"since": "abc"}, **AJAX).status_code, 400
        )
        self.assertEqual(
            self.client.get(self.url, {"since": "-1"}, **AJAX).status_code, 400
        )

    def test_get_resyncs_pruned_cursor_with_snapshot(self):
        newest = make_live_update(self.note)
        self._post_json(
            reverse("note:live_snapshot", args=[self.note.id]),
            {
                "snapshot": "Y29tcGFjdGVk",
                "snapshot_iv": VALID_IV_B64,
                "covers_seq": newest.pk,
            },
        )

        response = self.client.get(self.url, {"since": 0}, **AJAX)

        payload = response.json()
        self.assertEqual(payload["snapshot"], "Y29tcGFjdGVk")
        self.assertEqual(payload["seq"], newest.pk)
        self.assertEqual(payload["updates"], [])

    def test_post_appends_update(self):
        response = self._post_json(
            self.url, {"payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        row = LiveNoteUpdate.objects.get(pk=payload["seq"])
        self.assertEqual(row.note, self.note)
        self.assertEqual(payload["pending"], 1)

    def test_post_missing_fields_rejected(self):
        response = self._post_json(self.url, {"payload": VALID_CONTENT_B64})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(LiveNoteUpdate.objects.count(), 0)

    def test_post_full_tail_answers_409(self):
        make_live_update(self.note)

        with patch("apps.note.services.MAX_LIVE_PENDING_UPDATES", 1):
            response = self._post_json(
                self.url, {"payload": VALID_CONTENT_B64, "iv": VALID_IV_B64}
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], ERROR_LIVE_TAIL_FULL)
        self.assertEqual(LiveNoteUpdate.objects.count(), 1)

    def test_post_to_expired_note_is_terminal_404(self):
        note = make_live_note(expires_at=timezone.now() - timedelta(minutes=1))

        response = self._post_json(
            reverse("note:live_updates", args=[note.id]),
            {"payload": VALID_CONTENT_B64, "iv": VALID_IV_B64},
        )

        self.assertEqual(response.status_code, 404)
        self.assertFalse(LiveNote.objects.filter(pk=note.pk).exists())


class LiveNoteSnapshotViewTests(LiveViewTestCase):
    """POST /live/<uuid>/snapshot/: client compaction."""

    def setUp(self):
        super().setUp()
        self.note = make_live_note()
        self.url = reverse("note:live_snapshot", args=[self.note.id])

    def test_valid_compaction_prunes_covered_rows(self):
        first = make_live_update(self.note)
        second = make_live_update(self.note)

        response = self._post_json(
            self.url,
            {
                "snapshot": "Y29tcGFjdGVk",
                "snapshot_iv": VALID_IV_B64,
                "covers_seq": first.pk,
            },
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["snapshot_seq"], first.pk)
        self.assertEqual(payload["deleted_updates"], 1)
        self.note.refresh_from_db()
        self.assertEqual(self.note.snapshot, "Y29tcGFjdGVk")
        self.assertEqual(
            list(self.note.updates.values_list("pk", flat=True)), [second.pk]
        )

    def test_stale_compaction_answers_409(self):
        newest = make_live_update(self.note)
        self._post_json(
            self.url,
            {
                "snapshot": "Y29tcGFjdGVk",
                "snapshot_iv": VALID_IV_B64,
                "covers_seq": newest.pk,
            },
        )

        response = self._post_json(
            self.url,
            {
                "snapshot": VALID_CONTENT_B64,
                "snapshot_iv": VALID_IV_B64,
                "covers_seq": newest.pk,
            },
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"], ERROR_LIVE_STALE_SNAPSHOT)

    def test_covers_seq_beyond_newest_answers_409(self):
        newest = make_live_update(self.note)

        response = self._post_json(
            self.url,
            {
                "snapshot": VALID_CONTENT_B64,
                "snapshot_iv": VALID_IV_B64,
                "covers_seq": newest.pk + 100,
            },
        )

        self.assertEqual(response.status_code, 409)

    def test_missing_or_invalid_covers_seq_rejected(self):
        make_live_update(self.note)
        base = {"snapshot": VALID_CONTENT_B64, "snapshot_iv": VALID_IV_B64}

        self.assertEqual(self._post_json(self.url, base).status_code, 400)
        self.assertEqual(
            self._post_json(self.url, {**base, "covers_seq": "abc"}).status_code, 400
        )
        self.assertEqual(
            self._post_json(self.url, {**base, "covers_seq": True}).status_code, 400
        )
        self.assertEqual(
            self._post_json(self.url, {**base, "covers_seq": -1}).status_code, 400
        )


class LiveRateLimitTests(LiveViewTestCase):
    """The JSON endpoints answer 429 as JSON, so the sync client can back off."""

    def test_snapshot_endpoint_answers_json_429_over_the_limit(self):
        note = make_live_note()
        url = reverse("note:live_snapshot", args=[note.id])
        limit = int(RATE_LIMIT_LIVE_SNAPSHOT.split("/")[0])

        for _ in range(limit):
            response = self._post_json(url, {})
            self.assertEqual(response.status_code, 400)  # invalid body, not limited

        response = self._post_json(url, {})

        self.assertEqual(response.status_code, 429)
        payload = response.json()
        self.assertFalse(payload["success"])
        self.assertIn("error", payload)
