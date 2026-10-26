"""
Tests for the note app views.

All requests go through the real URL space: ``/`` and ``/<uuid>/`` are claimed
by apps.core's host dispatchers, which route note-host requests to these
views, so the tests set HTTP_HOST to the note subdomain (the exact pattern
used by apps.core's IndexViewTests).
"""

from datetime import timedelta

from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from apps.note.constants import MAX_NOTE_CONTENT_LENGTH
from apps.note.models import SharedNote

from .factories import VALID_CONTENT_B64, VALID_IV_B64, make_note, make_plain_note

AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}
NOTE_HOST = {"HTTP_HOST": "note.proxima.red"}


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    NOTE_SITE_URL="https://note.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "note.proxima.red", "testserver"],
)
class CreateNoteViewTests(TestCase):
    """GET renders the editor; POST creates encrypted or plain-text notes."""

    def setUp(self):
        self.client = Client()
        cache.clear()  # reset rate-limit counters between tests

    def test_get_renders_editor(self):
        response = self.client.get("/", **NOTE_HOST)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "note/editor.html")

    def test_editor_context_contains_url_construction_data(self):
        response = self.client.get("/", **NOTE_HOST)
        self.assertContains(response, "data-retrieve-url-base")
        self.assertContains(response, "00000000-0000-0000-0000-000000000000")

    def test_editor_context_contains_live_share_data(self):
        """The editable-link flow needs the live create URL and URL base."""
        response = self.client.get("/", **NOTE_HOST)
        self.assertContains(response, "data-live-create-url")
        self.assertContains(response, "data-live-url-base")
        self.assertContains(response, "/live/00000000-0000-0000-0000-000000000000/")
        self.assertContains(response, 'id="share-editable-btn"')

    def test_editor_renders_noscript_plain_text_form(self):
        """The no-JS fallback form (plain-text default + expiry select) is in
        the editor markup so the page degrades without JavaScript."""
        response = self.client.get("/", **NOTE_HOST)

        self.assertContains(response, 'name="content"')
        self.assertContains(response, 'name="is_encrypted" value="0"')
        self.assertContains(response, 'name="expiry_time"')
        self.assertContains(response, "editor__noscript-share")

    def test_post_creates_encrypted_note(self):
        response = self.client.post(
            "/",
            {
                "content": VALID_CONTENT_B64,
                "iv": VALID_IV_B64,
                "is_encrypted": "1",
                "expiry_time": "1hour",
            },
            **NOTE_HOST,
            **AJAX,
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        note = SharedNote.objects.get(pk=payload["note_id"])
        self.assertTrue(note.is_encrypted)
        self.assertEqual(note.content, VALID_CONTENT_B64)

    def test_post_creates_plain_text_note(self):
        response = self.client.post(
            "/",
            {"content": "# Plain markdown", "is_encrypted": "0"},
            **NOTE_HOST,
            **AJAX,
        )

        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertFalse(payload["is_encrypted"])
        note = SharedNote.objects.get(pk=payload["note_id"])
        self.assertFalse(note.is_encrypted)
        self.assertEqual(note.iv, "")

    def test_post_missing_content_is_rejected(self):
        response = self.client.post("/", {"content": ""}, **NOTE_HOST, **AJAX)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(SharedNote.objects.count(), 0)

    def test_post_encrypted_without_iv_is_rejected(self):
        response = self.client.post(
            "/",
            {"content": VALID_CONTENT_B64, "is_encrypted": "1"},
            **NOTE_HOST,
            **AJAX,
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])

    def test_post_oversize_content_is_rejected(self):
        response = self.client.post(
            "/",
            {
                "content": "A" * (MAX_NOTE_CONTENT_LENGTH + 4),
                "is_encrypted": "0",
            },
            **NOTE_HOST,
            **AJAX,
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(SharedNote.objects.count(), 0)

    def test_missing_is_encrypted_fails_closed_to_encrypted(self):
        """Without an explicit is_encrypted=0 the payload is treated as
        encrypted, so plain markdown is rejected (not silently stored)."""
        response = self.client.post(
            "/", {"content": "# not ciphertext"}, **NOTE_HOST, **AJAX
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(SharedNote.objects.count(), 0)

    def test_non_ajax_post_renders_editor_with_link(self):
        """The no-JS fallback form creates a plain-text note and re-renders
        the editor with the share link."""
        response = self.client.post(
            "/", {"content": "# no-js note", "is_encrypted": "0"}, **NOTE_HOST
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "note/editor.html")
        note = SharedNote.objects.get()
        self.assertContains(response, str(note.id))


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    NOTE_SITE_URL="https://note.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "note.proxima.red", "testserver"],
)
class RetrieveNoteViewTests(TestCase):
    """GET /<uuid>/ on the note host serves the note for client-side handling."""

    def setUp(self):
        self.client = Client()
        cache.clear()  # reset rate-limit counters between tests

    def test_retrieve_returns_note_payload(self):
        note = make_note()

        response = self.client.get(f"/{note.id}/", **NOTE_HOST)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "note/retrieve.html")
        self.assertContains(response, 'id="note-data"')
        self.assertContains(response, VALID_CONTENT_B64)

    def test_retrieve_increments_access_count(self):
        note = make_note()

        self.client.get(f"/{note.id}/", **NOTE_HOST)
        self.client.get(f"/{note.id}/", **NOTE_HOST)

        note.refresh_from_db()
        self.assertEqual(note.access_count, 2)

    def test_plain_text_note_shows_unencrypted_banner(self):
        note = make_plain_note()

        response = self.client.get(f"/{note.id}/", **NOTE_HOST)

        self.assertContains(response, "not end-to-end encrypted")

    def test_encrypted_note_has_no_banner(self):
        note = make_note()

        response = self.client.get(f"/{note.id}/", **NOTE_HOST)

        self.assertNotContains(response, "not end-to-end encrypted")

    def test_plain_text_note_renders_raw_content_without_js(self):
        """A plain-text note is server-readable, so the <noscript> fallback
        shows its raw text (unformatted) for visitors without JavaScript."""
        note = make_plain_note(content="# no-js title\n\nplain body text")

        response = self.client.get(f"/{note.id}/", **NOTE_HOST)

        self.assertContains(response, "note-view__plain")
        self.assertContains(response, "plain body text")

    def test_encrypted_note_noscript_requires_javascript(self):
        """An encrypted note cannot be decrypted without JavaScript, so the
        fallback says so rather than showing opaque ciphertext as text."""
        note = make_note()

        response = self.client.get(f"/{note.id}/", **NOTE_HOST)

        self.assertContains(response, "JavaScript is required to decrypt")

    def test_expired_note_is_deleted_and_shows_expired_page(self):
        note = make_note(expires_at=timezone.now() - timedelta(minutes=1))

        response = self.client.get(f"/{note.id}/", **NOTE_HOST)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "note/expired.html")
        self.assertFalse(SharedNote.objects.filter(pk=note.pk).exists())

    def test_unknown_uuid_404s(self):
        response = self.client.get(
            "/00000000-0000-0000-0000-000000000000/", **NOTE_HOST
        )
        self.assertEqual(response.status_code, 404)
