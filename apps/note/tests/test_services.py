"""Tests for the note app service layer."""

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.note import services
from apps.note.constants import DEFAULT_EXPIRY, EXPIRY_MAP
from apps.note.models import SharedNote

from .factories import VALID_CONTENT_B64, VALID_IV_B64, make_note


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
