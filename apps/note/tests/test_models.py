"""
Tests for the note app models.

Covers SharedNote defaults, string representations, expiry, the cross-field
clean() rules between is_encrypted/content/iv, and the FK relationship with
the custom User model.
"""

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.note.constants import MAX_NOTE_CONTENT_LENGTH
from apps.note.models import SharedNote

from .factories import VALID_IV_B64, make_note, make_plain_note


class SharedNoteModelTests(TestCase):
    """Test cases for the SharedNote model."""

    def test_create_note_defaults(self):
        """A freshly created note has sane defaults."""
        note = make_note()

        self.assertIsNotNone(note.id)
        self.assertEqual(note.access_count, 0)
        self.assertTrue(note.is_encrypted)
        self.assertIsNotNone(note.created_at)

    def test_str_never_contains_content(self):
        """str()/repr() reference the id and mode, never the note body."""
        note = make_note()
        plain = make_plain_note(content="super secret plaintext body")

        self.assertIn("encrypted", str(note))
        self.assertIn("plain-text", str(plain))
        self.assertNotIn("super secret", str(plain))
        self.assertNotIn("super secret", repr(plain))

    def test_repr_includes_id_and_expiry(self):
        """repr() references the note id prefix and both timestamps."""
        note = make_note()
        text = repr(note)
        self.assertIn(str(note.id)[:8], text)
        self.assertIn(note.created_at.isoformat(), text)
        self.assertIn(note.expires_at.isoformat(), text)

    def test_is_expired_false_for_future(self):
        """is_expired() is False while expires_at is in the future."""
        note = make_note(expires_at=timezone.now() + timedelta(hours=1))
        self.assertFalse(note.is_expired())

    def test_is_expired_true_for_past(self):
        """is_expired() is True once expires_at is in the past."""
        note = make_note(expires_at=timezone.now() - timedelta(hours=1))
        self.assertTrue(note.is_expired())

    def test_default_ordering_is_newest_first(self):
        """Notes are ordered by created_at descending."""
        first = make_note()
        second = make_note()

        notes = list(SharedNote.objects.all())
        self.assertEqual(notes[0].id, second.id)
        self.assertEqual(notes[1].id, first.id)

    def test_cascade_delete_with_user(self):
        """Deleting the owner cascades to their notes; anonymous notes stay."""
        user = create_user_with_password("password-123")
        owned = make_note(created_by=user)
        anonymous = make_note()

        user.delete()

        self.assertFalse(SharedNote.objects.filter(pk=owned.pk).exists())
        self.assertTrue(SharedNote.objects.filter(pk=anonymous.pk).exists())


class SharedNoteCleanTests(TestCase):
    """The clean() matrix for encrypted vs. plain-text notes."""

    def _unsaved_note(self, **overrides):
        data = {
            "content": "ZW5jcnlwdGVk",
            "iv": VALID_IV_B64,
            "is_encrypted": True,
            "expires_at": timezone.now() + timedelta(days=1),
        }
        data.update(overrides)
        return SharedNote(**data)

    def test_encrypted_with_iv_and_base64_content_is_valid(self):
        """The canonical encrypted note passes full_clean()."""
        self._unsaved_note().full_clean()

    def test_plain_text_with_raw_markdown_is_valid(self):
        """A plain-text note may hold arbitrary (non-Base64) markdown."""
        self._unsaved_note(
            content="# Not base64! *at all*", iv="", is_encrypted=False
        ).full_clean()

    def test_encrypted_without_iv_is_rejected(self):
        """An encrypted note without an IV fails validation."""
        with self.assertRaises(ValidationError) as ctx:
            self._unsaved_note(iv="").full_clean()
        self.assertIn("iv", ctx.exception.message_dict)

    def test_encrypted_with_non_base64_content_is_rejected(self):
        """An encrypted note whose content is not Base64 fails validation."""
        with self.assertRaises(ValidationError) as ctx:
            self._unsaved_note(content="not base64 at all!").full_clean()
        self.assertIn("content", ctx.exception.message_dict)

    def test_plain_text_with_iv_is_rejected(self):
        """A plain-text note carrying an IV is a client bug and is rejected."""
        with self.assertRaises(ValidationError) as ctx:
            self._unsaved_note(
                content="# markdown", iv=VALID_IV_B64, is_encrypted=False
            ).full_clean()
        self.assertIn("iv", ctx.exception.message_dict)

    def test_content_over_cap_is_rejected(self):
        """Content beyond MAX_NOTE_CONTENT_LENGTH fails validation."""
        oversize = "A" * (MAX_NOTE_CONTENT_LENGTH + 4)
        with self.assertRaises(ValidationError):
            self._unsaved_note(content=oversize, iv="", is_encrypted=False).full_clean()

    def test_empty_content_is_rejected(self):
        """An empty note body fails validation."""
        with self.assertRaises(ValidationError):
            self._unsaved_note(content="", iv="", is_encrypted=False).full_clean()
