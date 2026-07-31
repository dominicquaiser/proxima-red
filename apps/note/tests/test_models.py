"""
Tests for the note app models.

Covers SharedNote defaults, string representations, expiry, the cross-field
clean() rules between is_encrypted/content/iv, the FK relationship with the
custom User model, and the vault models (VaultNote, VaultIndex).
"""

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.note.constants import MAX_NOTE_CONTENT_LENGTH
from apps.note.models import LiveNote, LiveNoteUpdate, SharedNote, VaultIndex, VaultNote

from .factories import (
    VALID_CONTENT_B64,
    VALID_IV_B64,
    make_live_note,
    make_live_update,
    make_note,
    make_plain_note,
    make_vault_index,
    make_vault_note,
)


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


class VaultNoteModelTests(TestCase):
    """The always-encrypted, never-expiring vault note."""

    def setUp(self):
        self.user = create_user_with_password("password-123")

    def test_create_defaults(self):
        note = make_vault_note(self.user)
        self.assertIsNotNone(note.id)
        self.assertIsNotNone(note.created_at)
        self.assertIsNotNone(note.updated_at)
        self.assertEqual(note.user, self.user)

    def test_str_and_repr_never_contain_content(self):
        note = make_vault_note(self.user)
        self.assertNotIn(VALID_CONTENT_B64, str(note))
        self.assertNotIn(VALID_CONTENT_B64, repr(note))
        self.assertIn(str(note.id)[:8], repr(note))

    def test_validation_requires_iv(self):
        note = VaultNote(user=self.user, content=VALID_CONTENT_B64, iv="")
        with self.assertRaises(ValidationError) as ctx:
            note.full_clean()
        self.assertIn("iv", ctx.exception.message_dict)

    def test_validation_requires_base64_content(self):
        note = VaultNote(user=self.user, content="not base64!!", iv=VALID_IV_B64)
        with self.assertRaises(ValidationError) as ctx:
            note.full_clean()
        self.assertIn("content", ctx.exception.message_dict)

    def test_default_ordering_is_most_recently_updated_first(self):
        first = make_vault_note(self.user)
        second = make_vault_note(self.user)
        first.content = "dXBkYXRlZA=="
        first.save()

        notes = list(VaultNote.objects.all())
        self.assertEqual(notes[0].id, first.id)
        self.assertEqual(notes[1].id, second.id)

    def test_cascade_delete_with_user(self):
        make_vault_note(self.user)
        self.user.delete()
        self.assertFalse(VaultNote.objects.exists())


class VaultIndexModelTests(TestCase):
    """The per-user encrypted vault index."""

    def setUp(self):
        self.user = create_user_with_password("password-123")

    def test_str_and_repr_never_contain_ciphertext(self):
        index = make_vault_index(self.user)
        self.assertNotIn(VALID_CONTENT_B64, str(index))
        self.assertNotIn(VALID_CONTENT_B64, repr(index))
        self.assertIn(self.user.user_id, str(index))

    def test_one_index_per_user(self):
        make_vault_index(self.user)
        with self.assertRaises(IntegrityError):
            make_vault_index(self.user)

    def test_validation_requires_iv_and_base64_data(self):
        with self.assertRaises(ValidationError):
            VaultIndex(
                user=self.user, encrypted_data=VALID_CONTENT_B64, iv=""
            ).full_clean()
        with self.assertRaises(ValidationError):
            VaultIndex(
                user=self.user, encrypted_data="not base64!!", iv=VALID_IV_B64
            ).full_clean()

    def test_cascade_delete_with_user(self):
        make_vault_index(self.user)
        self.user.delete()
        self.assertFalse(VaultIndex.objects.exists())


class LiveNoteModelTests(TestCase):
    """The editable share link's document: encrypted snapshot + expiry."""

    def test_create_defaults(self):
        note = make_live_note()

        self.assertIsNotNone(note.id)
        self.assertEqual(note.snapshot_seq, 0)
        self.assertEqual(note.access_count, 0)
        self.assertIsNone(note.created_by)
        self.assertIsNotNone(note.created_at)
        self.assertIsNotNone(note.updated_at)

    def test_str_and_repr_never_contain_snapshot(self):
        note = make_live_note()
        self.assertNotIn(VALID_CONTENT_B64, str(note))
        self.assertNotIn(VALID_CONTENT_B64, repr(note))
        self.assertIn(str(note.id)[:8], repr(note))

    def test_is_expired_follows_expires_at(self):
        active = make_live_note(expires_at=timezone.now() + timedelta(hours=1))
        expired = make_live_note(expires_at=timezone.now() - timedelta(hours=1))

        self.assertFalse(active.is_expired())
        self.assertTrue(expired.is_expired())

    def test_validation_requires_iv_and_base64_snapshot(self):
        expires = timezone.now() + timedelta(days=1)
        with self.assertRaises(ValidationError) as ctx:
            LiveNote(
                snapshot=VALID_CONTENT_B64, snapshot_iv="", expires_at=expires
            ).full_clean()
        self.assertIn("snapshot_iv", ctx.exception.message_dict)
        with self.assertRaises(ValidationError) as ctx:
            LiveNote(
                snapshot="not base64!!", snapshot_iv=VALID_IV_B64, expires_at=expires
            ).full_clean()
        self.assertIn("snapshot", ctx.exception.message_dict)

    def test_cascade_delete_with_user(self):
        """Deleting the creator cascades; anonymous live notes stay."""
        user = create_user_with_password("password-123")
        owned = make_live_note(created_by=user)
        anonymous = make_live_note()

        user.delete()

        self.assertFalse(LiveNote.objects.filter(pk=owned.pk).exists())
        self.assertTrue(LiveNote.objects.filter(pk=anonymous.pk).exists())


class LiveNoteUpdateModelTests(TestCase):
    """The append-only encrypted update log rows."""

    def setUp(self):
        self.note = make_live_note()

    def test_ids_are_monotonic_in_append_order(self):
        """The BigAuto pk is the sync cursor: later appends get larger ids."""
        first = make_live_update(self.note)
        second = make_live_update(self.note)
        third = make_live_update(self.note)

        self.assertLess(first.pk, second.pk)
        self.assertLess(second.pk, third.pk)
        self.assertEqual(
            list(self.note.updates.values_list("pk", flat=True)),
            sorted([first.pk, second.pk, third.pk]),
        )

    def test_str_and_repr_never_contain_payload(self):
        update = make_live_update(self.note)
        self.assertNotIn(VALID_CONTENT_B64, str(update))
        self.assertNotIn(VALID_CONTENT_B64, repr(update))

    def test_validation_requires_iv_and_base64_payload(self):
        with self.assertRaises(ValidationError) as ctx:
            LiveNoteUpdate(
                note=self.note, payload=VALID_CONTENT_B64, iv=""
            ).full_clean()
        self.assertIn("iv", ctx.exception.message_dict)
        with self.assertRaises(ValidationError) as ctx:
            LiveNoteUpdate(
                note=self.note, payload="not base64!!", iv=VALID_IV_B64
            ).full_clean()
        self.assertIn("payload", ctx.exception.message_dict)

    def test_cascade_delete_with_note(self):
        make_live_update(self.note)
        make_live_update(self.note)

        self.note.delete()

        self.assertFalse(LiveNoteUpdate.objects.exists())
