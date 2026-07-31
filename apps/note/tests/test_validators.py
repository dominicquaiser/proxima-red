"""Tests for the note app validators."""

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.note.constants import (
    MAX_LIVE_SNAPSHOT_LENGTH,
    MAX_LIVE_UPDATE_LENGTH,
    MAX_NOTE_CONTENT_LENGTH,
    MAX_VAULT_INDEX_LENGTH,
    MAX_VAULT_NOTE_CONTENT_LENGTH,
)
from apps.note.validators import (
    validate_base64_content,
    validate_live_snapshot,
    validate_live_update_payload,
    validate_note_content,
    validate_optional_iv,
    validate_required_iv,
    validate_vault_index_data,
    validate_vault_note_content,
)


class ValidateNoteContentTests(SimpleTestCase):
    """validate_note_content: presence and cap, no encoding assumptions."""

    def test_accepts_plain_markdown(self):
        validate_note_content("# Heading\n\nBody text.")

    def test_accepts_base64(self):
        validate_note_content("ZW5jcnlwdGVk")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            validate_note_content("")

    def test_rejects_whitespace_only(self):
        with self.assertRaises(ValidationError):
            validate_note_content("   \n\t ")

    def test_rejects_over_cap(self):
        with self.assertRaises(ValidationError):
            validate_note_content("A" * (MAX_NOTE_CONTENT_LENGTH + 1))

    def test_accepts_exactly_cap(self):
        validate_note_content("A" * MAX_NOTE_CONTENT_LENGTH)


class ValidateBase64ContentTests(SimpleTestCase):
    """validate_base64_content: the strict-Base64 rule for ciphertext."""

    def test_accepts_strict_base64(self):
        validate_base64_content("ZW5jcnlwdGVk")

    def test_rejects_non_base64(self):
        with self.assertRaises(ValidationError):
            validate_base64_content("not base64 at all!")


class ValidateOptionalIvTests(SimpleTestCase):
    """validate_optional_iv: empty allowed, otherwise a 12-byte Base64 IV."""

    def test_accepts_empty(self):
        validate_optional_iv("")

    def test_accepts_valid_12_byte_iv(self):
        validate_optional_iv("AAAAAAAAAAAAAAAA")  # 16 Base64 chars -> 12 bytes

    def test_rejects_wrong_byte_length(self):
        with self.assertRaises(ValidationError):
            validate_optional_iv("AAAA")  # 3 bytes

    def test_rejects_non_base64(self):
        with self.assertRaises(ValidationError):
            validate_optional_iv("!!!!not-base64!!")

    def test_rejects_over_length(self):
        with self.assertRaises(ValidationError):
            validate_optional_iv("A" * 32)


class ValidateRequiredIvTests(SimpleTestCase):
    """validate_required_iv: like the optional rule but empty is rejected."""

    def test_accepts_valid_12_byte_iv(self):
        validate_required_iv("AAAAAAAAAAAAAAAA")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError) as ctx:
            validate_required_iv("")
        self.assertEqual(ctx.exception.code, "missing_iv")

    def test_rejects_wrong_byte_length(self):
        with self.assertRaises(ValidationError):
            validate_required_iv("AAAA")

    def test_rejects_non_base64(self):
        with self.assertRaises(ValidationError):
            validate_required_iv("!!!!not-base64!!")


class ValidateVaultNoteContentTests(SimpleTestCase):
    """validate_vault_note_content: presence, cap, and strict Base64."""

    def test_accepts_base64(self):
        validate_vault_note_content("ZW5jcnlwdGVk")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            validate_vault_note_content("")

    def test_rejects_raw_markdown(self):
        """Vault notes are always ciphertext; raw markdown must not pass."""
        with self.assertRaises(ValidationError):
            validate_vault_note_content("# Heading, not base64!")

    def test_rejects_over_cap(self):
        with self.assertRaises(ValidationError):
            validate_vault_note_content(
                "AAAA" * (MAX_VAULT_NOTE_CONTENT_LENGTH // 4 + 1)
            )

    def test_accepts_base64_at_cap(self):
        validate_vault_note_content("AAAA" * (MAX_VAULT_NOTE_CONTENT_LENGTH // 4))


class ValidateVaultIndexDataTests(SimpleTestCase):
    """validate_vault_index_data: presence, cap, and strict Base64."""

    def test_accepts_base64(self):
        validate_vault_index_data("ZW5jcnlwdGVk")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            validate_vault_index_data("")

    def test_rejects_non_base64(self):
        with self.assertRaises(ValidationError):
            validate_vault_index_data("{json: not encrypted}")

    def test_rejects_over_cap(self):
        with self.assertRaises(ValidationError):
            validate_vault_index_data("AAAA" * (MAX_VAULT_INDEX_LENGTH // 4 + 1))


class ValidateLiveSnapshotTests(SimpleTestCase):
    """validate_live_snapshot: presence, cap, and strict Base64."""

    def test_accepts_base64(self):
        validate_live_snapshot("ZW5jcnlwdGVk")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            validate_live_snapshot("")

    def test_rejects_non_base64(self):
        with self.assertRaises(ValidationError):
            validate_live_snapshot("not a yjs snapshot!")

    def test_rejects_over_cap(self):
        with self.assertRaises(ValidationError):
            validate_live_snapshot("AAAA" * (MAX_LIVE_SNAPSHOT_LENGTH // 4 + 1))

    def test_accepts_base64_at_cap(self):
        validate_live_snapshot("AAAA" * (MAX_LIVE_SNAPSHOT_LENGTH // 4))


class ValidateLiveUpdatePayloadTests(SimpleTestCase):
    """validate_live_update_payload: presence, cap, and strict Base64."""

    def test_accepts_base64(self):
        validate_live_update_payload("ZW5jcnlwdGVk")

    def test_rejects_empty(self):
        with self.assertRaises(ValidationError):
            validate_live_update_payload("")

    def test_rejects_non_base64(self):
        with self.assertRaises(ValidationError):
            validate_live_update_payload("not a yjs update!")

    def test_rejects_over_cap(self):
        with self.assertRaises(ValidationError):
            validate_live_update_payload("AAAA" * (MAX_LIVE_UPDATE_LENGTH // 4 + 1))
