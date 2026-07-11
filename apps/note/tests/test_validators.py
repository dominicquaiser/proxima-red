"""Tests for the note app validators."""

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from apps.note.constants import MAX_NOTE_CONTENT_LENGTH
from apps.note.validators import (
    validate_base64_content,
    validate_note_content,
    validate_optional_iv,
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
