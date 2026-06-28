"""
Tests for the passwd app field validators used by the models.
"""

import base64

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.passwd.constants import (
    GCM_IV_LENGTH_BYTES,
    MAX_ENCRYPTED_DATA_LENGTH,
    MAX_ENCRYPTED_TITLE_LENGTH,
    MAX_IV_LENGTH,
    MAX_VAULT_DATA_LENGTH,
)
from apps.passwd.validators import (
    validate_encrypted_data,
    validate_iv,
    validate_iv_bytes,
    validate_optional_encrypted_title,
    validate_optional_iv,
    validate_vault_data,
)


class ValidatorTests(TestCase):
    """Test cases for the model field validators."""

    def test_validate_encrypted_data_accepts_value(self):
        """A non-empty payload passes validation."""
        validate_encrypted_data("ZW5jcnlwdGVk")  # should not raise

    def test_validate_encrypted_data_rejects_empty(self):
        """Empty or whitespace-only payloads are rejected."""
        with self.assertRaises(ValidationError):
            validate_encrypted_data("")
        with self.assertRaises(ValidationError):
            validate_encrypted_data("   ")

    def test_validate_encrypted_data_rejects_too_long(self):
        """Payloads beyond the maximum length are rejected."""
        with self.assertRaises(ValidationError):
            validate_encrypted_data("A" * (MAX_ENCRYPTED_DATA_LENGTH + 1))

    def test_validate_vault_data_accepts_beyond_single_share_cap(self):
        """The vault holds many shares, so it accepts more than one share's worth."""
        # Length kept a multiple of 4 so it is valid Base64; above the single-share
        # cap but well within the vault cap.
        oversized_for_share = "A" * (MAX_ENCRYPTED_DATA_LENGTH + 4)
        with self.assertRaises(ValidationError):
            validate_encrypted_data(oversized_for_share)
        validate_vault_data(oversized_for_share)  # should not raise

    def test_validate_vault_data_rejects_too_long(self):
        """Payloads beyond the vault cap are rejected."""
        with self.assertRaises(ValidationError):
            validate_vault_data("A" * (MAX_VAULT_DATA_LENGTH + 1))

    def test_validate_vault_data_rejects_empty(self):
        """Empty vault payloads are rejected like any encrypted blob."""
        with self.assertRaises(ValidationError):
            validate_vault_data("")

    def test_validate_iv_accepts_base64(self):
        """A valid Base64 IV passes validation."""
        validate_iv("AAAAAAAAAAAAAAAA")  # should not raise

    def test_validate_iv_rejects_empty(self):
        """An empty IV is rejected."""
        with self.assertRaises(ValidationError):
            validate_iv("")

    def test_validate_iv_rejects_whitespace_only(self):
        """A whitespace-only IV is rejected like an empty one."""
        with self.assertRaises(ValidationError):
            validate_iv("   ")

    def test_validate_iv_rejects_non_base64(self):
        """An IV containing non-Base64 characters is rejected."""
        with self.assertRaises(ValidationError):
            validate_iv("not base64!!")

    def test_validate_iv_rejects_wrong_decoded_length(self):
        """A valid Base64 value must decode to the AES-GCM IV length."""
        short_iv = base64.b64encode(b"\x00" * (GCM_IV_LENGTH_BYTES - 1)).decode("utf-8")
        with self.assertRaises(ValidationError):
            validate_iv(short_iv)

    def test_validate_iv_rejects_too_long(self):
        """An IV beyond the maximum length is rejected."""
        with self.assertRaises(ValidationError):
            validate_iv("A" * (MAX_IV_LENGTH + 1))

    def test_validate_optional_encrypted_title_allows_empty(self):
        """The optional title validator accepts an empty value."""
        validate_optional_encrypted_title("")  # should not raise

    def test_validate_optional_encrypted_title_rejects_too_long(self):
        """A present title beyond the maximum length is rejected."""
        with self.assertRaises(ValidationError):
            validate_optional_encrypted_title("A" * (MAX_ENCRYPTED_TITLE_LENGTH + 1))

    def test_validate_optional_iv_allows_empty(self):
        """The optional IV validator accepts an empty value."""
        validate_optional_iv("")  # should not raise

    def test_validate_optional_iv_rejects_non_base64(self):
        """A present optional IV must still be Base64."""
        with self.assertRaises(ValidationError):
            validate_optional_iv("not base64!!")

    def test_validate_optional_iv_rejects_wrong_decoded_length(self):
        """A present optional IV must decode to the AES-GCM IV length."""
        short_iv = base64.b64encode(b"\x00" * (GCM_IV_LENGTH_BYTES - 1)).decode("utf-8")
        with self.assertRaises(ValidationError):
            validate_optional_iv(short_iv)

    def test_validate_iv_bytes_accepts_exact_length(self):
        """Raw IV bytes are accepted only at the AES-GCM size."""
        validate_iv_bytes(b"\x00" * GCM_IV_LENGTH_BYTES)

    def test_validate_iv_bytes_rejects_wrong_length(self):
        """Raw IV bytes with the wrong length are rejected."""
        with self.assertRaises(ValidationError):
            validate_iv_bytes(b"\x00" * (GCM_IV_LENGTH_BYTES - 1))

    def test_validate_iv_bytes_rejects_empty(self):
        """Empty raw IV bytes are rejected."""
        with self.assertRaises(ValidationError):
            validate_iv_bytes(b"")
