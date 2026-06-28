"""
Custom validators for the password sharing application.

This module provides validation functions for encrypted data,
initialization vectors, and other security-sensitive fields.
"""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.core.encoding import decode_base64

from .constants import (
    GCM_IV_LENGTH_BYTES,
    MAX_ENCRYPTED_DATA_LENGTH,
    MAX_ENCRYPTED_TITLE_LENGTH,
    MAX_IV_LENGTH,
    MAX_VAULT_DATA_LENGTH,
)


def _check_max_length(value: str, max_length: int, label: str, code: str) -> None:
    """Raise ValidationError if ``value`` exceeds ``max_length`` characters."""
    if len(value) > max_length:
        raise ValidationError(
            _("%(label)s exceeds maximum length of %(max_length)d characters.")
            % {"label": label, "max_length": max_length},
            code=code,
        )


def _decode_base64(value: str, label: str = "Value") -> bytes:
    """Decode ``value`` or raise ValidationError when it is not strict Base64."""
    try:
        return decode_base64(value)
    except ValueError:
        raise ValidationError(
            _("%(label)s must be a valid Base64-encoded string.") % {"label": label},
            code="invalid_base64",
        )


def _check_iv_length(num_bytes: int) -> None:
    """Raise ValidationError unless an IV is the exact AES-GCM byte size.

    Shared by the Base64 validators (after decoding) and the raw-bytes validator,
    so the 12-byte AES-GCM rule lives in exactly one place.
    """
    if num_bytes != GCM_IV_LENGTH_BYTES:
        raise ValidationError(
            _("Initialization vector must be exactly %(length)d bytes.")
            % {"length": GCM_IV_LENGTH_BYTES},
            code="invalid_iv_length",
        )


def _check_iv_byte_length(value: str, label: str = "IV") -> None:
    """Raise ValidationError if a Base64 IV does not decode to the AES-GCM size."""
    _check_iv_length(len(_decode_base64(value, label)))


def _validate_encrypted_blob(value: str, max_length: int) -> None:
    """
    Shared rules for a required Base64 ciphertext blob.

    Ensures the value is non-empty, within ``max_length`` characters (to prevent
    abuse), and valid Base64. The byte cap is the only thing that differs between
    an anonymous single share (:data:`MAX_ENCRYPTED_DATA_LENGTH`) and the
    authenticated vault, which packs every share into one blob
    (:data:`MAX_VAULT_DATA_LENGTH`).

    Raises:
        ValidationError: If validation fails
    """
    if not value or not value.strip():
        raise ValidationError(
            _("Encrypted data cannot be empty."), code="empty_encrypted_data"
        )
    _check_max_length(value, max_length, "Encrypted data", "encrypted_data_too_long")
    _decode_base64(value, "Encrypted data")


def validate_encrypted_data(value: str) -> None:
    """Validate the ciphertext of a single anonymous share.

    Capped at :data:`MAX_ENCRYPTED_DATA_LENGTH`; the unauthenticated create
    endpoint relies on this tight bound to limit abuse.
    """
    _validate_encrypted_blob(value, MAX_ENCRYPTED_DATA_LENGTH)


def validate_vault_data(value: str) -> None:
    """Validate the authenticated vault blob.

    The vault is a single encrypted document holding every share a user has saved
    (share id + per-share key + title/tags), so it is capped at the larger
    :data:`MAX_VAULT_DATA_LENGTH` rather than the one-secret share limit.
    """
    _validate_encrypted_blob(value, MAX_VAULT_DATA_LENGTH)


def validate_optional_encrypted_title(value: str) -> None:
    """
    Validate the optional encrypted title field.

    The title is encrypted client-side (Base64-encoded ciphertext) and may be
    empty when the user did not provide one. When present, it must not exceed
    the maximum allowed length.

    Args:
        value: The encrypted title string to validate

    Raises:
        ValidationError: If validation fails
    """
    if not value:
        return
    _check_max_length(
        value,
        MAX_ENCRYPTED_TITLE_LENGTH,
        "Encrypted title",
        "encrypted_title_too_long",
    )
    _decode_base64(value, "Encrypted title")


def _validate_base64_iv(value: str, *, required: bool) -> None:
    """
    Validate a Base64-encoded AES-GCM IV: encoding, length bound, decoded size.

    Single source of truth for the required and optional IV validators, which
    differ only in how they treat an empty value. With ``required=True`` an
    empty/whitespace value is rejected; with ``required=False`` an empty value
    passes (the encrypted title's IV is absent when no title was given).

    Raises:
        ValidationError: If validation fails
    """
    if not value:
        if required:
            raise ValidationError(
                _("Initialization vector cannot be empty."), code="empty_iv"
            )
        return
    if required and not value.strip():
        raise ValidationError(
            _("Initialization vector cannot be empty."), code="empty_iv"
        )
    _check_max_length(value, MAX_IV_LENGTH, "IV", "iv_too_long")
    _check_iv_byte_length(value, "IV")


def validate_iv(value: str) -> None:
    """Validate a required Base64-encoded initialization vector (IV) field."""
    _validate_base64_iv(value, required=True)


def validate_optional_iv(value: str) -> None:
    """Validate an optional Base64-encoded IV; an empty value is permitted.

    Used for the encrypted title's IV, which is absent when no title was given.
    """
    _validate_base64_iv(value, required=False)


def validate_iv_bytes(value: bytes) -> None:
    """
    Validate a raw AES-GCM initialization vector.

    ``ServiceData.iv`` is stored as bytes, not Base64 text, so it checks the raw
    byte length directly (sharing :func:`_check_iv_length` with the Base64 path).
    """
    if not value:
        raise ValidationError(
            _("Initialization vector cannot be empty."), code="empty_iv"
        )
    _check_iv_length(len(value))
