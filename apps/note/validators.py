"""
Custom validators for the note sharing application.

Field validators cover the mode-independent rules (presence, length caps, IV
shape). The rules that depend on whether a note is encrypted or plain text
(Base64 content, IV required vs. forbidden) live in ``SharedNote.clean()``,
because a plain-text note's content must *not* be required to be Base64.

The tiny IV/Base64 helpers mirror ``apps.passwd.validators`` instead of
importing them: the tools share conventions, not code (see the note in
``apps.note.constants``).
"""

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.core.encoding import decode_base64

from .constants import GCM_IV_LENGTH_BYTES, MAX_IV_LENGTH, MAX_NOTE_CONTENT_LENGTH


def _check_max_length(value: str, max_length: int, label: str, code: str) -> None:
    """Reject a value that exceeds a character limit.

    Args:
        value (str): Value whose length is checked.
        max_length (int): Maximum permitted number of characters.
        label (str): Human-readable field label used in the error message.
        code (str): Stable Django validation error code.

    Returns:
        None: The value is accepted.

    Raises:
        ValidationError: If ``value`` is longer than ``max_length``.
    """
    if len(value) > max_length:
        raise ValidationError(
            _("%(label)s exceeds maximum length of %(max_length)d characters.")
            % {"label": label, "max_length": max_length},
            code=code,
        )


def _decode_base64(value: str, label: str = "Value") -> bytes:
    """Decode a strict Base64 value.

    Args:
        value (str): Base64 text to decode.
        label (str): Human-readable field label used in the error message.

    Returns:
        bytes: Decoded bytes.

    Raises:
        ValidationError: If ``value`` is not strict Base64.
    """
    try:
        return decode_base64(value)
    except ValueError:
        raise ValidationError(
            _("%(label)s must be a valid Base64-encoded string.") % {"label": label},
            code="invalid_base64",
        )


def validate_note_content(value: str) -> None:
    """Validate a note body: non-empty and within the abuse cap.

    Applies to encrypted and plain-text notes alike, so it makes no assumption
    about encoding. Encrypted notes additionally get a strict-Base64 check via
    :func:`validate_base64_content` from ``SharedNote.clean()``.

    Args:
        value (str): Encrypted ciphertext or plain-text Markdown to validate.

    Returns:
        None: The value is accepted.

    Raises:
        ValidationError: If the value is empty, whitespace-only, or longer than
            ``MAX_NOTE_CONTENT_LENGTH``.
    """
    if not value or not value.strip():
        raise ValidationError(_("Note content cannot be empty."), code="empty_content")
    _check_max_length(
        value, MAX_NOTE_CONTENT_LENGTH, "Note content", "content_too_long"
    )


def validate_base64_content(value: str) -> None:
    """Validate encrypted note content as strict Base64 ciphertext.

    Args:
        value (str): Encrypted note content to validate.

    Returns:
        None: The value is accepted.

    Raises:
        ValidationError: If ``value`` is not strict Base64.
    """
    _decode_base64(value, "Encrypted note content")


def validate_optional_iv(value: str) -> None:
    """Validate a Base64-encoded AES-GCM IV; an empty value is permitted.

    Plain-text notes store no IV. Whether an IV is required (encrypted note)
    or must be absent (plain-text note) is a cross-field rule enforced in
    ``SharedNote.clean()``.

    Args:
        value (str): Base64-encoded IV or an empty string.

    Returns:
        None: The value is accepted.

    Raises:
        ValidationError: If a non-empty value exceeds ``MAX_IV_LENGTH``, is not
            strict Base64, or does not decode to ``GCM_IV_LENGTH_BYTES`` bytes.
    """
    if not value:
        return
    _check_max_length(value, MAX_IV_LENGTH, "IV", "iv_too_long")
    if len(_decode_base64(value, "IV")) != GCM_IV_LENGTH_BYTES:
        raise ValidationError(
            _("Initialization vector must be exactly %(length)d bytes.")
            % {"length": GCM_IV_LENGTH_BYTES},
            code="invalid_iv_length",
        )
