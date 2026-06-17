"""Strict Base64 helpers shared by forms, validators, and serializers."""

import base64
import binascii


class InvalidBase64Error(ValueError):
    """Raised when input is not strict Base64."""


class Base64LengthError(ValueError):
    """Raised when decoded Base64 data has the wrong byte length."""


def encode_base64(data: bytes) -> str:
    """Encode binary data as a UTF-8 Base64 string."""
    return base64.b64encode(data).decode("utf-8")


def decode_base64(data: str) -> bytes:
    """Decode strict Base64 data or raise a sanitized ValueError."""
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise InvalidBase64Error("Invalid Base64 data") from exc


def decode_base64_exact_length(data: str, expected_length: int) -> bytes:
    """Decode Base64 data and require an exact decoded byte length."""
    decoded = decode_base64(data)
    if len(decoded) != expected_length:
        raise Base64LengthError("Invalid decoded byte length")
    return decoded
