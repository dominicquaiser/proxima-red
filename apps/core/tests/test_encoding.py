"""Tests for shared Base64 encoding helpers."""

from django.test import SimpleTestCase

from apps.core.encoding import (
    Base64LengthError,
    InvalidBase64Error,
    decode_base64,
    decode_base64_exact_length,
    encode_base64,
)


class Base64EncodingTests(SimpleTestCase):
    """Strict Base64 helpers sanitize decode errors and check byte lengths."""

    def test_round_trip(self):
        data = b"\x00\x01\x02\xff"
        encoded = encode_base64(data)

        self.assertEqual(encoded, "AAEC/w==")
        self.assertEqual(decode_base64(encoded), data)

    def test_invalid_base64_raises_sanitized_error(self):
        with self.assertRaisesMessage(InvalidBase64Error, "Invalid Base64 data"):
            decode_base64("not base64!!")

    def test_exact_length_accepts_expected_length(self):
        self.assertEqual(
            decode_base64_exact_length("AAAAAAAAAAAAAAAA", 12), b"\x00" * 12
        )

    def test_exact_length_rejects_wrong_length(self):
        with self.assertRaises(Base64LengthError):
            decode_base64_exact_length("AAA=", 12)
