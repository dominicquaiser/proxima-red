"""Shared factories for the note app's tests."""

from datetime import timedelta

from django.utils import timezone

from apps.note.models import SharedNote

# "encrypted" in Base64 and a 12-byte all-zero IV, mirroring the passwd tests.
VALID_CONTENT_B64 = "ZW5jcnlwdGVk"
VALID_IV_B64 = "AAAAAAAAAAAAAAAA"


def make_note(**overrides):
    """Create a SharedNote with sensible (encrypted) defaults for tests."""
    data = {
        "content": VALID_CONTENT_B64,
        "iv": VALID_IV_B64,
        "is_encrypted": True,
        "expires_at": timezone.now() + timedelta(days=1),
    }
    data.update(overrides)
    return SharedNote.objects.create(**data)


def make_plain_note(**overrides):
    """Create a plain-text SharedNote for tests."""
    data = {
        "content": "# Hello\n\nSome *markdown*.",
        "iv": "",
        "is_encrypted": False,
        "expires_at": timezone.now() + timedelta(days=1),
    }
    data.update(overrides)
    return SharedNote.objects.create(**data)
