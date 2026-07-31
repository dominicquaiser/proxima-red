"""Shared factories for the note app's tests."""

from datetime import timedelta

from django.utils import timezone

from apps.note.models import (
    LiveNote,
    LiveNoteCollaborator,
    LiveNoteUpdate,
    SharedNote,
    VaultIndex,
    VaultNote,
)

# "encrypted" in Base64 and a 12-byte all-zero IV, mirroring the passwd tests.
VALID_CONTENT_B64 = "ZW5jcnlwdGVk"
VALID_IV_B64 = "AAAAAAAAAAAAAAAA"
# A stand-in SPKI ephemeral key for wrap fixtures (server never checks EC math).
VALID_EPHEMERAL_KEY_B64 = "ZXBoZW1lcmFscHVibGlja2V5"


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


def make_live_note(**overrides):
    """Create a LiveNote with valid encrypted-snapshot defaults for tests."""
    data = {
        "snapshot": VALID_CONTENT_B64,
        "snapshot_iv": VALID_IV_B64,
        "expires_at": timezone.now() + timedelta(days=1),
    }
    data.update(overrides)
    return LiveNote.objects.create(**data)


def make_live_update(note, **overrides):
    """Append a LiveNoteUpdate with valid ciphertext defaults for tests."""
    data = {
        "note": note,
        "payload": VALID_CONTENT_B64,
        "iv": VALID_IV_B64,
    }
    data.update(overrides)
    return LiveNoteUpdate.objects.create(**data)


def make_live_collaborator(note, user, **overrides):
    """Create a LiveNoteCollaborator grant with valid wrap fixtures."""
    data = {
        "note": note,
        "user": user,
        "role": LiveNoteCollaborator.ROLE_EDITOR,
        "wrapped_key": VALID_CONTENT_B64,
        "wrap_iv": VALID_IV_B64,
        "ephemeral_public_key": VALID_EPHEMERAL_KEY_B64,
        "key_epoch": note.key_epoch,
    }
    data.update(overrides)
    return LiveNoteCollaborator.objects.create(**data)


def make_restricted_live_note(owner, **overrides):
    """Create a restricted LiveNote owned by ``owner`` (with the owner grant)."""
    note = make_live_note(
        created_by=owner, access_mode=LiveNote.ACCESS_RESTRICTED, **overrides
    )
    make_live_collaborator(note, owner, role=LiveNoteCollaborator.ROLE_OWNER)
    return note


def make_vault_note(user, **overrides):
    """Create a VaultNote with valid ciphertext defaults for tests."""
    data = {
        "user": user,
        "content": VALID_CONTENT_B64,
        "iv": VALID_IV_B64,
    }
    data.update(overrides)
    return VaultNote.objects.create(**data)


def make_vault_index(user, **overrides):
    """Create a VaultIndex with valid ciphertext defaults for tests."""
    data = {
        "user": user,
        "encrypted_data": VALID_CONTENT_B64,
        "iv": VALID_IV_B64,
    }
    data.update(overrides)
    return VaultIndex.objects.create(**data)
