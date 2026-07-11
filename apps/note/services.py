"""
Business logic and service functions for the note sharing application.

Mirrors the structure of ``apps.passwd.services``. All cryptographic
operations happen client-side; these functions only move note bodies in and
out of the database. Encrypted notes are opaque ciphertext to the server;
plain-text notes are stored as-is, which the user explicitly opted into.
"""

import logging

from django.db.models import F, QuerySet
from django.utils import timezone

from apps.auth.models import User

from .constants import DEFAULT_EXPIRY, EXPIRY_MAP
from .models import SharedNote

logger = logging.getLogger(__name__)


def create_note(
    *,
    content: str,
    iv: str = "",
    is_encrypted: bool = True,
    expiry_key: str = DEFAULT_EXPIRY,
    created_by: User | None = None,
) -> SharedNote:
    """Create and store a shared note.

    The expiry key is looked up in ``EXPIRY_MAP`` (falling back to the default
    when unknown) and turned into an absolute ``expires_at`` timestamp.

    Args:
        content (str): Base64 ciphertext for an encrypted note or raw Markdown
            for a plain-text note.
        iv (str): Base64-encoded initialization vector. Plain-text notes use an
            empty string.
        is_encrypted (bool): Whether ``content`` was encrypted client-side.
        expiry_key (str): Key in ``EXPIRY_MAP``, such as ``"1day"``. Unknown
            keys use ``DEFAULT_EXPIRY``.
        created_by (User | None): Authenticated owner, or ``None`` for an
            anonymous note.

    Returns:
        SharedNote: The validated and persisted note.

    Raises:
        ValidationError: If the note fields or encryption mode are invalid.
    """
    delta = EXPIRY_MAP.get(expiry_key, EXPIRY_MAP[DEFAULT_EXPIRY])
    expires_at = timezone.now() + delta

    note = SharedNote(
        content=content,
        iv=iv,
        is_encrypted=is_encrypted,
        expires_at=expires_at,
        created_by=created_by,
    )
    note.full_clean()
    note.save()
    return note


def expired_notes(*, now=None) -> QuerySet[SharedNote]:
    """Return notes whose expiry time has passed.

    Single source of truth for "what counts as expired", shared by the cleanup
    helper and the ``delete_expired_notes`` management command so the cutoff is
    defined in exactly one place.

    Args:
        now (datetime.datetime | None): Expiry cutoff. The current time is used
            when omitted or ``None``.

    Returns:
        QuerySet[SharedNote]: Lazily evaluated expired notes.
    """
    return SharedNote.objects.filter(expires_at__lte=(now or timezone.now()))


def delete_expired_notes(*, now=None, batch_size=None) -> int:
    """Delete notes whose expiry time has passed.

    Args:
        now (datetime.datetime | None): Expiry cutoff. The current time is used
            when omitted or ``None``.
        batch_size (int | None): Number of rows to delete per batch. ``None``
            deletes all matching rows in one operation.

    Returns:
        int: Number of deleted ``SharedNote`` rows.
    """
    queryset = expired_notes(now=now)

    if batch_size is None:
        deleted_count = queryset.count()
        if deleted_count:
            queryset.delete()
        return deleted_count

    return _delete_in_batches(queryset, batch_size)


def _delete_in_batches(queryset: QuerySet[SharedNote], batch_size: int) -> int:
    """Delete a queryset in fixed-size batches.

    Args:
        queryset (QuerySet[SharedNote]): Rows eligible for deletion.
        batch_size (int): Maximum rows selected for each delete operation.

    Returns:
        int: Total number of deleted model rows.
    """
    total_deleted = 0
    while True:
        batch_ids = list(queryset.values_list("pk", flat=True)[:batch_size])
        if not batch_ids:
            break
        deleted, _ = SharedNote.objects.filter(pk__in=batch_ids).delete()
        total_deleted += deleted
    return total_deleted


def register_note_access(pk) -> None:
    """Atomically increment a note's access counter.

    Uses an ``F`` expression so concurrent retrievals don't lose updates.

    Args:
        pk (uuid.UUID | str): Primary key of the accessed note. An unknown key
            is a no-op.

    Returns:
        None: The counter is updated directly in the database.
    """
    SharedNote.objects.filter(pk=pk).update(access_count=F("access_count") + 1)
