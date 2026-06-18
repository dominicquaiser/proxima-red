"""
Business logic and service functions for the password sharing application.

This module separates share/vault persistence and export concerns from the
views, mirroring ``apps.auth.services``. All cryptographic operations happen
client-side; these functions only move opaque ciphertext in and out of the
database (zero-knowledge architecture).
"""

import logging
from typing import Any

from django.db.models import F, QuerySet
from django.utils import timezone

from apps.auth.models import User
from apps.core.encoding import encode_base64

from .constants import DEFAULT_EXPIRY, EXPIRY_MAP
from .models import ServiceData, SharedPassword

logger = logging.getLogger(__name__)


def serialize_service_data(
    service_data: ServiceData, *, include_updated_at: bool = False
) -> dict[str, Any]:
    """Return the encrypted vault blob in the shape expected by clients/exports."""
    payload: dict[str, Any] = {
        "encrypted_data": service_data.encrypted_data,
        "iv": encode_base64(bytes(service_data.iv)),
    }
    if include_updated_at:
        payload["updated_at"] = service_data.updated_at.isoformat()
    return payload


def create_share(
    *,
    encrypted_data: str,
    iv: str,
    encrypted_title: str = "",
    title_iv: str = "",
    expiry_key: str = DEFAULT_EXPIRY,
    created_by: User | None = None,
) -> SharedPassword:
    """
    Create and store an encrypted password share.

    The expiry key is looked up in ``EXPIRY_MAP`` (falling back to the default
    when unknown) and turned into an absolute ``expires_at`` timestamp.

    Args:
        encrypted_data: Client-side encrypted password (Base64 ciphertext).
        iv: Base64-encoded initialization vector for the password.
        encrypted_title: Optional Base64 ciphertext for the title.
        title_iv: Optional Base64 IV for the title.
        expiry_key: One of the keys in ``EXPIRY_MAP`` (e.g. ``"1day"``).
        created_by: Authenticated owner, or None for anonymous shares.

    Returns:
        The created ``SharedPassword`` instance.
    """
    delta = EXPIRY_MAP.get(expiry_key, EXPIRY_MAP[DEFAULT_EXPIRY])
    expires_at = timezone.now() + delta

    share = SharedPassword(
        encrypted_data=encrypted_data,
        iv=iv,
        encrypted_title=encrypted_title,
        title_iv=title_iv,
        expires_at=expires_at,
        created_by=created_by,
    )
    share.full_clean()
    share.save()
    return share


def expired_shares(*, now=None) -> QuerySet[SharedPassword]:
    """
    Return the queryset of shares whose expiry time has passed.

    Single source of truth for "what counts as expired", shared by the cleanup
    helpers and the ``delete_expired`` management command (count, statistics, and
    dry-run samples) so the cutoff is defined in exactly one place.

    Args:
        now: Optional timestamp used as the expiry cutoff (defaults to now).

    Returns:
        A ``SharedPassword`` queryset of the expired rows.
    """
    return SharedPassword.objects.filter(expires_at__lte=(now or timezone.now()))


def delete_expired_shares(*, now=None, batch_size=None) -> int:
    """
    Delete shares whose expiry time has passed.

    Args:
        now: Optional timestamp used as the expiry cutoff.
        batch_size: When set, delete in chunks of this many rows to bound the
            memory and lock footprint on a large backlog; when ``None`` (the
            default) delete in a single query.

    Returns:
        Number of ``SharedPassword`` rows deleted.
    """
    queryset = expired_shares(now=now)

    if batch_size is None:
        deleted_count = queryset.count()
        if deleted_count:
            queryset.delete()
        return deleted_count

    return _delete_in_batches(queryset, batch_size)


def _delete_in_batches(queryset: QuerySet[SharedPassword], batch_size: int) -> int:
    """Delete ``queryset`` rows in chunks of ``batch_size``; return the total deleted."""
    total_deleted = 0
    while True:
        batch_ids = list(queryset.values_list("pk", flat=True)[:batch_size])
        if not batch_ids:
            break
        deleted, _ = SharedPassword.objects.filter(pk__in=batch_ids).delete()
        total_deleted += deleted
    return total_deleted


def delete_user_share(user: User, share_id) -> bool:
    """
    Delete a share owned by ``user``.

    Scoping the delete to ``created_by=user`` is the authorization gate: a user
    can only revoke their own shares, and an unknown, foreign, or already-deleted
    id is a harmless no-op (the operation is idempotent).

    Args:
        user: The authenticated owner requesting the deletion.
        share_id: Primary key (UUID) of the share to delete.

    Returns:
        ``True`` if a row was deleted, ``False`` if nothing matched.
    """
    deleted, _ = SharedPassword.objects.filter(pk=share_id, created_by=user).delete()
    return bool(deleted)


def register_share_access(pk) -> None:
    """
    Atomically increment a share's access counter.

    Uses an ``F`` expression so concurrent retrievals don't lose updates.

    Args:
        pk: Primary key (UUID) of the share that was accessed.
    """
    SharedPassword.objects.filter(pk=pk).update(access_count=F("access_count") + 1)


def get_user_vault_data(user: User) -> dict[str, Any] | None:
    """
    Return the user's encrypted vault blob for the client, or None.

    Args:
        user: The owning user.

    Returns:
        A dict with ``encrypted_data`` and a Base64-encoded ``iv``, or ``None``
        when the user has no stored vault data yet.
    """
    try:
        service_data = ServiceData.objects.get(user=user)
    except ServiceData.DoesNotExist:
        return None

    return serialize_service_data(service_data)


def save_user_vault_data(user: User, encrypted_data: str, iv: bytes) -> ServiceData:
    """
    Create or update the user's encrypted vault data.

    Args:
        user: The owning user.
        encrypted_data: Client-encrypted vault blob (Base64 ciphertext).
        iv: Raw initialization vector bytes for the blob.

    Returns:
        The created or updated ``ServiceData`` instance.
    """
    try:
        service_data = ServiceData.objects.get(user=user)
        service_data.encrypted_data = encrypted_data
        service_data.iv = iv
    except ServiceData.DoesNotExist:
        service_data = ServiceData(user=user, encrypted_data=encrypted_data, iv=iv)
    service_data.full_clean()
    service_data.save()
    return service_data


def build_user_export(user: User) -> dict[str, Any]:
    """
    Build a GDPR data-export payload for the user.

    Args:
        user: The user whose data should be exported.

    Returns:
        A JSON-serializable dict with account metadata and, when present, the
        user's encrypted vault blob (the server cannot decrypt it).
    """
    export: dict[str, Any] = {
        "exported_at": timezone.now().isoformat(),
        "account": {
            "user_id": user.user_id,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat(),
        },
        "vault": None,
    }

    try:
        service_data = ServiceData.objects.get(user=user)
    except ServiceData.DoesNotExist:
        return export

    export["vault"] = serialize_service_data(service_data, include_updated_at=True)
    return export
