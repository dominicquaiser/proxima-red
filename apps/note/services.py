"""
Business logic and service functions for the note sharing application.

Mirrors the structure of ``apps.passwd.services``. All cryptographic
operations happen client-side; these functions only move note bodies in and
out of the database. Encrypted notes are opaque ciphertext to the server;
plain-text notes are stored as-is, which the user explicitly opted into.

Grouped into four sections, in this order: shared notes (create, expire,
count accesses), live notes (the CRDT snapshot/update-log sync backing
editable share links), named collaborators (restricted live notes, M4), and
the authenticated note vault.

Two conventions run through the live-note and collaboration functions:

- Anything that mutates a live note's log or key takes ``select_for_update()``
  on the ``LiveNote`` row. That single lock is what makes update ids a usable
  sync cursor, the tail caps sound, and re-keys atomic.
- Rejections raise ``ValidationError`` with a stable ``code`` (``stale_epoch``,
  ``pending_tail_full``, ``rekey_stale``, ...). The codes are this layer's
  vocabulary for what went wrong; ``apps.note.views`` maps them to HTTP
  statuses and the consumer maps them to frames, so neither transport needs to
  re-derive the reason.
"""

import logging
import uuid as uuid_module
from datetime import timedelta
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F, Max, QuerySet, Sum
from django.db.models.functions import Length
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.auth.models import User, UserKeyPair

from .constants import (
    DEFAULT_EXPIRY,
    EXPIRY_MAP,
    LOG_LIVE_EXPIRED_DELETED,
    MAX_COLLABORATORS_PER_NOTE,
    MAX_LIVE_PENDING_LENGTH,
    MAX_LIVE_PENDING_UPDATES,
    MAX_VAULT_NOTES_PER_USER,
    VAULT_TRASH_RETENTION_DAYS,
)
from .models import (
    LiveNote,
    LiveNoteCollaborator,
    LiveNoteUpdate,
    SharedNote,
    VaultIndex,
    VaultNote,
)

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


def _delete_in_batches(queryset: QuerySet, batch_size: int) -> int:
    """Delete a queryset in fixed-size batches.

    Shared by the shared-note and live-note expiry sweeps; the model is read
    off the queryset. The count covers that model's rows only, so a cascade
    (live-note updates) doesn't inflate the reported number.

    Args:
        queryset (QuerySet): Rows eligible for deletion.
        batch_size (int): Maximum rows selected for each delete operation.

    Returns:
        int: Total number of deleted rows of the queryset's own model.
    """
    model = queryset.model
    total_deleted = 0
    while True:
        batch_ids = list(queryset.values_list("pk", flat=True)[:batch_size])
        if not batch_ids:
            break
        _, per_model = model.objects.filter(pk__in=batch_ids).delete()
        total_deleted += per_model.get(model._meta.label, 0)
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


# ── Live notes (editable share links) ──────────────────────────────────────


def create_live_note(
    *,
    snapshot: str,
    snapshot_iv: str,
    expiry_key: str = DEFAULT_EXPIRY,
    created_by: User | None = None,
) -> LiveNote:
    """Create and store a live note seeded with an encrypted Yjs snapshot.

    Mirrors :func:`create_note`: the expiry key is looked up in ``EXPIRY_MAP``
    (falling back to the default when unknown) and fixed at creation.

    Args:
        snapshot (str): Base64 ciphertext of the encoded Yjs document state.
        snapshot_iv (str): Base64-encoded initialization vector.
        expiry_key (str): Key in ``EXPIRY_MAP``, such as ``"1day"``. Unknown
            keys use ``DEFAULT_EXPIRY``.
        created_by (User | None): Authenticated creator, or ``None`` for an
            anonymous live note.

    Returns:
        LiveNote: The validated and persisted live note.

    Raises:
        ValidationError: If the snapshot fields are invalid.
    """
    delta = EXPIRY_MAP.get(expiry_key, EXPIRY_MAP[DEFAULT_EXPIRY])
    expires_at = timezone.now() + delta

    note = LiveNote(
        snapshot=snapshot,
        snapshot_iv=snapshot_iv,
        expires_at=expires_at,
        created_by=created_by,
    )
    note.full_clean()
    note.save()
    return note


def register_live_note_access(pk) -> None:
    """Atomically increment a live note's access counter.

    Args:
        pk (uuid.UUID | str): Primary key of the opened live note. An unknown
            key is a no-op.

    Returns:
        None: The counter is updated directly in the database.
    """
    LiveNote.objects.filter(pk=pk).update(access_count=F("access_count") + 1)


def get_active_live_note(pk) -> LiveNote | None:
    """Fetch a live note, deleting and dropping it if it has expired.

    The single "does this note exist right now" gate shared by both
    transports: the HTTP endpoints' ``_live_note_or_404_json`` and the
    consumer's ``_load_active_note`` both call it, so the expire-on-read
    behaviour (and the deletion log) lives in exactly one place. Unknown and
    expired are indistinguishable here — both return ``None`` — because each
    transport renders both as its terminal "gone" signal (HTTP 404 / WS close
    ``WS_CLOSE_NOT_FOUND``).

    Args:
        pk (uuid.UUID | str): Primary key of the requested live note.

    Returns:
        LiveNote | None: The active note, or ``None`` when it is unknown or
        expired (an expired row is deleted as a side effect).
    """
    note = LiveNote.objects.filter(pk=pk).first()
    if note is None:
        return None
    if note.is_expired():
        note.delete()
        logger.info(LOG_LIVE_EXPIRED_DELETED, pk)
        return None
    return note


def _serialize_live_updates(rows: list[LiveNoteUpdate]) -> list[dict[str, Any]]:
    """Return update rows in the wire shape of the sync protocol.

    Args:
        rows (list[LiveNoteUpdate]): Update rows in ascending id order.

    Returns:
        list[dict[str, Any]]: ``seq`` (the row id, the client's cursor),
        ``payload``, and ``iv`` per row.
    """
    return [{"seq": row.pk, "payload": row.payload, "iv": row.iv} for row in rows]


def live_note_state(note: LiveNote) -> dict[str, Any]:
    """Return a live note's full sync state for a joining client.

    Args:
        note (LiveNote): The live note being opened.

    Returns:
        dict[str, Any]: The encrypted snapshot pair, the pending update tail
        (ascending), ``seq`` (the client's initial poll cursor: the last
        update's id, or ``snapshot_seq`` when the tail is empty), ``pending``
        (tail row count, the client's compaction signal), and the expiry.
    """
    rows = list(note.updates.all())
    return {
        "snapshot": note.snapshot,
        "snapshot_iv": note.snapshot_iv,
        "updates": _serialize_live_updates(rows),
        "seq": rows[-1].pk if rows else note.snapshot_seq,
        "pending": len(rows),
        "key_epoch": note.key_epoch,
        "expires_at": note.expires_at.isoformat(),
    }


def live_updates_since(note: LiveNote, since: int) -> dict[str, Any]:
    """Return the updates a polling client has not seen yet.

    A cursor older than ``snapshot_seq`` means the rows the client is missing
    were compacted away; the response then carries the snapshot as well and
    the entire pending tail. Applying a snapshot is just another Yjs update,
    so the client needs no special resync state.

    Args:
        note (LiveNote): The live note being polled.
        since (int): The client's cursor (last update id it has applied, or
            the ``seq`` it received when loading state).

    Returns:
        dict[str, Any]: ``updates`` (ascending rows with id greater than the
        cursor), the client's new ``seq`` cursor, ``pending`` (total tail
        size), and, only on resync, the ``snapshot``/``snapshot_iv`` pair.
    """
    resync = since < note.snapshot_seq
    query = note.updates.all() if resync else note.updates.filter(id__gt=since)
    rows = list(query)

    if rows:
        seq = rows[-1].pk
    elif resync:
        seq = note.snapshot_seq
    else:
        seq = since

    payload: dict[str, Any] = {
        "updates": _serialize_live_updates(rows),
        "seq": seq,
        "pending": len(rows) if resync else note.updates.count(),
        "key_epoch": note.key_epoch,
    }
    if resync:
        payload["snapshot"] = note.snapshot
        payload["snapshot_iv"] = note.snapshot_iv
    return payload


def append_live_update(
    pk, *, payload: str, iv: str, key_epoch: int = 0
) -> tuple[LiveNoteUpdate, int, int]:
    """Append one encrypted Yjs update to a live note's log.

    Runs inside a transaction holding a row lock on the parent note. The lock
    serializes appends per note, which the sync cursor depends on: without it,
    two concurrent inserts could commit out of id order and a poll landing
    between the commits would advance its cursor past the not-yet-visible
    smaller id, skipping that update forever. (``select_for_update`` is a
    no-op on SQLite, where the global write lock serializes anyway; it matters
    on production Postgres.) The same lock makes the tail-cap check sound.

    The returned ``prev_seq`` is the newest id already in the log when this
    row was inserted (the note's ``snapshot_seq`` for an empty tail),
    computed under the same lock so consecutive appends chain gaplessly:
    row N's ``prev_seq`` is row N-1's ``seq``. WebSocket pushes carry the
    pair so a client can detect a missed frame (``prev_seq`` ahead of its
    cursor) and gap-heal with one HTTP ``?since=`` fetch.

    Args:
        pk (uuid.UUID | str): Primary key of the live note.
        payload (str): Base64 ciphertext of one merged Yjs update.
        iv (str): Base64-encoded initialization vector.
        key_epoch (int): The document-key generation the client encrypted
            under. Must match the note's current ``key_epoch`` (both 0 for
            link-mode and pre-M4 clients, so the check is invisible there);
            a mismatch means a rekey happened and the client is on a stale
            key, so reject rather than store ciphertext no current reader can
            decrypt.

    Returns:
        tuple[LiveNoteUpdate, int, int]: The persisted row, the pending tail
        size including it, and ``prev_seq``.

    Raises:
        LiveNote.DoesNotExist: If the note is unknown (or was deleted by the
            expiry sweep between the caller's fetch and the lock).
        ValidationError: Code ``stale_epoch`` when the note was re-keyed,
            code ``pending_tail_full`` when the tail is at capacity (the
            client must compact first), or if the fields fail model
            validation.
    """
    with transaction.atomic():
        note = LiveNote.objects.select_for_update().get(pk=pk)

        if key_epoch != note.key_epoch:
            raise ValidationError(
                _("The document key has changed (stale epoch)."), code="stale_epoch"
            )

        pending_count = note.updates.count()
        if pending_count >= MAX_LIVE_PENDING_UPDATES:
            raise ValidationError(
                _("Update log is full (%(max)d pending updates).")
                % {"max": MAX_LIVE_PENDING_UPDATES},
                code="pending_tail_full",
            )
        prev_seq = note.snapshot_seq
        if pending_count:
            tail = note.updates.aggregate(
                total=Sum(Length("payload")), newest=Max("id")
            )
            prev_seq = tail["newest"]
            if (tail["total"] or 0) + len(payload) > MAX_LIVE_PENDING_LENGTH:
                raise ValidationError(
                    _("Update log is full (%(max)d pending characters).")
                    % {"max": MAX_LIVE_PENDING_LENGTH},
                    code="pending_tail_full",
                )

        row = LiveNoteUpdate(note=note, payload=payload, iv=iv)
        row.full_clean()
        row.save()
        return row, pending_count + 1, prev_seq


def save_live_snapshot(pk, *, snapshot: str, snapshot_iv: str, covers_seq: int) -> int:
    """Replace a live note's snapshot with a client's compaction and prune the log.

    First valid writer wins: a compaction whose ``covers_seq`` is not newer
    than the stored ``snapshot_seq`` lost a race with another client and is
    rejected (harmlessly, since the winner's snapshot already covers it). A
    ``covers_seq`` beyond the newest update row would claim to cover updates
    that don't exist and is likewise rejected, preserving the invariant that
    rows with ``id <= snapshot_seq`` never exist.

    The snapshot may legitimately contain *more* than ``covers_seq`` (the
    compacting client's own unflushed edits): a CRDT superset is safe, as the
    invariant only requires that it covers every row being deleted. Holding
    the same row lock as :func:`append_live_update` guarantees no row at or
    below ``covers_seq`` can appear after the check.

    Args:
        pk (uuid.UUID | str): Primary key of the live note.
        snapshot (str): Base64 ciphertext of the full encoded Yjs state.
        snapshot_iv (str): Base64-encoded initialization vector.
        covers_seq (int): The compacting client's applied cursor: every update
            row with an id at or below it is folded into the snapshot.

    Returns:
        int: Number of pruned update rows.

    Raises:
        LiveNote.DoesNotExist: If the note is unknown or already deleted.
        ValidationError: Codes ``stale_snapshot`` (lost compaction race) or
            ``covers_unknown_updates`` (cursor beyond the newest row), or if
            the fields fail model validation. Nothing is persisted.
    """
    with transaction.atomic():
        note = LiveNote.objects.select_for_update().get(pk=pk)

        if covers_seq <= note.snapshot_seq:
            raise ValidationError(
                _("A newer snapshot already covers these updates."),
                code="stale_snapshot",
            )
        newest = note.updates.aggregate(newest=Max("id"))["newest"]
        if newest is None or covers_seq > newest:
            raise ValidationError(
                _("The snapshot claims to cover updates that do not exist."),
                code="covers_unknown_updates",
            )

        note.snapshot = snapshot
        note.snapshot_iv = snapshot_iv
        note.snapshot_seq = covers_seq
        note.full_clean()
        note.save()

        deleted, _row_counts = note.updates.filter(id__lte=covers_seq).delete()
        return deleted


def expired_live_notes(*, now=None) -> QuerySet[LiveNote]:
    """Return live notes whose expiry time has passed.

    The live-note counterpart of :func:`expired_notes`, sharing its single-
    source-of-truth role for the cutoff.

    Args:
        now (datetime.datetime | None): Expiry cutoff. The current time is used
            when omitted or ``None``.

    Returns:
        QuerySet[LiveNote]: Lazily evaluated expired live notes.
    """
    return LiveNote.objects.filter(expires_at__lte=(now or timezone.now()))


def delete_expired_live_notes(*, now=None, batch_size=None) -> int:
    """Delete live notes whose expiry time has passed.

    Update rows go with their note via the FK cascade; the returned count is
    live notes only.

    Args:
        now (datetime.datetime | None): Expiry cutoff. The current time is used
            when omitted or ``None``.
        batch_size (int | None): Number of rows to delete per batch. ``None``
            deletes all matching rows in one operation.

    Returns:
        int: Number of deleted ``LiveNote`` rows.
    """
    queryset = expired_live_notes(now=now)

    if batch_size is None:
        deleted_count = queryset.count()
        if deleted_count:
            queryset.delete()
        return deleted_count

    return _delete_in_batches(queryset, batch_size)


# ── Named collaborators (restricted live notes, M4) ─────────────────────────


def get_live_collaborator(note: LiveNote, user_id: str) -> LiveNoteCollaborator | None:
    """Return a user's collaborator row on a note, if any.

    Args:
        note (LiveNote): The live note.
        user_id (str): The public 8-digit user id.

    Returns:
        LiveNoteCollaborator | None: The grant row, or ``None``.
    """
    return (
        note.collaborators.filter(user__user_id=user_id).select_related("user").first()
    )


def serialize_collaborators(note: LiveNote) -> list[dict[str, Any]]:
    """Return a note's collaborators for the management UI (no key material).

    Args:
        note (LiveNote): The restricted live note.

    Returns:
        list[dict[str, Any]]: ``user_id`` and ``role`` per collaborator.
    """
    return [
        {"user_id": c.user.user_id, "role": c.role}
        for c in note.collaborators.select_related("user").all()
    ]


def get_live_note_wrap(note: LiveNote, user_id: str) -> dict[str, Any] | None:
    """Return the current-epoch wrapped document key for a collaborator.

    Args:
        note (LiveNote): The restricted live note.
        user_id (str): The requesting collaborator's user id.

    Returns:
        dict[str, Any] | None: The wrap triple plus ``key_epoch``, or ``None``
        when the user is not a collaborator or holds only a stale wrap (which
        can happen briefly if they read between a revoke and their re-fetch;
        a stale wrap is treated as no access).
    """
    row = get_live_collaborator(note, user_id)
    if row is None or row.key_epoch != note.key_epoch:
        return None
    return {
        "wrapped_key": row.wrapped_key,
        "wrap_iv": row.wrap_iv,
        "ephemeral_public_key": row.ephemeral_public_key,
        "key_epoch": row.key_epoch,
    }


def restrict_live_note(pk, *, owner_user: User, wrap: dict) -> LiveNoteCollaborator:
    """Switch a link note to restricted access, seeding the owner's wrap.

    Only the note's creator may restrict it (there are no collaborator rows
    yet, so ``created_by`` is the authority). The current document key is
    wrapped to the owner's own public key. There is no key rotation, so
    existing tabs holding the fragment key keep working; the gate is what
    changes.

    Args:
        pk: Primary key of the live note.
        owner_user (User): The authenticated creator.
        wrap (dict): ``wrapped_key``, ``wrap_iv``, ``ephemeral_public_key``:
            the current doc key wrapped to ``owner_user``'s public key.

    Returns:
        LiveNoteCollaborator: The owner's grant row.

    Raises:
        LiveNote.DoesNotExist: Unknown note.
        ValidationError: Codes ``not_owner`` (not the creator) or
            ``already_restricted``.
    """
    with transaction.atomic():
        note = LiveNote.objects.select_for_update().get(pk=pk)
        if note.created_by_id != owner_user.id:
            raise ValidationError(_("Only the owner can restrict."), code="not_owner")
        if note.access_mode == LiveNote.ACCESS_RESTRICTED:
            raise ValidationError(_("Already restricted."), code="already_restricted")

        note.access_mode = LiveNote.ACCESS_RESTRICTED
        note.save(update_fields=["access_mode", "updated_at"])
        return LiveNoteCollaborator.objects.create(
            note=note,
            user=owner_user,
            role=LiveNoteCollaborator.ROLE_OWNER,
            wrapped_key=wrap["wrapped_key"],
            wrap_iv=wrap["wrap_iv"],
            ephemeral_public_key=wrap["ephemeral_public_key"],
            key_epoch=note.key_epoch,
        )


def unrestrict_live_note(pk, *, owner_user: User) -> None:
    """Revert a restricted note to link access, dropping all collaborator rows.

    Owner-only. The document key is unchanged (whoever holds the fragment key
    keeps access: the honest consequence, surfaced in the UI copy), so this is
    a gate change, not a re-key.

    Args:
        pk: Primary key of the live note.
        owner_user (User): The authenticated owner.

    Raises:
        LiveNote.DoesNotExist: Unknown note.
        ValidationError: Codes ``not_owner`` or ``not_restricted``.
    """
    with transaction.atomic():
        note = LiveNote.objects.select_for_update().get(pk=pk)
        _require_owner(note, owner_user)
        if note.access_mode != LiveNote.ACCESS_RESTRICTED:
            raise ValidationError(_("Not restricted."), code="not_restricted")
        note.access_mode = LiveNote.ACCESS_LINK
        note.save(update_fields=["access_mode", "updated_at"])
        note.collaborators.all().delete()


def add_live_collaborator(pk, *, owner_user: User, invitee_user_id: str, wrap: dict):
    """Grant a named collaborator access by wrapping the doc key to them.

    Owner-only. Idempotent-ish: re-inviting an existing collaborator refreshes
    their wrap. Capped at ``MAX_COLLABORATORS_PER_NOTE`` (which also bounds the
    revocation rekey body, since that re-wraps to everyone remaining).

    Args:
        pk: Primary key of the live note.
        owner_user (User): The authenticated owner.
        invitee_user_id (str): The invitee's public user id.
        wrap (dict): The current doc key wrapped to the invitee's public key.

    Returns:
        LiveNoteCollaborator: The created or refreshed grant.

    Raises:
        LiveNote.DoesNotExist: Unknown note.
        User.DoesNotExist: Unknown invitee.
        ValidationError: Codes ``not_owner``, ``not_restricted``, or
            ``collab_limit``.
    """
    with transaction.atomic():
        note = LiveNote.objects.select_for_update().get(pk=pk)
        _require_owner(note, owner_user)
        if note.access_mode != LiveNote.ACCESS_RESTRICTED:
            raise ValidationError(_("Not restricted."), code="not_restricted")

        invitee = User.objects.get(user_id=invitee_user_id)
        existing = note.collaborators.filter(user=invitee).first()
        if (
            existing is None
            and note.collaborators.count() >= MAX_COLLABORATORS_PER_NOTE
        ):
            raise ValidationError(_("Collaborator limit reached."), code="collab_limit")

        collaborator, _created = LiveNoteCollaborator.objects.update_or_create(
            note=note,
            user=invitee,
            defaults={
                "wrapped_key": wrap["wrapped_key"],
                "wrap_iv": wrap["wrap_iv"],
                "ephemeral_public_key": wrap["ephemeral_public_key"],
                "key_epoch": note.key_epoch,
                # Never demote an existing owner; a fresh invite is an editor.
                "role": existing.role if existing else LiveNoteCollaborator.ROLE_EDITOR,
            },
        )
        return collaborator


def rekey_live_note(
    pk,
    *,
    owner_user: User,
    snapshot: str,
    snapshot_iv: str,
    covers_seq: int,
    key_epoch: int,
    remove_user_id: str | None,
    wraps: list[dict],
) -> int:
    """Rotate a restricted note's document key: the atomic revocation path.

    One transaction under the append/snapshot row lock does everything a
    revocation needs, so no collaborator is ever stranded between steps:

    1. verify the caller owns the note and ``key_epoch`` is exactly the next
       generation;
    2. verify ``covers_seq`` equals the newest update id, **strictly**,
       unlike ``save_live_snapshot`` (which permits a superset): a mixed-key
       log is not allowed, so the new snapshot must fold in the entire tail;
    3. write the snapshot under the new key, bump ``key_epoch``, delete the
       whole tail (all under the old key);
    4. delete the revoked collaborator (if any);
    5. re-wrap the new doc key to every remaining collaborator (the ``wraps``
       must cover exactly them: a missing wrap would strand someone, an extra
       one references a non-collaborator).

    A racing ``append`` bumps the newest id, so step 2 fails with 409 and the
    client flushes and retries; the rekey never half-applies.

    Args:
        pk: Primary key of the live note.
        owner_user (User): The authenticated owner.
        snapshot / snapshot_iv (str): The full state re-encrypted under the
            new key.
        covers_seq (int): Must equal the newest tail id (or ``snapshot_seq``
            for an empty tail).
        key_epoch (int): Must equal the note's current epoch + 1.
        remove_user_id (str | None): Collaborator to revoke, or ``None`` for a
            plain rotation.
        wraps (list[dict]): ``user_id`` + wrap triple for every remaining
            collaborator.

    Returns:
        int: The new ``key_epoch``.

    Raises:
        LiveNote.DoesNotExist: Unknown note.
        ValidationError: Codes ``not_owner``, ``not_restricted``,
            ``rekey_epoch``, ``rekey_stale``, or ``wraps_mismatch``.
    """
    with transaction.atomic():
        note = LiveNote.objects.select_for_update().get(pk=pk)

        # Guards (all under the row lock, cheapest first): only the owner may
        # rekey, only a restricted note has keys to rotate, the epoch must be
        # exactly the next generation, and the snapshot must fold in the whole
        # tail (strict equality — a mixed-key log is forbidden).
        _require_owner(note, owner_user)
        if note.access_mode != LiveNote.ACCESS_RESTRICTED:
            raise ValidationError(_("Not restricted."), code="not_restricted")
        if key_epoch != note.key_epoch + 1:
            raise ValidationError(_("Unexpected key epoch."), code="rekey_epoch")

        newest = note.updates.aggregate(newest=Max("id"))["newest"]
        expected = newest if newest is not None else note.snapshot_seq
        if covers_seq != expected:
            raise ValidationError(
                _("The rekey snapshot must cover the whole tail."), code="rekey_stale"
            )

        # Work (order matters): validate the wrap set against the survivors,
        # swap in the new-key snapshot and drop the old-key tail, remove the
        # revoked row, then re-wrap the new key to the survivors.
        survivors = _rekey_survivors(note, remove_user_id, wraps)
        _write_rekeyed_snapshot(
            note,
            snapshot=snapshot,
            snapshot_iv=snapshot_iv,
            covers_seq=covers_seq,
            key_epoch=key_epoch,
        )
        if remove_user_id is not None:
            note.collaborators.filter(user__user_id=remove_user_id).delete()
        _rewrap_collaborators(survivors, wraps, key_epoch)
        return key_epoch


def _rekey_survivors(
    note: LiveNote, remove_user_id: str | None, wraps: list[dict]
) -> list[LiveNoteCollaborator]:
    """Return the collaborators a rekey must re-wrap, validating the wrap set.

    Called under the ``LiveNote`` row lock by :func:`rekey_live_note`, before
    anything is written. The survivors are every current collaborator except
    the revoked one; ``wraps`` must carry a new wrap for exactly them — a
    missing wrap would strand a survivor, an extra one references a
    non-collaborator.

    Args:
        note (LiveNote): The locked live note.
        remove_user_id (str | None): Collaborator being revoked, or ``None``
            for a plain rotation.
        wraps (list[dict]): ``user_id`` + wrap triple per intended survivor.

    Returns:
        list[LiveNoteCollaborator]: The survivor rows (revoked user excluded).

    Raises:
        ValidationError: Code ``wraps_mismatch`` when ``wraps`` does not cover
            exactly the survivors.
    """
    remaining = list(note.collaborators.select_related("user").all())
    if remove_user_id is not None:
        remaining = [c for c in remaining if c.user.user_id != remove_user_id]
    if {w["user_id"] for w in wraps} != {c.user.user_id for c in remaining}:
        raise ValidationError(
            _("Wraps must cover exactly the remaining collaborators."),
            code="wraps_mismatch",
        )
    return remaining


def _write_rekeyed_snapshot(
    note: LiveNote,
    *,
    snapshot: str,
    snapshot_iv: str,
    covers_seq: int,
    key_epoch: int,
) -> None:
    """Store the new-key snapshot, bump the epoch, and drop the whole tail.

    Called under the ``LiveNote`` row lock by :func:`rekey_live_note` once the
    guards pass. Every existing update row is under the old key; the strict
    ``covers_seq`` check guarantees the snapshot folds in the entire tail, so
    the rows are pruned wholesale rather than mixed with the new key.

    Args:
        note (LiveNote): The locked live note.
        snapshot (str): Full state re-encrypted under the new key.
        snapshot_iv (str): Base64-encoded initialization vector.
        covers_seq (int): The new ``snapshot_seq`` (the whole tail).
        key_epoch (int): The new key generation.
    """
    note.snapshot = snapshot
    note.snapshot_iv = snapshot_iv
    note.snapshot_seq = covers_seq
    note.key_epoch = key_epoch
    note.full_clean()
    note.save()
    note.updates.all().delete()


def _rewrap_collaborators(
    survivors: list[LiveNoteCollaborator], wraps: list[dict], key_epoch: int
) -> None:
    """Re-wrap the new document key to each surviving collaborator.

    Called under the ``LiveNote`` row lock by :func:`rekey_live_note`. The
    caller has already verified ``wraps`` covers exactly ``survivors`` (see
    :func:`_rekey_survivors`), so every survivor has a matching wrap.

    Args:
        survivors (list[LiveNoteCollaborator]): Rows to re-wrap.
        wraps (list[dict]): ``user_id`` + wrap triple per survivor.
        key_epoch (int): The new key generation stamped on each row.
    """
    wraps_by_id = {w["user_id"]: w for w in wraps}
    for collaborator in survivors:
        wrap = wraps_by_id[collaborator.user.user_id]
        collaborator.wrapped_key = wrap["wrapped_key"]
        collaborator.wrap_iv = wrap["wrap_iv"]
        collaborator.ephemeral_public_key = wrap["ephemeral_public_key"]
        collaborator.key_epoch = key_epoch
        collaborator.save(
            update_fields=[
                "wrapped_key",
                "wrap_iv",
                "ephemeral_public_key",
                "key_epoch",
            ]
        )


def _require_owner(note: LiveNote, user: User) -> None:
    """Raise ``ValidationError(code="not_owner")`` unless ``user`` owns ``note``.

    Ownership is the ``owner``-role collaborator row (created at restrict); a
    plain editor or a non-collaborator cannot manage access. Note that
    :func:`restrict_live_note` cannot use this, since it runs before any
    collaborator row exists and checks ``created_by`` instead.

    Args:
        note (LiveNote): The restricted live note.
        user (User): The user whose ownership is asserted.

    Returns:
        None: The user owns the note.

    Raises:
        ValidationError: Code ``not_owner`` when the user holds no owner-role
            collaborator row on the note.
    """
    owner = note.collaborators.filter(
        user=user, role=LiveNoteCollaborator.ROLE_OWNER
    ).exists()
    if not owner:
        raise ValidationError(
            _("Only the owner can manage collaborators."), code="not_owner"
        )


# ── Note vault (authenticated) ─────────────────────────────────────────────


def serialize_vault_index(
    index: VaultIndex, *, include_updated_at: bool = False
) -> dict[str, Any]:
    """Return the encrypted vault index in the shape expected by clients/exports.

    Args:
        index (VaultIndex): The stored index row.
        include_updated_at (bool): Whether to add the last-save timestamp
            (used by the GDPR export).

    Returns:
        dict[str, Any]: ``encrypted_data`` and Base64 ``iv`` (plus
        ``updated_at`` when requested).
    """
    payload: dict[str, Any] = {
        "encrypted_data": index.encrypted_data,
        "iv": index.iv,
    }
    if include_updated_at:
        payload["updated_at"] = index.updated_at.isoformat()
    return payload


def get_vault_index(user: User) -> dict[str, Any] | None:
    """Return the user's encrypted vault index for the client, or ``None``.

    Args:
        user (User): The owning user.

    Returns:
        dict[str, Any] | None: ``encrypted_data`` and ``iv``, or ``None`` when
        the user has no vault index yet.
    """
    try:
        index = VaultIndex.objects.get(user=user)
    except VaultIndex.DoesNotExist:
        return None
    return serialize_vault_index(index)


def save_vault_index(user: User, encrypted_data: str, iv: str) -> VaultIndex:
    """Create or update the user's encrypted vault index.

    Args:
        user (User): The owning user.
        encrypted_data (str): Client-encrypted index JSON (Base64 ciphertext).
        iv (str): Base64-encoded initialization vector.

    Returns:
        VaultIndex: The created or updated index row.

    Raises:
        ValidationError: If the payload fails model validation.
    """
    try:
        index = VaultIndex.objects.get(user=user)
        index.encrypted_data = encrypted_data
        index.iv = iv
    except VaultIndex.DoesNotExist:
        index = VaultIndex(user=user, encrypted_data=encrypted_data, iv=iv)
    index.full_clean()
    index.save()
    return index


def serialize_vault_note(
    note: VaultNote, *, include_content: bool = True
) -> dict[str, Any]:
    """Return a vault note in the shape expected by clients/exports.

    Args:
        note (VaultNote): The stored note row.
        include_content (bool): Whether to include the ciphertext and IV; the
            list endpoint omits them by default so the vault UI can render the
            tree without transferring every document.

    Returns:
        dict[str, Any]: Note id, timestamps, trash state, ciphertext size, and
        optionally the ciphertext + IV.
    """
    payload: dict[str, Any] = {
        "id": str(note.id),
        "created_at": note.created_at.isoformat(),
        "updated_at": note.updated_at.isoformat(),
        # The client reconciles this against the trash flag in its encrypted
        # index on every load, so an interrupted trash/restore self-heals.
        "trashed_at": note.trashed_at.isoformat() if note.trashed_at else None,
        "size": len(note.content),
    }
    if include_content:
        payload["content"] = note.content
        payload["iv"] = note.iv
    return payload


def list_vault_notes(user: User, *, include_content: bool = False) -> list[dict]:
    """Return all of the user's vault notes.

    Args:
        user (User): The owning user.
        include_content (bool): Whether to include each note's ciphertext and
            IV (used by the password-change migration and orphan recovery).

    Returns:
        list[dict]: Serialized notes, most recently updated first.
    """
    return [
        serialize_vault_note(note, include_content=include_content)
        for note in user.vault_notes.all()
    ]


def create_vault_note(user: User, *, content: str, iv: str) -> VaultNote:
    """Create a vault note for the user, enforcing the per-user quota.

    Args:
        user (User): The owning user.
        content (str): Base64 AES-256-GCM ciphertext of the markdown document.
        iv (str): Base64-encoded initialization vector.

    Returns:
        VaultNote: The validated and persisted note.

    Raises:
        ValidationError: If the quota is reached (code ``note_quota``) or the
            fields fail model validation.
    """
    if user.vault_notes.count() >= MAX_VAULT_NOTES_PER_USER:
        raise ValidationError(
            _("Note vault is full (%(max)d notes).")
            % {"max": MAX_VAULT_NOTES_PER_USER},
            code="note_quota",
        )
    note = VaultNote(user=user, content=content, iv=iv)
    note.full_clean()
    note.save()
    return note


def get_vault_note(user: User, pk) -> VaultNote | None:
    """Return one of the user's vault notes, or ``None``.

    Scoping the lookup to ``user`` is the authorization gate: a foreign or
    unknown id is indistinguishable from a missing note.

    Args:
        user (User): The authenticated owner.
        pk (uuid.UUID | str): Primary key of the requested note.

    Returns:
        VaultNote | None: The note, or ``None`` when nothing matched. A
        malformed UUID string reads as "not found" rather than an error, since
        client-supplied ids reach this via the migration payload.
    """
    try:
        return VaultNote.objects.filter(user=user, pk=pk).first()
    except (ValueError, ValidationError):
        return None


def update_vault_note(user: User, pk, *, content: str, iv: str) -> VaultNote | None:
    """Overwrite one of the user's vault notes.

    Args:
        user (User): The authenticated owner.
        pk (uuid.UUID | str): Primary key of the note to update.
        content (str): New Base64 ciphertext.
        iv (str): New Base64-encoded initialization vector.

    Returns:
        VaultNote | None: The updated note, or ``None`` when the id did not
        match one of the user's notes.

    Raises:
        ValidationError: If the fields fail model validation.
    """
    note = get_vault_note(user, pk)
    if note is None:
        return None
    note.content = content
    note.iv = iv
    note.full_clean()
    note.save()
    return note


def delete_vault_note(user: User, pk) -> bool:
    """Delete one of the user's vault notes.

    Owner-scoped and idempotent, like ``apps.passwd.services.delete_user_share``:
    an unknown, foreign, or already-deleted id is a harmless no-op.

    Args:
        user (User): The authenticated owner.
        pk (uuid.UUID | str): Primary key of the note to delete.

    Returns:
        bool: ``True`` if a row was deleted, ``False`` if nothing matched.
    """
    deleted, _row_counts = VaultNote.objects.filter(user=user, pk=pk).delete()
    return bool(deleted)


def set_vault_notes_trashed(user: User, ids, *, trashed: bool) -> int:
    """Move the user's notes to Trash, or restore them.

    One owner-scoped ``UPDATE``, so trashing a whole folder costs a single
    query and a single request. ``QuerySet.update()`` is deliberate: it
    bypasses ``auto_now``, leaving ``updated_at`` alone because moving a note
    to Trash is not a content write.

    Idempotent, like ``delete_vault_note``: unknown, foreign, and already-set
    ids are harmless no-ops. Unparseable ids are dropped rather than raising,
    since these come straight from a client payload.

    Args:
        user (User): The authenticated owner.
        ids (Iterable[uuid.UUID | str]): Primary keys to update.
        trashed (bool): ``True`` stamps ``trashed_at`` with the current server
            time, ``False`` clears it.

    Returns:
        int: Number of rows actually updated.
    """
    valid_ids = []
    for value in ids:
        try:
            valid_ids.append(uuid_module.UUID(str(value)))
        except (AttributeError, TypeError, ValueError):
            continue

    if not valid_ids:
        return 0

    return VaultNote.objects.filter(user=user, pk__in=valid_ids).update(
        trashed_at=timezone.now() if trashed else None
    )


def expired_trashed_vault_notes(*, now=None) -> QuerySet[VaultNote]:
    """Return vault notes that have sat in Trash past the retention window.

    The vault-note counterpart of :func:`expired_notes`, sharing its single-
    source-of-truth role for the cutoff. Active notes (``trashed_at`` null)
    never match: vault notes have no expiry of their own.

    Args:
        now (datetime.datetime | None): Reference time the retention window is
            measured back from. The current time is used when omitted.

    Returns:
        QuerySet[VaultNote]: Lazily evaluated notes due for deletion.
    """
    cutoff = (now or timezone.now()) - timedelta(days=VAULT_TRASH_RETENTION_DAYS)
    return VaultNote.objects.filter(trashed_at__isnull=False, trashed_at__lte=cutoff)


def delete_expired_trashed_vault_notes(*, now=None, batch_size=None) -> int:
    """Delete vault notes that have sat in Trash past the retention window.

    Args:
        now (datetime.datetime | None): Reference time the retention window is
            measured back from. The current time is used when omitted.
        batch_size (int | None): Number of rows to delete per batch. ``None``
            deletes all matching rows in one operation.

    Returns:
        int: Number of deleted ``VaultNote`` rows.
    """
    queryset = expired_trashed_vault_notes(now=now)

    if batch_size is None:
        deleted_count = queryset.count()
        if deleted_count:
            queryset.delete()
        return deleted_count

    return _delete_in_batches(queryset, batch_size)


def migrate_vault_data(
    user: User,
    *,
    notes: list[dict],
    index_payload: dict | None = None,
    keypair_payload: dict | None = None,
) -> int:
    """Re-write vault note ciphertexts (and optionally the index) atomically.

    Backs the password-change flow: the client re-encrypts every note under
    the new vault key and submits them in batches. Each batch is all-or-
    nothing, since an unknown or foreign note id rolls the whole batch back,
    so a partial batch can never mix keys.

    Args:
        user (User): The authenticated owner.
        notes (list[dict]): Items with ``id``, ``content``, ``iv``.
        index_payload (dict | None): Optional ``{"encrypted_data", "iv"}`` to
            save after the notes (the index is the client's commit marker, so
            it travels in the final batch).
        keypair_payload (dict | None): Optional
            ``{"encrypted_private_key", "iv"}``, the collaboration private
            key re-encrypted under the new vault key. Rides the final batch
            with the index (same transaction), so an interrupted migration
            can never leave "index new-key, keypair old-key". The public key
            never changes here.

    Returns:
        int: Number of migrated note rows.

    Raises:
        ValidationError: If any id is unknown/foreign (code ``unknown_note``),
            a keypair payload arrives for an account without one (code
            ``unknown_keypair``), or any payload fails model validation.
            Nothing is persisted.
    """
    with transaction.atomic():
        migrated = 0
        for item in notes:
            note = get_vault_note(user, item["id"])
            if note is None:
                raise ValidationError(
                    _("Unknown note id in migration payload."), code="unknown_note"
                )
            note.content = item["content"]
            note.iv = item["iv"]
            note.full_clean()
            note.save()
            migrated += 1
        if index_payload is not None:
            save_vault_index(user, index_payload["encrypted_data"], index_payload["iv"])
        if keypair_payload is not None:
            keypair = UserKeyPair.objects.filter(user=user).first()
            if keypair is None:
                raise ValidationError(
                    _("No keypair exists for this account."), code="unknown_keypair"
                )
            keypair.encrypted_private_key = keypair_payload["encrypted_private_key"]
            keypair.private_key_iv = keypair_payload["iv"]
            keypair.full_clean()
            keypair.save()
        return migrated


def build_note_vault_export(user: User) -> dict[str, Any]:
    """Build the note-vault section of the account's GDPR data export.

    Args:
        user (User): The user whose data should be exported.

    Returns:
        dict[str, Any]: The encrypted index (or ``None``) and every encrypted
        vault note (the server cannot decrypt either).
    """
    try:
        index = VaultIndex.objects.get(user=user)
        index_payload = serialize_vault_index(index, include_updated_at=True)
    except VaultIndex.DoesNotExist:
        index_payload = None

    return {
        "index": index_payload,
        "notes": list_vault_notes(user, include_content=True),
    }
