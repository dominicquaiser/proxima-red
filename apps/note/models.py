"""
Models for the note sharing application.

A shared note is a static markdown snapshot with an expiry, mirroring the
anonymous password share: by default the content is encrypted client-side
with AES-256-GCM and the key travels only in the share URL's fragment, so the
server stores opaque ciphertext (zero-knowledge architecture). Users may also
explicitly create a plain-text share, which the server *can* read; the
``is_encrypted`` flag records that choice honestly.
"""

import uuid

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.auth.models import User

from .validators import (
    validate_base64_content,
    validate_live_snapshot,
    validate_live_update_payload,
    validate_note_content,
    validate_optional_iv,
    validate_required_iv,
    validate_vault_index_data,
    validate_vault_note_content,
)


class SharedNote(models.Model):
    """
    Represents a shared markdown note with expiration and access tracking.

    Encrypted notes (the default) hold Base64 ciphertext in ``content`` plus a
    Base64 IV; the AES-256-GCM key is embedded in the shareable URL fragment
    (after #) and never reaches the server. Plain-text notes hold raw markdown
    in ``content`` and no IV.

    There are no title fields: the retrieve page renders the whole document
    immediately, so the note's own first heading is its title (derived
    client-side only, e.g. for the download filename).

    Attributes:
        id (uuid.UUID): UUID primary key for the note.
        created_by (User | None): Authenticated owner for account cleanup, or
            ``None`` for an anonymous note.
        content (str): Base64 ciphertext for an encrypted note or raw Markdown
            for a plain-text note.
        iv (str): Base64-encoded initialization vector, or an empty string for
            a plain-text note.
        is_encrypted (bool): Whether ``content`` is encrypted client-side.
        created_at (datetime.datetime): Timestamp when the note was created.
        expires_at (datetime.datetime): Timestamp after which the note is
            considered expired.
        access_count (int): Number of times the note has been accessed.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this shared note"),
    )

    created_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="shared_notes",
        help_text=_(
            "Authenticated user that created this note; empty for anonymous notes"
        ),
    )

    content = models.TextField(
        validators=[validate_note_content],
        help_text=_(
            "Note body: Base64 ciphertext when encrypted, raw markdown when plain text"
        ),
    )

    iv = models.TextField(
        blank=True,
        default="",
        validators=[validate_optional_iv],
        help_text=_(
            "Initialization vector for AES-GCM encryption (Base64-encoded); "
            "empty for plain-text notes"
        ),
    )

    is_encrypted = models.BooleanField(
        default=True,
        help_text=_("Whether the content was encrypted client-side"),
    )

    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Timestamp when this note was created")
    )

    # Indexed via Meta.indexes (note_expires_idx); no db_index=True here, which
    # would add a second, redundant index on the same column.
    expires_at = models.DateTimeField(
        help_text=_("Timestamp when this note expires and will be deleted"),
    )

    access_count = models.IntegerField(
        default=0, help_text=_("Number of times this note has been accessed")
    )

    class Meta:
        db_table = "note_sharednote"
        verbose_name = _("Shared Note")
        verbose_name_plural = _("Shared Notes")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["expires_at"], name="note_expires_idx"),
            models.Index(fields=["-created_at"], name="note_created_idx"),
        ]

    def __str__(self) -> str:
        """Return string representation of the note.

        The content may be encrypted (and even plain-text bodies are user
        secrets), so it is never shown here.

        Returns:
            str: A non-sensitive label containing the ID prefix and storage
            mode.
        """
        mode = "encrypted" if self.is_encrypted else "plain-text"
        return f"Note {str(self.id)[:8]}... ({mode})"

    def __repr__(self) -> str:
        """Return a detailed, non-sensitive representation for debugging.

        Returns:
            str: Model metadata excluding the note content.
        """
        return (
            f"<SharedNote id={str(self.id)[:8]}... "
            f"encrypted={self.is_encrypted} "
            f"created={self.created_at.isoformat()} "
            f"expires={self.expires_at.isoformat()} "
            f"accesses={self.access_count}>"
        )

    def clean(self) -> None:
        """Enforce the cross-field rules between ``is_encrypted``, ``content``, ``iv``.

        Encrypted notes must carry strict-Base64 ciphertext and an IV; a
        plain-text note carrying an IV is a client bug worth rejecting loudly.
        These checks live here rather than in field validators because a field
        validator cannot see ``is_encrypted``.

        Returns:
            None: The model is validated in place.

        Raises:
            ValidationError: If encrypted content is not strict Base64, an
                encrypted note has no IV, or a plain-text note has an IV.
        """
        errors = {}
        if self.is_encrypted:
            if not self.iv:
                errors["iv"] = ValidationError(
                    _("Encrypted notes require an initialization vector."),
                    code="missing_iv",
                )
            if self.content:
                try:
                    validate_base64_content(self.content)
                except ValidationError as exc:
                    errors["content"] = exc
        elif self.iv:
            errors["iv"] = ValidationError(
                _("Plain-text notes must not carry an initialization vector."),
                code="unexpected_iv",
            )
        if errors:
            raise ValidationError(errors)

    def is_expired(self) -> bool:
        """Check whether the note has expired.

        Returns:
            bool: ``True`` when the current time is later than ``expires_at``.
        """
        return timezone.now() > self.expires_at


class LiveNote(models.Model):
    """
    An editable share link's document: encrypted CRDT snapshot plus update log.

    A live note is a collaborative document that anyone holding the share link
    can edit. The document is a Yjs CRDT that only the clients can read: the
    AES-256-GCM key travels in the URL fragment (like shared notes), edits are
    merged client-side, and the server merely stores and relays ciphertext.
    ``snapshot`` holds the encrypted full CRDT state; edits accumulate as
    :class:`LiveNoteUpdate` rows until a client writes a re-encrypted compacted
    snapshot (the server cannot compact what it cannot read).

    ``snapshot_seq`` is the highest :class:`LiveNoteUpdate` id folded into the
    snapshot. Compaction deletes the covered rows in the same transaction, so
    rows with ``id <= snapshot_seq`` never exist: the pending tail is simply
    ``self.updates.all()``, and a client whose sync cursor is older than
    ``snapshot_seq`` has provably missed pruned history and is re-sent the
    snapshot (applying it is CRDT-idempotent).

    Attributes:
        id (uuid.UUID): UUID primary key for the live note.
        created_by (User | None): Authenticated creator for account cleanup,
            or ``None`` for an anonymous live note.
        snapshot (str): Base64 AES-256-GCM ciphertext of the encoded Yjs state.
        snapshot_iv (str): Base64-encoded initialization vector of the snapshot.
        snapshot_seq (int): Highest update id covered by the snapshot; 0 for a
            freshly seeded document.
        access_mode (str): ``ACCESS_LINK`` (anyone holding the link may edit)
            or ``ACCESS_RESTRICTED`` (a session plus a
            :class:`LiveNoteCollaborator` row is required).
        key_epoch (int): Document-key generation, incremented by each rekey.
            Always 0 for link-mode and pre-M4 notes.
        created_at (datetime.datetime): Timestamp when the live note was created.
        updated_at (datetime.datetime): Timestamp of the last snapshot write.
        expires_at (datetime.datetime): Timestamp after which the live note is
            considered expired (fixed at creation, like shared notes).
        access_count (int): Number of times the live page has been opened.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this live note"),
    )

    created_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="live_notes",
        help_text=_(
            "Authenticated user that created this live note; empty for "
            "anonymous live notes"
        ),
    )

    snapshot = models.TextField(
        validators=[validate_live_snapshot],
        help_text=_("Base64 AES-256-GCM ciphertext of the encoded Yjs document state"),
    )

    # Base64 TextField like VaultNote.iv (the note-app convention).
    snapshot_iv = models.TextField(
        validators=[validate_required_iv],
        help_text=_("Initialization vector for the snapshot (Base64-encoded)"),
    )

    snapshot_seq = models.BigIntegerField(
        default=0,
        help_text=_("Highest update id folded into the snapshot; 0 when seeded"),
    )

    # ── Named-collaborator access control (M4) ──────────────────────────────
    # "link" is the default anonymous editable-share behavior (holding the
    # fragment key is the capability); "restricted" gates every endpoint on a
    # session + a LiveNoteCollaborator row and wraps the doc key per user.
    ACCESS_LINK = "link"
    ACCESS_RESTRICTED = "restricted"
    ACCESS_MODES = [
        (ACCESS_LINK, "Anyone with the link"),
        (ACCESS_RESTRICTED, "Named collaborators only"),
    ]
    access_mode = models.CharField(
        max_length=10,
        choices=ACCESS_MODES,
        default=ACCESS_LINK,
        help_text=_(
            "Whether the link alone grants access, or a collaborator row is required"
        ),
    )

    # Bumped on each rekey (revocation). Appends carry the epoch they encrypted
    # under; a mismatch is rejected so a client on the old key can't append
    # ciphertext no one else can read. 0 for link-mode / pre-M4 notes.
    key_epoch = models.BigIntegerField(
        default=0,
        help_text=_("Document-key generation; incremented on each rekey"),
    )

    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Timestamp when this live note was created")
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text=_("Timestamp of the last snapshot write")
    )

    # Indexed via Meta.indexes (note_live_expires_idx), mirroring SharedNote.
    expires_at = models.DateTimeField(
        help_text=_("Timestamp when this live note expires and will be deleted"),
    )

    access_count = models.IntegerField(
        default=0, help_text=_("Number of times the live page has been opened")
    )

    class Meta:
        db_table = "note_livenote"
        verbose_name = _("Live Note")
        verbose_name_plural = _("Live Notes")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["expires_at"], name="note_live_expires_idx"),
        ]

    def __str__(self) -> str:
        """Return string representation of the live note.

        The snapshot is ciphertext of a user document and is never shown.

        Returns:
            str: A non-sensitive label containing the ID prefix.
        """
        return f"Live note {str(self.id)[:8]}..."

    def __repr__(self) -> str:
        """Return a detailed, non-sensitive representation for debugging.

        Returns:
            str: Model metadata excluding the document content.
        """
        return (
            f"<LiveNote id={str(self.id)[:8]}... "
            f"snapshot_seq={self.snapshot_seq} "
            f"created={self.created_at.isoformat()} "
            f"expires={self.expires_at.isoformat()} "
            f"accesses={self.access_count}>"
        )

    def is_expired(self) -> bool:
        """Check whether the live note has expired.

        Returns:
            bool: ``True`` when the current time is later than ``expires_at``.
        """
        return timezone.now() > self.expires_at


class LiveNoteUpdate(models.Model):
    """
    One encrypted Yjs update appended to a live note's log.

    The implicit ``BigAutoField`` primary key doubles as the sync cursor:
    ids are globally monotonic, clients poll "rows with ``id`` greater than my
    cursor" scoped to their note, and gaps (from other notes' traffic) are
    harmless. Appends are serialized per note via a row lock on the parent
    (see ``services.append_live_update``), so a row's id is never made visible
    to a poller before a smaller id has committed.

    Attributes:
        note (LiveNote): Parent live note.
        payload (str): Base64 AES-256-GCM ciphertext of one merged Yjs update.
        iv (str): Base64-encoded initialization vector.
        created_at (datetime.datetime): Timestamp when the update was appended.
    """

    # The composite (note, id) index below serves the per-note tail scan, so a
    # second index on the FK column alone would be redundant.
    note = models.ForeignKey(
        LiveNote,
        on_delete=models.CASCADE,
        related_name="updates",
        db_index=False,
        help_text=_("Live note this update belongs to"),
    )

    payload = models.TextField(
        validators=[validate_live_update_payload],
        help_text=_("Base64 AES-256-GCM ciphertext of one merged Yjs update"),
    )

    iv = models.TextField(
        validators=[validate_required_iv],
        help_text=_("Initialization vector for AES-GCM encryption (Base64-encoded)"),
    )

    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Timestamp when this update was appended")
    )

    class Meta:
        db_table = "note_livenoteupdate"
        verbose_name = _("Live Note Update")
        verbose_name_plural = _("Live Note Updates")
        ordering = ["id"]
        indexes = [
            models.Index(fields=["note", "id"], name="note_liveupd_note_id_idx"),
        ]

    def __str__(self) -> str:
        """Return string representation of the update.

        The payload is ciphertext of user edits and is never shown.

        Returns:
            str: A non-sensitive label containing the id and note prefix.
        """
        return f"Live update {self.pk} for note {str(self.note_id)[:8]}..."

    def __repr__(self) -> str:
        """Return a detailed, non-sensitive representation for debugging.

        Returns:
            str: Model metadata excluding the update payload.
        """
        return (
            f"<LiveNoteUpdate id={self.pk} "
            f"note={str(self.note_id)[:8]}... "
            f"created={self.created_at.isoformat()}>"
        )


class LiveNoteCollaborator(models.Model):
    """
    A named collaborator's access to a restricted live note (M4).

    Holds the document key **wrapped to this collaborator's public key** (see
    ``static/shared/js/keywrap.js``): only the collaborator's private key can
    unwrap it, so the server stores the wrap but can never open the document.
    The row's existence is also the access grant: restricted endpoints check
    for it. Revoking = deleting the row and rekeying the document (rotate the
    doc key, re-wrap to the survivors, bump ``LiveNote.key_epoch``), so a
    removed collaborator cannot read anything written afterward.

    Attributes:
        note (LiveNote): The restricted live note.
        user (User): The collaborator.
        role (str): ``owner`` (may invite/revoke/rekey) or ``editor``.
        wrapped_key (str): Base64 AES-GCM ciphertext of the doc key.
        wrap_iv (str): Base64 IV for the wrap.
        ephemeral_public_key (str): Base64 SPKI of the wrap's ephemeral key.
        key_epoch (int): The document key generation this wrap is for; must
            match ``LiveNote.key_epoch`` to be current.
    """

    ROLE_OWNER = "owner"
    ROLE_EDITOR = "editor"
    ROLES = [(ROLE_OWNER, "Owner"), (ROLE_EDITOR, "Editor")]

    note = models.ForeignKey(
        LiveNote,
        on_delete=models.CASCADE,
        related_name="collaborators",
        help_text=_("Restricted live note this grant belongs to"),
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="live_collaborations",
        help_text=_("The collaborator"),
    )
    role = models.CharField(max_length=8, choices=ROLES, default=ROLE_EDITOR)
    wrapped_key = models.TextField(
        help_text=_(
            "Base64 AES-GCM ciphertext of the document key, wrapped to this user"
        )
    )
    wrap_iv = models.TextField(help_text=_("Base64 IV for the wrapped key"))
    ephemeral_public_key = models.TextField(
        help_text=_("Base64 SPKI of the wrap's ephemeral ECDH public key")
    )
    key_epoch = models.BigIntegerField(
        default=0, help_text=_("Document-key generation this wrap decrypts")
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "note_livenotecollaborator"
        verbose_name = _("Live Note Collaborator")
        verbose_name_plural = _("Live Note Collaborators")
        constraints = [
            models.UniqueConstraint(
                fields=["note", "user"], name="note_livecollab_unique_note_user"
            )
        ]
        indexes = [
            models.Index(fields=["note", "user"], name="note_livecollab_note_user_idx"),
        ]

    def __str__(self) -> str:
        """Return a non-sensitive label (no wrapped key material)."""
        return f"Collaborator {self.user_id} on note {str(self.note_id)[:8]}..."

    def __repr__(self) -> str:
        """Return a non-sensitive detailed representation."""
        return (
            f"<LiveNoteCollaborator note={str(self.note_id)[:8]}... "
            f"user={self.user_id} role={self.role} epoch={self.key_epoch}>"
        )


class VaultNote(models.Model):
    """
    An authenticated user's vault note: one encrypted markdown document.

    Vault notes are always encrypted client-side with the user's vault key
    (AES-256-GCM), so the server only ever stores opaque ciphertext. The note
    carries no name and no folder: names and the folder tree live exclusively
    in the user's encrypted :class:`VaultIndex`, so the server learns nothing
    about the vault's structure. There is deliberately no ``expires_at``:
    vault notes never expire and are structurally invisible to the expired-
    share sweeps, which query :class:`SharedNote` only.

    Attributes:
        id (uuid.UUID): UUID primary key for the note.
        user (User): Owning account; vault notes are never anonymous.
        content (str): Base64 AES-256-GCM ciphertext of the markdown document.
        iv (str): Base64-encoded initialization vector.
        created_at (datetime.datetime): Timestamp when the note was created.
        updated_at (datetime.datetime): Timestamp of the last content write.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this vault note"),
    )

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="vault_notes",
        help_text=_("Account that owns this vault note"),
    )

    content = models.TextField(
        validators=[validate_vault_note_content],
        help_text=_("Base64 AES-256-GCM ciphertext of the note's markdown"),
    )

    # Base64 TextField like SharedNote.iv (the note-app convention), not a
    # BinaryField like the passwd tool's ServiceData.iv: it spares every view
    # the encode/decode shuffle that CLAUDE.md flags as a special case.
    iv = models.TextField(
        validators=[validate_required_iv],
        help_text=_("Initialization vector for AES-GCM encryption (Base64-encoded)"),
    )

    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Timestamp when this note was created")
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text=_("Timestamp of the last content update")
    )

    class Meta:
        db_table = "note_vaultnote"
        verbose_name = _("Vault Note")
        verbose_name_plural = _("Vault Notes")
        ordering = ["-updated_at"]

    def __str__(self) -> str:
        """Return string representation of the vault note.

        The content is ciphertext of a user secret and is never shown.

        Returns:
            str: A non-sensitive label containing the ID prefix.
        """
        return f"Vault note {str(self.id)[:8]}..."

    def __repr__(self) -> str:
        """Return a detailed, non-sensitive representation for debugging.

        Returns:
            str: Model metadata excluding the note content.
        """
        return (
            f"<VaultNote id={str(self.id)[:8]}... "
            f"user={self.user.user_id} "
            f"created={self.created_at.isoformat()} "
            f"updated={self.updated_at.isoformat()}>"
        )


class VaultIndex(models.Model):
    """
    A user's encrypted note-vault index: the folder tree and note names.

    The index is a single JSON document (folders, note names, folder
    assignments, and trash state) encrypted client-side under the vault key.
    It is the client's commit marker: note rows are written first and the
    index last, so on load the client reconciles the decrypted index against
    the actual rows (dropping stale entries, adopting orphans).

    Attributes:
        user (User): Owning account (one index per user).
        encrypted_data (str): Base64 AES-256-GCM ciphertext of the index JSON.
        iv (str): Base64-encoded initialization vector.
        created_at (datetime.datetime): Timestamp when the index was created.
        updated_at (datetime.datetime): Timestamp of the last save.
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="note_vault_index",
        help_text=_("Account that owns this vault index"),
    )

    encrypted_data = models.TextField(
        validators=[validate_vault_index_data],
        help_text=_("Base64 AES-256-GCM ciphertext of the vault index JSON"),
    )

    # Base64 TextField for the same reason as VaultNote.iv.
    iv = models.TextField(
        validators=[validate_required_iv],
        help_text=_("Initialization vector for AES-GCM encryption (Base64-encoded)"),
    )

    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Timestamp when this index was created")
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text=_("Timestamp of the last index save")
    )

    class Meta:
        db_table = "note_vaultindex"
        verbose_name = _("Vault Index")
        verbose_name_plural = _("Vault Indexes")

    def __str__(self) -> str:
        """Return string representation of the vault index.

        Returns:
            str: A non-sensitive label naming the owning user.
        """
        return f"Vault index for user {self.user.user_id}"

    def __repr__(self) -> str:
        """Return a detailed, non-sensitive representation for debugging.

        Returns:
            str: Model metadata excluding the encrypted payload.
        """
        return (
            f"<VaultIndex user={self.user.user_id} "
            f"updated={self.updated_at.isoformat()}>"
        )
