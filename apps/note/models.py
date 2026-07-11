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
    validate_note_content,
    validate_optional_iv,
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
