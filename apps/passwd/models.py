"""
Models for the password sharing application.

This module defines the data models for securely sharing encrypted passwords
and storing user-specific encrypted service data. All password data is
encrypted client-side before being stored on the server (zero-knowledge architecture).
"""

import uuid

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.auth.models import User

from .constants import GCM_IV_LENGTH_BYTES
from .validators import (
    validate_encrypted_data,
    validate_iv,
    validate_iv_bytes,
    validate_optional_encrypted_title,
    validate_optional_iv,
)


class SharedPassword(models.Model):
    """
    Represents a securely shared password with expiration and access tracking.

    This model stores encrypted password data that has been encrypted client-side
    using AES-256-GCM. The server never has access to the plaintext password.
    The encryption key is embedded in the shareable URL fragment (after #) and
    never reaches the server.

    Attributes:
        id: UUID primary key for the share
        created_by: Authenticated owner for account cleanup, or None
        encrypted_data: Base64-encoded encrypted password (ciphertext)
        iv: Base64-encoded initialization vector used for encryption
        encrypted_title: Base64-encoded encrypted title (ciphertext), or empty
        title_iv: Base64-encoded IV for the encrypted title, or empty
        created_at: Timestamp when the share was created
        expires_at: Timestamp when the share expires and should be deleted
        access_count: Number of times this share has been accessed
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text=_("Unique identifier for this password share"),
    )

    created_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="shared_passwords",
        help_text=_(
            "Authenticated user that created this share; empty for anonymous shares"
        ),
    )

    encrypted_data = models.TextField(
        validators=[validate_encrypted_data],
        help_text=_("Client-side encrypted password data (Base64-encoded ciphertext)"),
    )

    iv = models.TextField(
        validators=[validate_iv],
        help_text=_("Initialization vector for AES-GCM encryption (Base64-encoded)"),
    )

    encrypted_title = models.TextField(
        blank=True,
        default="",
        validators=[validate_optional_encrypted_title],
        help_text=_(
            "Client-side encrypted title (Base64-encoded ciphertext); empty if none"
        ),
    )

    title_iv = models.TextField(
        blank=True,
        default="",
        validators=[validate_optional_iv],
        help_text=_(
            "Initialization vector for the encrypted title (Base64-encoded); empty if none"
        ),
    )

    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Timestamp when this share was created")
    )

    # Indexed via Meta.indexes (passwd_expires_idx); no db_index=True here, which
    # would add a second, redundant index on the same column.
    expires_at = models.DateTimeField(
        help_text=_("Timestamp when this share expires and will be deleted"),
    )

    access_count = models.IntegerField(
        default=0, help_text=_("Number of times this share has been accessed")
    )

    class Meta:
        db_table = "passwd_sharedpassword"
        verbose_name = _("Shared Password")
        verbose_name_plural = _("Shared Passwords")
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["expires_at"], name="passwd_expires_idx"),
            models.Index(fields=["-created_at"], name="passwd_created_idx"),
        ]

    def __str__(self) -> str:
        """Return string representation of the share.

        The title is encrypted client-side, so it cannot be shown here.
        """
        label = "titled" if self.encrypted_title else "untitled"
        return f"Share {str(self.id)[:8]}... ({label})"

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return (
            f"<SharedPassword id={str(self.id)[:8]}... "
            f"created={self.created_at.isoformat()} "
            f"expires={self.expires_at.isoformat()} "
            f"accesses={self.access_count}>"
        )

    def is_expired(self) -> bool:
        """
        Check if this share has expired.

        Returns:
            True if the share has expired, False otherwise
        """
        return timezone.now() > self.expires_at


class ServiceData(models.Model):
    """
    Stores encrypted user-specific data for the sharing service.

    This model stores client-encrypted data that allows users to maintain
    a persistent vault of their shared passwords across sessions.
    The data is encrypted with the user's master key, which is derived
    from their password and never stored server-side.

    Attributes:
        user: One-to-one relationship with the User model
        encrypted_data: Client-encrypted JSON blob containing user's shares
        iv: Initialization vector for AES-256-GCM encryption (binary)
        created_at: Timestamp when this record was created
        updated_at: Timestamp when this record was last updated
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="service_data",
        help_text=_("User who owns this encrypted data"),
    )

    encrypted_data = models.TextField(
        validators=[validate_encrypted_data],
        help_text=_("Client-encrypted JSON blob for the sharing service"),
    )

    iv = models.BinaryField(
        max_length=GCM_IV_LENGTH_BYTES,
        validators=[validate_iv_bytes],
        help_text=_("Initialization vector for AES-256-GCM encryption (12 bytes)"),
    )

    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Timestamp when this record was created")
    )

    updated_at = models.DateTimeField(
        auto_now=True, help_text=_("Timestamp when this record was last updated")
    )

    class Meta:
        db_table = "passwd_servicedata"
        verbose_name = _("Service Data")
        verbose_name_plural = _("Service Data")
        # No explicit index on user: OneToOneField is unique, which already
        # creates an index on the column, so a second one would be redundant.

    def __str__(self) -> str:
        """Return string representation of the service data."""
        return f"Sharing data for User {self.user.user_id}"

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return (
            f"<ServiceData user_id={self.user.user_id} "
            f"updated={self.updated_at.isoformat()}>"
        )
