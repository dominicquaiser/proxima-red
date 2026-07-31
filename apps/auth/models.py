"""
User authentication models.

This module defines the User model for authentication across all services.
The model stores authentication credentials and handles user identification.
"""

from __future__ import annotations

import secrets
import string

from django.db import models

from .constants import (
    MAX_KEYPAIR_IV_LENGTH,
    MAX_PRIVATE_KEY_BLOB_LENGTH,
    USER_ID_LENGTH,
)


def generate_user_id() -> str:
    """
    Generate a cryptographically secure 8-character numeric identifier.

    Returns:
        String of 8 random digits
    """
    return "".join(secrets.choice(string.digits) for _ in range(USER_ID_LENGTH))


def is_valid_user_id(value: str) -> bool:
    """
    Return True when ``value`` has the public user_id shape (8 digits).

    Single source of truth for the format check, shared by the signin form
    and the salts endpoint.
    """
    return len(value) == USER_ID_LENGTH and value.isdigit()


class User(models.Model):
    """
    User account model for authentication across all services.

    This model stores only authentication-related information:
    - user_id: Unique 8-digit numeric identifier
    - password_hash: Argon2 hash of a client-derived authentication secret
    - auth_salt: Client-side salt for deriving the authentication secret
    - vault_salt: Client-side salt for deriving the vault encryption key

    The user_id serves as the public identifier for the user, while the
    password_hash is used for server-side authentication. The salts are public
    inputs for browser-side key derivation; the raw account password is never
    required by the server.

    Attributes:
        user_id: 8-character unique numeric identifier
        password_hash: Argon2 hash of the client-derived auth secret
        auth_salt: Base64-encoded salt for the client auth secret
        vault_salt: Base64-encoded salt for client-side vault key derivation
        created_at: Timestamp when the account was created
        updated_at: Timestamp when the account was last modified
    """

    user_id = models.CharField(
        max_length=USER_ID_LENGTH,
        unique=True,
        default=generate_user_id,
        help_text="8-character numeric identifier for the user",
    )
    password_hash = models.CharField(
        max_length=128,
        help_text="Argon2 hash of client-derived authentication secret",
    )
    auth_salt = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text="Salt for client-side authentication secret derivation",
    )
    vault_salt = models.CharField(
        max_length=64,
        help_text="Salt for client-side vault key derivation (PBKDF2-SHA256)",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # Table name explicitly set to 'proxima_user' to avoid conflict with
        # Django's built-in auth_user table when the app is named 'auth'.
        # This allows the app directory to be named 'auth' while maintaining database
        # compatibility and preventing table name collisions.
        db_table = "proxima_user"
        # No explicit index on user_id: unique=True on the field already creates
        # one, so a second plain index would be redundant.
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self) -> str:
        """Return string representation of the user."""
        return f"User {self.user_id}"

    def __repr__(self) -> str:
        """Return detailed representation for debugging."""
        return (
            f"<User user_id={self.user_id} "
            f"created={self.created_at.isoformat() if self.created_at else 'N/A'}>"
        )


class UserKeyPair(models.Model):
    """
    Per-account asymmetric keypair for named-collaborator key wrapping.

    A separate model rather than columns on ``proxima_user`` on purpose: that
    table's documented contract is authentication-only, and keypairs are
    created lazily (at signup, or at an existing account's first
    collaboration action), so a nullable-column sprawl is avoided.

    Zero-knowledge split: the public key is plaintext (it is public); the
    private key is stored as AES-256-GCM ciphertext under the account's
    VAULT key — the server holds the blob but can never open it. The public
    key never rotates on password change; only the blob is re-encrypted
    (through the transactional ``/vault/migrate/`` batch, so it can never
    end up under a different key than the vault index).

    Attributes:
        user: Owning account (one keypair per account).
        public_key: Base64 SPKI ECDH P-256 public key (91 bytes decoded).
        encrypted_private_key: Base64 AES-GCM ciphertext of the PKCS8 key.
        private_key_iv: Base64 initialization vector for the blob.
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="keypair",
    )
    public_key = models.CharField(
        max_length=256,
        help_text="Base64 SPKI ECDH P-256 public key (server-distributed)",
    )
    encrypted_private_key = models.CharField(
        max_length=MAX_PRIVATE_KEY_BLOB_LENGTH,
        help_text="Base64 AES-GCM ciphertext of the PKCS8 private key (vault key)",
    )
    private_key_iv = models.CharField(
        max_length=MAX_KEYPAIR_IV_LENGTH,
        help_text="Base64 IV for the encrypted private key blob",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "proxima_user_keypair"
        verbose_name = "User keypair"
        verbose_name_plural = "User keypairs"

    def __str__(self) -> str:
        """Return a non-sensitive string representation."""
        return f"KeyPair for User {self.user.user_id}"

    def __repr__(self) -> str:
        """Return a non-sensitive detailed representation."""
        return f"<UserKeyPair user_id={self.user.user_id}>"
