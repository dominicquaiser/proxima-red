"""
Business logic and service functions for authentication.

This module contains reusable business logic for user authentication,
password management, and session handling. It separates concerns from
views and provides a clean interface for authentication operations.
"""

import base64
import hashlib
import hmac
import logging

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.db import IntegrityError, transaction
from django.http import HttpRequest

from .models import User
from .exceptions import UserCreationError
from .constants import (
    SALT_LENGTH_BYTES,
    MAX_USER_CREATION_RETRIES,
    LOG_INTEGRITY_ERROR,
    LOG_USER_CREATION_FAILED,
    SESSION_KEY_USER_ID,
    SESSION_KEY_AUTHENTICATED,
)

logger = logging.getLogger(__name__)


def generate_decoy_salt(user_id: str, *, purpose: str) -> str:
    """
    Return a deterministic decoy salt for an unknown ``user_id``.

    The public salts endpoint must answer for *every* ``user_id`` so it can't be
    used as an account-existence oracle. Returning a freshly random salt on each
    call would itself be the tell: a real account returns the same salt every
    time, so a missing account that returned a different value on each request
    would stand out. Decoys are therefore derived deterministically from the
    server secret and the ``user_id`` - stable per id across calls, distinct per
    id, and indistinguishable from a real random salt (same 32-byte length).
    HMAC keyed on ``SECRET_KEY`` keeps them unforgeable by clients.

    Args:
        user_id: The (non-existent) user identifier that was looked up.
        purpose: Domain separator so the auth and vault decoys differ.

    Returns:
        Base64-encoded decoy salt of ``SALT_LENGTH_BYTES`` bytes.
    """
    digest = hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        f"{purpose}:{user_id}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest[:SALT_LENGTH_BYTES]).decode("utf-8")


def create_user_with_auth_secret(
    auth_secret: str, *, auth_salt: str, vault_salt: str
) -> User:
    """
    Create a new user from a client-derived authentication secret.

    This function handles user creation with automatic retry logic for
    handling unique constraint violations on user_id generation.

    Args:
        auth_secret: Client-derived authentication secret to be Argon2-hashed.
        auth_salt: Public salt the browser used to derive ``auth_secret``.
        vault_salt: Public salt the browser uses to derive the vault key.

    Returns:
        User object if successful

    Raises:
        UserCreationError: If unable to create user after maximum retries
    """
    password_hash = make_password(auth_secret)

    for attempt in range(MAX_USER_CREATION_RETRIES):
        try:
            with transaction.atomic():
                user = User.objects.create(
                    password_hash=password_hash,
                    auth_salt=auth_salt,
                    vault_salt=vault_salt,
                )
            return user
        except IntegrityError:
            logger.warning(LOG_INTEGRITY_ERROR.format(attempt=attempt + 1))
            continue

    logger.error(LOG_USER_CREATION_FAILED)
    raise UserCreationError(
        f"Failed to create user after {MAX_USER_CREATION_RETRIES} attempts "
        "due to user_id collisions"
    )


def authenticate_user(user_id: str, auth_secret: str) -> User | None:
    """
    Authenticate a user with their user_id and client-derived auth secret.

    Args:
        user_id: The user's 8-digit numeric ID
        auth_secret: Client-derived authentication secret

    Returns:
        User object if authentication successful, None otherwise
    """
    try:
        user = User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        # Run the password hasher once even when the account is missing, so the
        # response time doesn't reveal whether a user_id exists. Without this the
        # missing-user path skips the (deliberately slow) Argon2 verification and
        # returns measurably faster. Mirrors Django's own `ModelBackend.authenticate`.
        make_password(auth_secret)
        return None

    if check_password(auth_secret, user.password_hash):
        return user
    return None


def change_user_auth_secret(
    user: User, *, new_auth_secret: str, auth_salt: str, vault_salt: str
) -> tuple[str, str, str]:
    """
    Change a user's client-derived authentication secret and KDF salts.

    This function updates the server-side hash of the client auth secret and
    rotates the public salts used for future browser-side derivation.

    Args:
        user: User object whose password should be changed
        new_auth_secret: New client-derived authentication secret
        auth_salt: New public authentication derivation salt
        vault_salt: New public vault derivation salt

    Returns:
        Tuple of (new_password_hash, new_auth_salt, new_vault_salt)
    """
    new_password_hash = make_password(new_auth_secret)

    user.password_hash = new_password_hash
    user.auth_salt = auth_salt
    user.vault_salt = vault_salt
    user.save(update_fields=["password_hash", "auth_salt", "vault_salt", "updated_at"])

    return new_password_hash, auth_salt, vault_salt


def get_user_by_id(user_id: str) -> User | None:
    """
    Retrieve a user by their user_id.

    Args:
        user_id: The user's 8-digit numeric ID

    Returns:
        User object if found, None otherwise
    """
    try:
        return User.objects.get(user_id=user_id)
    except User.DoesNotExist:
        return None


def delete_user_account(user: User) -> None:
    """
    Delete a user's account.

    This function permanently deletes the user and all associated data.
    Related models with CASCADE delete will be automatically removed.

    Args:
        user: User object to delete

    Raises:
        Exception: If deletion fails for any reason
    """
    with transaction.atomic():
        user.delete()


def create_user_session(request: HttpRequest, user: User) -> None:
    """
    Create an authenticated session for a user.

    This function flushes any existing session, creates a new one, and
    sets the necessary session variables for authentication.

    Args:
        request: Django request object
        user: User object to create session for
    """
    request.session.flush()
    request.session[SESSION_KEY_USER_ID] = user.user_id
    request.session[SESSION_KEY_AUTHENTICATED] = True
    request.session.set_expiry(settings.SESSION_COOKIE_AGE)


def regenerate_session_after_password_change(request: HttpRequest) -> None:
    """
    Regenerate session after password change to prevent session fixation.

    Django's cycle_key() changes the session ID while automatically preserving
    all session data, preventing session fixation attacks after password changes.
    This is a security best practice to ensure any session ID obtained before
    the password change becomes invalid.

    Args:
        request: Django request object

    Security Note:
        Session fixation is an attack where an attacker obtains a valid session ID
        before authentication and reuses it after the victim logs in. By cycling
        the session key after password changes, we invalidate any previously
        obtained session IDs.
    """
    # Cycle session key (preserves data, changes session ID)
    request.session.cycle_key()

    # Reset session timeout
    request.session.set_expiry(settings.SESSION_COOKIE_AGE)


def destroy_user_session(request: HttpRequest) -> None:
    """
    Destroy a user's session (sign out).

    Args:
        request: Django request object
    """
    request.session.flush()
