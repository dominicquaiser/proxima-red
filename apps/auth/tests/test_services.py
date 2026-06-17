"""Tests for the authentication service functions."""

import base64
from unittest.mock import patch

from django.contrib.auth.hashers import check_password
from django.db import IntegrityError
from django.test import TestCase

from apps.auth.exceptions import UserCreationError
from apps.auth.models import User
from apps.auth.constants import SALT_LENGTH_BYTES
from apps.auth.services import (
    authenticate_user,
    change_user_auth_secret,
    create_user_with_auth_secret,
    generate_decoy_salt,
    get_user_by_id,
)

AUTH_SECRET = base64.b64encode(b"a" * 32).decode()
NEW_AUTH_SECRET = base64.b64encode(b"b" * 32).decode()
WRONG_AUTH_SECRET = base64.b64encode(b"c" * 32).decode()
AUTH_SALT = base64.b64encode(b"d" * 32).decode()
VAULT_SALT = base64.b64encode(b"e" * 32).decode()
NEW_AUTH_SALT = base64.b64encode(b"f" * 32).decode()
NEW_VAULT_SALT = base64.b64encode(b"g" * 32).decode()


class AuthenticationServicesTests(TestCase):
    """Test cases for authentication service functions."""

    def test_generate_decoy_salt_is_deterministic(self):
        """Decoys are stable per (user_id, purpose) so they can't reveal absence."""
        first = generate_decoy_salt("12345678", purpose="auth")
        second = generate_decoy_salt("12345678", purpose="auth")
        self.assertEqual(first, second)

    def test_generate_decoy_salt_matches_real_salt_shape(self):
        """A decoy is indistinguishable in shape from a real salt (32 bytes b64)."""
        decoy = generate_decoy_salt("12345678", purpose="auth")
        self.assertEqual(len(base64.b64decode(decoy)), SALT_LENGTH_BYTES)

    def test_generate_decoy_salt_varies_by_user_and_purpose(self):
        """Different ids and the auth/vault purposes yield different decoys."""
        self.assertNotEqual(
            generate_decoy_salt("12345678", purpose="auth"),
            generate_decoy_salt("87654321", purpose="auth"),
        )
        self.assertNotEqual(
            generate_decoy_salt("12345678", purpose="auth"),
            generate_decoy_salt("12345678", purpose="vault"),
        )

    def test_create_user_with_auth_secret(self):
        """Test creating user with auth-secret hashing."""
        user = create_user_with_auth_secret(
            AUTH_SECRET,
            auth_salt=AUTH_SALT,
            vault_salt=VAULT_SALT,
        )

        self.assertIsNotNone(user)
        self.assertIsInstance(user, User)
        self.assertTrue(check_password(AUTH_SECRET, user.password_hash))
        self.assertEqual(user.auth_salt, AUTH_SALT)
        self.assertEqual(user.vault_salt, VAULT_SALT)

    def test_authenticate_user_success(self):
        """Test successful user authentication."""
        user = create_user_with_auth_secret(
            AUTH_SECRET,
            auth_salt=AUTH_SALT,
            vault_salt=VAULT_SALT,
        )

        authenticated_user = authenticate_user(user.user_id, AUTH_SECRET)
        self.assertIsNotNone(authenticated_user)
        self.assertEqual(authenticated_user.user_id, user.user_id)

    def test_authenticate_user_wrong_password(self):
        """Test authentication fails with wrong password."""
        user = create_user_with_auth_secret(
            AUTH_SECRET,
            auth_salt=AUTH_SALT,
            vault_salt=VAULT_SALT,
        )

        authenticated_user = authenticate_user(user.user_id, WRONG_AUTH_SECRET)
        self.assertIsNone(authenticated_user)

    def test_authenticate_user_nonexistent(self):
        """Test authentication fails for nonexistent user."""
        authenticated_user = authenticate_user("99999999", AUTH_SECRET)
        self.assertIsNone(authenticated_user)

    def test_authenticate_nonexistent_user_still_runs_hasher(self):
        """A missing user_id still invokes the hasher, equalising response time
        with the existing-user path (no enumeration timing oracle)."""
        self.assertFalse(User.objects.filter(user_id="99999999").exists())
        with patch("apps.auth.services.make_password") as mock_make_password:
            result = authenticate_user("99999999", AUTH_SECRET)
        self.assertIsNone(result)
        mock_make_password.assert_called_once_with(AUTH_SECRET)

    def test_change_user_auth_secret(self):
        """Test changing the user's auth secret and salts."""
        user = create_user_with_auth_secret(
            AUTH_SECRET,
            auth_salt=AUTH_SALT,
            vault_salt=VAULT_SALT,
        )
        old_salt = user.vault_salt

        _, new_auth_salt, new_salt = change_user_auth_secret(
            user,
            new_auth_secret=NEW_AUTH_SECRET,
            auth_salt=NEW_AUTH_SALT,
            vault_salt=NEW_VAULT_SALT,
        )

        # Refresh user from database
        user.refresh_from_db()

        self.assertTrue(check_password(NEW_AUTH_SECRET, user.password_hash))
        self.assertFalse(check_password(AUTH_SECRET, user.password_hash))
        self.assertEqual(new_auth_salt, NEW_AUTH_SALT)
        self.assertEqual(user.auth_salt, NEW_AUTH_SALT)
        self.assertNotEqual(old_salt, new_salt)
        self.assertEqual(user.vault_salt, NEW_VAULT_SALT)

    def test_get_user_by_id(self):
        """Test retrieving user by ID."""
        user = create_user_with_auth_secret(
            AUTH_SECRET,
            auth_salt=AUTH_SALT,
            vault_salt=VAULT_SALT,
        )

        retrieved_user = get_user_by_id(user.user_id)
        self.assertIsNotNone(retrieved_user)
        self.assertEqual(retrieved_user.user_id, user.user_id)

    def test_get_user_by_id_nonexistent(self):
        """Test retrieving nonexistent user returns None."""
        retrieved_user = get_user_by_id("99999999")
        self.assertIsNone(retrieved_user)

    def test_create_user_raises_after_exhausting_retries(self):
        """Persistent user_id collisions surface as UserCreationError.

        Each attempt's ``User.objects.create`` is forced to raise
        ``IntegrityError`` (as a duplicate ``user_id`` would), so the retry loop
        runs to exhaustion and raises rather than looping forever.
        """
        with patch(
            "apps.auth.services.User.objects.create",
            side_effect=IntegrityError,
        ):
            with self.assertRaises(UserCreationError):
                create_user_with_auth_secret(
                    AUTH_SECRET,
                    auth_salt=AUTH_SALT,
                    vault_salt=VAULT_SALT,
                )
