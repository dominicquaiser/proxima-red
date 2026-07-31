"""Tests for the authentication forms and password policy."""

import base64

from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.auth.constants import (
    ERROR_INCORRECT_PASSWORD,
    ERROR_INCORRECT_PASSWORD_DELETION,
)
from apps.auth.forms import (
    AccountDeletionForm,
    PasswordChangeForm,
    SigninForm,
    SignupForm,
    validate_auth_secret,
)
from apps.auth.tests.factories import create_user_with_password

AUTH_SECRET = base64.b64encode(b"a" * 32).decode()
NEW_AUTH_SECRET = base64.b64encode(b"b" * 32).decode()
WRONG_AUTH_SECRET = base64.b64encode(b"c" * 32).decode()
AUTH_SALT = base64.b64encode(b"d" * 32).decode()
VAULT_SALT = base64.b64encode(b"e" * 32).decode()
NEW_AUTH_SALT = base64.b64encode(b"f" * 32).decode()
NEW_VAULT_SALT = base64.b64encode(b"g" * 32).decode()
# Collaboration keypair fixtures (ECDH P-256 SPKI is 91 bytes; the server
# only checks the decoded length, so a fixed-length blob suffices).
PUBLIC_KEY = base64.b64encode(b"\x01" * 91).decode()
PRIVATE_KEY_BLOB = base64.b64encode(b"encryptedpkcs8").decode()
KEYPAIR_IV = base64.b64encode(b"i" * 12).decode()


class Base64FieldValidatorTests(TestCase):
    """validate_base64_bytes reports each failure mode distinctly."""

    def test_empty_value_is_required(self):
        """An empty value fails with the 'required' message."""
        with self.assertRaisesMessage(ValidationError, "required"):
            validate_auth_secret("")

    def test_wrong_decoded_length_is_rejected(self):
        """Valid Base64 of the wrong decoded size fails with the length message."""
        too_short = base64.b64encode(b"a" * 16).decode()
        with self.assertRaisesMessage(ValidationError, "invalid length"):
            validate_auth_secret(too_short)


class SignupFormTests(TestCase):
    """Test cases for SignupForm."""

    def test_valid_signup_form(self):
        """Test valid signup form data."""
        form = SignupForm(
            data={
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
            }
        )
        self.assertTrue(form.is_valid())

    def test_signup_form_invalid_auth_secret(self):
        """Test signup form with malformed auth material."""
        form = SignupForm(
            data={
                "auth_secret": "not-base64",
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
            }
        )
        self.assertFalse(form.is_valid())
        self.assertIn("auth_secret", form.errors)

    def test_signup_form_accepts_valid_keypair(self):
        """A full, well-formed keypair triple is accepted and surfaced."""
        form = SignupForm(
            data={
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
                "public_key": PUBLIC_KEY,
                "encrypted_private_key": PRIVATE_KEY_BLOB,
                "private_key_iv": KEYPAIR_IV,
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        payload = form.keypair_payload()
        self.assertEqual(payload["public_key"], PUBLIC_KEY)

    def test_signup_form_without_keypair_yields_none(self):
        """The keypair is optional; absent fields mean no keypair payload."""
        form = SignupForm(
            data={
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
            }
        )
        self.assertTrue(form.is_valid())
        self.assertIsNone(form.keypair_payload())

    def test_signup_form_rejects_partial_keypair(self):
        """A partial triple is a buggy client, not a no-keypair signup."""
        form = SignupForm(
            data={
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
                "public_key": PUBLIC_KEY,  # blob + iv missing
            }
        )
        self.assertFalse(form.is_valid())

    def test_signup_form_rejects_wrong_public_key_length(self):
        form = SignupForm(
            data={
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
                "public_key": base64.b64encode(b"short").decode(),
                "encrypted_private_key": PRIVATE_KEY_BLOB,
                "private_key_iv": KEYPAIR_IV,
            }
        )
        self.assertFalse(form.is_valid())


class SigninFormTests(TestCase):
    """Test cases for SigninForm."""

    def test_valid_signin_form(self):
        """Test valid signin form data."""
        form = SigninForm(data={"user_id": "12345678", "auth_secret": AUTH_SECRET})
        self.assertTrue(form.is_valid())

    def test_signin_form_invalid_user_id(self):
        """Test signin form with invalid user_id format."""
        form = SigninForm(
            data={"user_id": "123", "auth_secret": AUTH_SECRET}  # Too short
        )
        self.assertFalse(form.is_valid())
        self.assertIn("user_id", form.errors)


class PasswordChangeFormTests(TestCase):
    """Test cases for PasswordChangeForm (needs the user's stored auth-secret hash)."""

    def setUp(self):
        self.current_auth_secret = AUTH_SECRET
        self.user = create_user_with_password(self.current_auth_secret)

    def _data(self, current=None, new=NEW_AUTH_SECRET):
        return {
            "current_auth_secret": current or self.current_auth_secret,
            "new_auth_secret": new,
            "auth_salt": NEW_AUTH_SALT,
            "vault_salt": NEW_VAULT_SALT,
        }

    def test_valid_password_change(self):
        """A correct current auth secret and new derivation material validate."""
        form = PasswordChangeForm(user=self.user, data=self._data())
        self.assertTrue(form.is_valid())

    def test_wrong_current_auth_secret_rejected(self):
        """An incorrect current auth secret fails on that field."""
        form = PasswordChangeForm(
            user=self.user, data=self._data(current=WRONG_AUTH_SECRET)
        )
        self.assertFalse(form.is_valid())
        self.assertIn(ERROR_INCORRECT_PASSWORD, str(form.errors))

    def test_new_auth_secret_must_be_valid_base64(self):
        """Malformed new auth material is rejected."""
        form = PasswordChangeForm(user=self.user, data=self._data(new="not-base64"))
        self.assertFalse(form.is_valid())
        self.assertIn("new_auth_secret", form.errors)


class AccountDeletionFormTests(TestCase):
    """Test cases for AccountDeletionForm."""

    def setUp(self):
        self.auth_secret = AUTH_SECRET
        self.user = create_user_with_password(self.auth_secret)

    def _form(self, auth_secret=None, confirmation_text="DELETE"):
        return AccountDeletionForm(
            user=self.user,
            data={
                "auth_secret": auth_secret or self.auth_secret,
                "confirmation_text": confirmation_text,
            },
        )

    def test_valid_deletion_confirmation(self):
        """The exact confirmation phrase with the right password validates."""
        self.assertTrue(self._form().is_valid())

    def test_confirmation_text_is_case_insensitive(self):
        """Lowercase 'delete' is normalised to DELETE and accepted."""
        self.assertTrue(self._form(confirmation_text="delete").is_valid())

    def test_wrong_confirmation_text_rejected(self):
        """A confirmation phrase other than DELETE is rejected."""
        self.assertFalse(self._form(confirmation_text="nope").is_valid())

    def test_wrong_auth_secret_rejected(self):
        """An incorrect auth secret fails even with a valid confirmation phrase."""
        form = self._form(auth_secret=WRONG_AUTH_SECRET)
        self.assertFalse(form.is_valid())
        self.assertIn(ERROR_INCORRECT_PASSWORD_DELETION, str(form.errors))
