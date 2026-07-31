"""Authentication forms for user signup, signin, password change, and account deletion."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django import forms
from django.contrib.auth.hashers import check_password

from apps.core.encoding import (
    Base64LengthError,
    decode_base64,
    decode_base64_exact_length,
)

from .models import is_valid_user_id
from .constants import (
    ACCOUNT_DELETION_CONFIRMATION_TEXT,
    AUTH_SECRET_LENGTH_BYTES,
    ERROR_INCORRECT_PASSWORD,
    ERROR_INCORRECT_PASSWORD_DELETION,
    ERROR_INVALID_USER_ID,
    ERROR_CONFIRMATION_TEXT,
    MAX_KEYPAIR_IV_LENGTH,
    MAX_PRIVATE_KEY_BLOB_LENGTH,
    PUBLIC_KEY_LENGTH_BYTES,
    SALT_LENGTH_BYTES,
    USER_ID_LENGTH,
)

if TYPE_CHECKING:
    from .models import User


def validate_base64_bytes(value: str, *, expected_length: int, label: str) -> str:
    """Validate a strict Base64 value and its decoded byte length."""
    if not value:
        raise forms.ValidationError(f"{label} is required.")
    try:
        decode_base64_exact_length(value, expected_length)
    except Base64LengthError:
        raise forms.ValidationError(f"{label} has an invalid length.")
    except ValueError:
        raise forms.ValidationError(f"{label} must be a valid Base64 value.")
    return value


def validate_auth_secret(value: str) -> str:
    """Validate the client-derived authentication secret shape."""
    return validate_base64_bytes(
        value,
        expected_length=AUTH_SECRET_LENGTH_BYTES,
        label="Authentication secret",
    )


def validate_kdf_salt(value: str, *, label: str = "Salt") -> str:
    """Validate a client-generated PBKDF2 salt."""
    return validate_base64_bytes(value, expected_length=SALT_LENGTH_BYTES, label=label)


def validate_base64_blob(value: str, *, max_chars: int, label: str) -> str:
    """Validate a strict Base64 blob of bounded (not exact) size."""
    if not value:
        raise forms.ValidationError(f"{label} is required.")
    if len(value) > max_chars:
        raise forms.ValidationError(f"{label} has an invalid length.")
    try:
        decode_base64(value)
    except ValueError:
        raise forms.ValidationError(f"{label} must be a valid Base64 value.")
    return value


class KeypairFieldsMixin:
    """Shared validation for the collaboration-keypair triple.

    Cross-runtime contract with static/shared/js/keywrap.js: the SPKI public
    key is exactly ``PUBLIC_KEY_LENGTH_BYTES`` (ECDH P-256); the private-key
    blob is a bounded AES-GCM ciphertext under the vault key; the IV is the
    app-wide 12 GCM bytes.
    """

    def clean_public_key(self) -> str:
        return validate_base64_bytes(
            self.cleaned_data.get("public_key"),
            expected_length=PUBLIC_KEY_LENGTH_BYTES,
            label="Public key",
        )

    def clean_encrypted_private_key(self) -> str:
        return validate_base64_blob(
            self.cleaned_data.get("encrypted_private_key"),
            max_chars=MAX_PRIVATE_KEY_BLOB_LENGTH,
            label="Encrypted private key",
        )

    def clean_private_key_iv(self) -> str:
        return validate_base64_bytes(
            self.cleaned_data.get("private_key_iv"),
            expected_length=12,  # 12 GCM bytes, the app-wide IV shape
            label="Private key IV",
        )


class KeypairForm(KeypairFieldsMixin, forms.Form):
    """Form for creating the account's collaboration keypair."""

    public_key = forms.CharField(widget=forms.HiddenInput())
    encrypted_private_key = forms.CharField(
        max_length=MAX_PRIVATE_KEY_BLOB_LENGTH, widget=forms.HiddenInput()
    )
    private_key_iv = forms.CharField(
        max_length=MAX_KEYPAIR_IV_LENGTH, widget=forms.HiddenInput()
    )


class PasswordVerificationMixin:
    """Mixin for forms that need to verify the user's current auth secret."""

    user: User | None

    def __init__(self, user: User | None, *args, **kwargs) -> None:
        self.user = user
        super().__init__(*args, **kwargs)

    def verify_auth_secret(self, auth_secret: str, error_message: str) -> str:
        """
        Check ``auth_secret`` against the user's stored hash.

        Raises immediately when ``self.user`` is ``None`` so callers don't need
        a separate guard against an unauthenticated context.
        """
        if not self.user or not check_password(auth_secret, self.user.password_hash):
            raise forms.ValidationError(error_message)
        return auth_secret


class PasswordChangeForm(PasswordVerificationMixin, forms.Form):
    """Form for updating the user's client-derived authentication secret."""

    current_auth_secret = forms.CharField(widget=forms.HiddenInput())
    new_auth_secret = forms.CharField(widget=forms.HiddenInput())
    auth_salt = forms.CharField(widget=forms.HiddenInput())
    vault_salt = forms.CharField(widget=forms.HiddenInput())

    def clean_current_auth_secret(self) -> str:
        auth_secret = validate_auth_secret(self.cleaned_data.get("current_auth_secret"))
        return self.verify_auth_secret(auth_secret, ERROR_INCORRECT_PASSWORD)

    def clean_new_auth_secret(self) -> str:
        return validate_auth_secret(self.cleaned_data.get("new_auth_secret"))

    def clean_auth_salt(self) -> str:
        return validate_kdf_salt(self.cleaned_data.get("auth_salt"), label="Auth salt")

    def clean_vault_salt(self) -> str:
        return validate_kdf_salt(
            self.cleaned_data.get("vault_salt"), label="Vault salt"
        )


class AccountDeletionForm(PasswordVerificationMixin, forms.Form):
    """Form for confirming account deletion."""

    auth_secret = forms.CharField(widget=forms.HiddenInput())

    confirmation_text = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "field__input",
                "placeholder": "Type DELETE in all caps",
                "required": True,
                "autocomplete": "off",
            }
        ),
        label="Confirmation",
    )

    def clean_auth_secret(self) -> str:
        auth_secret = validate_auth_secret(self.cleaned_data.get("auth_secret"))
        return self.verify_auth_secret(auth_secret, ERROR_INCORRECT_PASSWORD_DELETION)

    def clean_confirmation_text(self) -> str:
        # Normalised before comparing, so "delete" passes even though the UI says all-caps.
        confirmation = self.cleaned_data.get("confirmation_text", "")
        if confirmation.strip().upper() != ACCOUNT_DELETION_CONFIRMATION_TEXT:
            raise forms.ValidationError(ERROR_CONFIRMATION_TEXT)
        return confirmation


class SignupForm(forms.Form):
    """Form for creating a new user account.

    The collaboration-keypair triple is optional (a noscript-adjacent or older
    client simply doesn't send it; the keypair is then created lazily at the
    account's first collaboration action) but all-or-nothing: a partial triple
    means a buggy client and is rejected rather than half-stored.
    """

    auth_secret = forms.CharField(widget=forms.HiddenInput())
    auth_salt = forms.CharField(widget=forms.HiddenInput())
    vault_salt = forms.CharField(widget=forms.HiddenInput())
    public_key = forms.CharField(required=False, widget=forms.HiddenInput())
    encrypted_private_key = forms.CharField(
        required=False, max_length=MAX_PRIVATE_KEY_BLOB_LENGTH, widget=forms.HiddenInput()
    )
    private_key_iv = forms.CharField(
        required=False, max_length=MAX_KEYPAIR_IV_LENGTH, widget=forms.HiddenInput()
    )

    def clean_auth_secret(self) -> str:
        return validate_auth_secret(self.cleaned_data.get("auth_secret"))

    def clean_auth_salt(self) -> str:
        return validate_kdf_salt(self.cleaned_data.get("auth_salt"), label="Auth salt")

    def clean_vault_salt(self) -> str:
        return validate_kdf_salt(
            self.cleaned_data.get("vault_salt"), label="Vault salt"
        )

    def clean(self) -> dict:
        cleaned = super().clean()
        triple = (
            cleaned.get("public_key"),
            cleaned.get("encrypted_private_key"),
            cleaned.get("private_key_iv"),
        )
        if not any(triple):
            return cleaned
        if not all(triple):
            raise forms.ValidationError(
                "Keypair fields must be provided together."
            )
        # Reuse the strict keypair shape checks on the optional fields.
        cleaned["public_key"] = validate_base64_bytes(
            triple[0], expected_length=PUBLIC_KEY_LENGTH_BYTES, label="Public key"
        )
        cleaned["encrypted_private_key"] = validate_base64_blob(
            triple[1],
            max_chars=MAX_PRIVATE_KEY_BLOB_LENGTH,
            label="Encrypted private key",
        )
        cleaned["private_key_iv"] = validate_base64_bytes(
            triple[2], expected_length=12, label="Private key IV"
        )
        return cleaned

    def keypair_payload(self) -> dict | None:
        """Return the validated keypair triple, or None when not supplied."""
        if not self.cleaned_data.get("public_key"):
            return None
        return {
            "public_key": self.cleaned_data["public_key"],
            "encrypted_private_key": self.cleaned_data["encrypted_private_key"],
            "private_key_iv": self.cleaned_data["private_key_iv"],
        }


class SigninForm(forms.Form):
    """Form for signing into an existing user account."""

    user_id = forms.CharField(
        max_length=USER_ID_LENGTH,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Enter your 8-digit User ID",
                "pattern": "[0-9]{8}",
                "maxlength": "8",
                "required": True,
                "autocomplete": "username",
            }
        ),
        help_text="Your 8-digit numeric User ID",
        label="User ID",
    )

    auth_secret = forms.CharField(widget=forms.HiddenInput())

    def clean_user_id(self) -> str | None:
        user_id = self.cleaned_data.get("user_id")
        if user_id and not is_valid_user_id(user_id):
            raise forms.ValidationError(ERROR_INVALID_USER_ID)
        return user_id

    def clean_auth_secret(self) -> str:
        return validate_auth_secret(self.cleaned_data.get("auth_secret"))
