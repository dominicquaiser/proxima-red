"""Test-only user construction helpers.

Kept out of ``apps.auth.services`` so production code carries no test-only
constructors. Imported by both the auth and passwd test suites.
"""

import base64
import secrets

from apps.auth.constants import SALT_LENGTH_BYTES
from apps.auth.models import User
from apps.auth.services import create_user_with_auth_secret


def generate_salt() -> str:
    """Generate a Base64-encoded random KDF salt - a test stand-in for the client.

    In production these public salts are generated in the browser and POSTed to
    the server; the backend never creates them. Tests still need valid salts to
    build users, so this mirrors the client's salt shape: ``SALT_LENGTH_BYTES``
    random bytes, Base64-encoded.
    """
    return base64.b64encode(secrets.token_bytes(SALT_LENGTH_BYTES)).decode("utf-8")


def create_user_with_password(password: str) -> User:
    """
    Create a user from a client-derived authentication secret, generating fresh
    public salts.

    The argument is treated as a client-derived authentication secret, not a raw
    account password. Runtime auth views call
    :func:`apps.auth.services.create_user_with_auth_secret` explicitly; this
    wrapper just spares tests from generating the two salts every time.
    """
    return create_user_with_auth_secret(
        password,
        auth_salt=generate_salt(),
        vault_salt=generate_salt(),
    )
