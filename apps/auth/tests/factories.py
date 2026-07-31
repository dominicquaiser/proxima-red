"""Test-only user construction helpers.

Kept out of ``apps.auth.services`` so production code carries no test-only
constructors. Imported by both the auth and passwd test suites.
"""

import base64
import secrets

from apps.auth.constants import PUBLIC_KEY_LENGTH_BYTES, SALT_LENGTH_BYTES
from apps.auth.models import User, UserKeyPair
from apps.auth.services import create_user_with_auth_secret

# A stand-in for the browser's Base64 SPKI public key: the server only ever
# checks the decoded byte length (PUBLIC_KEY_LENGTH_BYTES), never the curve
# math, so a fixed-length blob is a valid fixture.
VALID_PUBLIC_KEY_B64 = base64.b64encode(b"\x01" * PUBLIC_KEY_LENGTH_BYTES).decode()
VALID_PRIVATE_KEY_BLOB_B64 = base64.b64encode(b"encryptedpkcs8blob").decode()
VALID_KEYPAIR_IV_B64 = "AAAAAAAAAAAAAAAA"  # 12 zero bytes, Base64


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


def make_keypair(user: User, **overrides) -> UserKeyPair:
    """Create a collaboration keypair row for ``user`` with valid fixtures."""
    fields = {
        "public_key": VALID_PUBLIC_KEY_B64,
        "encrypted_private_key": VALID_PRIVATE_KEY_BLOB_B64,
        "private_key_iv": VALID_KEYPAIR_IV_B64,
    }
    fields.update(overrides)
    return UserKeyPair.objects.create(user=user, **fields)
