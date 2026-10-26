"""Independent vault access windows inside the shared account session.

Only explicit note activity renews the note window. Reading state and using
password APIs never extend a grant. All times are server timestamps.
"""

import hashlib
import secrets
import time

from django.conf import settings

from .constants import (
    SESSION_KEY_CREDENTIAL_VERSION,
    SESSION_KEY_VAULT_EXPIRES_AT,
    SESSION_KEY_VAULT_SESSION_ID,
)


def credential_version(user):
    """Invalidate old sessions when the account password changes."""
    return hashlib.sha256(user.password_hash.encode()).hexdigest()


def identity(user):
    """Public identity of ciphertext this browser is allowed to write."""
    return f"{user.user_id}:{user.vault_salt}"


def grant_access(request, user, tools):
    """Called only after password verification (including sign-in/change)."""
    now = time.time()
    request.session[SESSION_KEY_CREDENTIAL_VERSION] = credential_version(user)
    if not request.session.get(SESSION_KEY_VAULT_SESSION_ID):
        request.session[SESSION_KEY_VAULT_SESSION_ID] = secrets.token_hex(16)
    for tool in tools:
        duration = (
            settings.PASSWORD_VAULT_TIMEOUT if tool == "pass" else settings.NOTE_VAULT_IDLE_TIMEOUT
        )
        request.session[SESSION_KEY_VAULT_EXPIRES_AT.format(tool=tool)] = now + duration
    request.session.set_expiry(settings.SESSION_COOKIE_AGE)


def access_state(request, user, tool):
    """Return state without changing the session or extending any deadline."""
    now = time.time()
    expiry = request.session.get(SESSION_KEY_VAULT_EXPIRES_AT.format(tool=tool), 0)
    valid_version = request.session.get(SESSION_KEY_CREDENTIAL_VERSION) == credential_version(user)
    unlocked = valid_version and isinstance(expiry, (int, float)) and expiry > now
    context = hashlib.sha256(
        f"{identity(user)}:{request.session.get(SESSION_KEY_VAULT_SESSION_ID, '')}".encode()
    ).hexdigest()
    return {
        "tool": tool,
        "user_id": user.user_id,
        "identity": identity(user),
        "cache_context": context,
        "unlocked": bool(unlocked),
        "expires_at": expiry if unlocked else 0,
        "server_time": now,
    }


def renew_note_access(request):
    """Renew only after the caller has checked the existing grant is valid."""
    request.session[SESSION_KEY_VAULT_EXPIRES_AT.format(tool="note")] = time.time() + settings.NOTE_VAULT_IDLE_TIMEOUT
    request.session.set_expiry(settings.SESSION_COOKIE_AGE)


def revoke_key_caches(request):
    """Rotate the cache context so key copies cached under the old one are refused."""
    request.session.pop(SESSION_KEY_VAULT_SESSION_ID, None)
