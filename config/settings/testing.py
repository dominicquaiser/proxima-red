"""
Test settings: fast and isolated.

Uses an in-memory SQLite database and a fast password hasher so the suite runs
quickly and independently of any configured DATABASE_URL.
"""

from .base import *  # noqa: F401,F403

DEBUG = False

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

# Fast hashing for tests (the real Argon2 hasher is slow by design).
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

SITE_URL = "http://testserver"
PASS_SITE_URL = "http://testserver"
# Equal to the other two on purpose: the host-dispatch tie-break (pass wins)
# keeps the all-hosts-equal behavior that existing tests rely on.
NOTE_SITE_URL = "http://testserver"
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]
