"""
Local development settings (default for manage.py).

Keeps DEBUG on and TLS-dependent security relaxed so the app works over plain
HTTP. The database defaults to the local SQLite file unless DATABASE_URL is set
(e.g. the dev Docker Compose points it at the Postgres service for parity).
"""

from .base import *  # noqa: F401,F403

DEBUG = True

ALLOWED_HOSTS = env.list(
    "ALLOWED_HOSTS", default=["localhost", "127.0.0.1", "0.0.0.0", ".localhost"]
)

# Relaxed cookie security for plain-HTTP local development.
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
