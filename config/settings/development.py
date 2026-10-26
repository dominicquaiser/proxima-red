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

# Zero-config note-tool host for local development: browsers resolve
# *.localhost to loopback and treat it as a secure context (so Web Crypto
# works), and ".localhost" is covered by the ALLOWED_HOSTS default above.
# The CSP string was already built in base.py with the base default; that is
# harmless because `form-action 'self'` covers the editor's same-origin POST.
NOTE_SITE_URL = env("NOTE_SITE_URL", default="http://note.localhost:8000")

# Relaxed cookie security for plain-HTTP local development.
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False

# django-extensions provides `runserver_plus`, used to serve the dev site over
# HTTPS (see docs/development.md). It is optional, so don't hard-fail the whole
# dev environment if it isn't installed.
try:
    import django_extensions  # noqa: F401

    INSTALLED_APPS += ["django_extensions"]
except ImportError:
    pass
