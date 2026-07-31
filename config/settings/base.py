"""
Base settings shared across all environments.

Environment-specific modules (development, production, testing) import everything
from here with ``from .base import *`` and then override what differs.

Configuration is read from environment variables via ``django-environ`` so the
same code runs locally, in Docker, and in production. Sensible development
defaults are provided here; production.py tightens or requires the sensitive ones.
"""

from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent

env = environ.Env()
# Load a local .env file if present (no-op when the file is absent, e.g. in CI).
environ.Env.read_env(BASE_DIR / ".env")


# A clearly-marked dev-only fallback keeps local and test runs friction-free.
# production.py requires SECRET_KEY from the environment and refuses to boot with
# this (publicly-known) value, so it can never reach a real deployment.
DEV_FALLBACK_SECRET_KEY = (
    "django-insecure-1t2hbk3qe$o=0co%6g9hi^i%f9#k5va^48_@(&4qr9!3i*zarx"
)
SECRET_KEY = env("SECRET_KEY", default=DEV_FALLBACK_SECRET_KEY)

DEBUG = env.bool("DEBUG", default=False)

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["localhost", "127.0.0.1", "0.0.0.0"])

SITE_URL = env("SITE_URL", default="http://localhost:8000")
PASS_SITE_URL = env("PASS_SITE_URL", default="http://localhost:8000")
NOTE_SITE_URL = env("NOTE_SITE_URL", default="http://localhost:8000")


# --- Static files ---

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
# Target for `collectstatic`; served by nginx in production.
STATIC_ROOT = BASE_DIR / "staticfiles"


# --- Application definition ---

# NB: django.contrib.auth is intentionally NOT installed. This project uses a
# custom user model and session auth (apps.auth); Django's built-in auth_user
# model and its admin / createsuperuser flow would only add an unused,
# raw-password-based account surface at odds with the zero-knowledge design. The
# password hashers (make_password/check_password, Argon2) are imported directly
# from django.contrib.auth.hashers and work without the app being in INSTALLED_APPS.
INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # WebSocket routing/consumers for live-note sync (apps.note.consumers).
    # Deliberately without daphne: `manage.py runserver` stays the plain WSGI
    # dev server (no WS - the live client falls back to polling); WebSockets
    # need an ASGI server (uvicorn) serving config.asgi.
    "channels",
    "apps.core",
    "apps.passwd",
    "apps.note",
    "apps.auth",  # Custom authentication app (table: proxima_user)
]

# NB: Django's AuthenticationMiddleware is intentionally omitted. This project
# uses a custom session auth (apps.auth) and never populates request.user, so
# including it would only inject a misleading AnonymousUser. The custom user is
# exposed to templates via apps.auth.context_processors.current_user instead.
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "apps.core.middleware.SecurityHeadersMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
                # Custom session user as {{ current_user }} (see the note on
                # MIDDLEWARE re: why Django's auth processor is not used).
                "apps.auth.context_processors.current_user",
                # Absolute base URLs for the two domains (proxima.red /
                # pass.proxima.red) so templates can build cross-domain links.
                "apps.core.context_processors.site_urls",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# ASGI entrypoint (HTTP + WebSocket ProtocolTypeRouter). Production and the
# uvicorn dev server serve this; config.wsgi remains for WSGI-only runners.
ASGI_APPLICATION = "config.asgi.application"

# --- Channel layer (WebSocket group fan-out) ---
# In-memory: correct for the single-process dev server and for tests. It does
# NOT fan out across processes, so production.py swaps in the Redis-backed
# layer (dedicated redis-channels service) for multi-worker gunicorn/uvicorn.
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    }
}


# --- Database ---
# Driven by DATABASE_URL; defaults to the local SQLite file for bare-metal dev.

DATABASES = {
    "default": env.db("DATABASE_URL", default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
}


# --- Cache ---
# In-memory cache: fine for single-process dev/test. This is the store
# django-ratelimit uses for its counters; production.py swaps in a shared Redis
# cache so those counters are consistent across Gunicorn workers.

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}


# --- Password validation ---
# No AUTH_PASSWORD_VALIDATORS: Django only applies them via validate_password(),
# which this custom-auth project never calls - signup/signin hash a client-derived
# secret of fixed length directly (validated in apps/auth/forms.py). Password
# strength is enforced client-side; the server only ever receives a fixed-size
# derived auth secret, so there is no raw password here for Django to validate.


# --- Internationalisation ---

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]


# --- Security ---
# TLS-dependent flags default to off here and are enabled in production.py.
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False

# Always-on hardening (safe in every environment).
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_DOMAIN = env("SESSION_COOKIE_DOMAIN", default=None)
CSRF_COOKIE_SAMESITE = "Lax"

# Strict session idle timeout, and the single source of truth for it:
# apps/auth/services.py reads settings.SESSION_COOKIE_AGE when it calls
# request.session.set_expiry() on sign-in and after a password change.
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 30 * 60  # 30 minutes, in seconds

# Additional security headers.
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# Don't leak request URLs to third parties. Applied by Django's SecurityMiddleware.
# "same-origin" (not "no-referrer") so cross-origin requests still send no
# referrer, while same-origin POSTs keep a real Origin header. Under
# "no-referrer" the browser sends Origin: null on POST, which Django's CSRF
# Origin check rejects with "null does not match any trusted origins".
SECURE_REFERRER_POLICY = "same-origin"

# --- Content Security Policy ---
# Applied by apps.core.middleware.SecurityHeadersMiddleware. script-src is locked
# to same-origin assets: the key defence for a browser-delivered E2EE app, since
# an injected or third-party script could read the URL-fragment share key or the
# sessionStorage vault key. Django's {{ ...|json_script }} emits a non-executable
# data block, so it is unaffected by script-src. style-src keeps 'unsafe-inline'
# because a handful of templates use inline style attributes (style injection is
# far lower risk than script injection). No third-party origins are loaded, so
# every fetch directive stays same-origin, which also makes Subresource
# Integrity moot here: there are no cross-origin scripts to pin.


def _ws_origin(url):
    """http(s):// origin -> its ws(s):// twin, for the CSP connect-src.

    The live-note WebSocket is same-origin on the note host, which CSP3
    `'self'` already covers in current browsers, but older Safari matched
    `'self'` by scheme too - listing the wss: origin explicitly is cheap
    insurance. (development.py overrides NOTE_SITE_URL after this string is
    built; that staleness is harmless because the dev WS stays same-origin
    and is covered by 'self'.)
    """
    for scheme, ws_scheme in (("https://", "wss://"), ("http://", "ws://")):
        if url.startswith(scheme):
            return ws_scheme + url[len(scheme) :]
    return url


CONTENT_SECURITY_POLICY = env(
    "CONTENT_SECURITY_POLICY",
    default="; ".join(
        [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            f"connect-src 'self' {PASS_SITE_URL} {_ws_origin(NOTE_SITE_URL)}",
            f"form-action 'self' {SITE_URL} {PASS_SITE_URL} {NOTE_SITE_URL}",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
        ]
    ),
)

# Disable powerful browser features the app never uses (defence in depth).
PERMISSIONS_POLICY = env(
    "PERMISSIONS_POLICY",
    default=(
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    ),
)

# --- Reverse-proxy client IP resolution ---
# Number of trusted reverse proxies in front of the app. Used by
# apps.core.http.get_client_ip to read the real client IP from X-Forwarded-For
# for rate limiting. 0 (no proxy) is correct for local/dev where requests hit the
# dev server directly; production.py raises this to 1 for nginx.
RATELIMIT_TRUSTED_PROXY_COUNT = env.int("RATELIMIT_TRUSTED_PROXY_COUNT", default=0)


# --- Logging ---
# Write to stdout/stderr so logs are captured by the container runtime
# (`docker compose logs`). Avoid file handlers with relative paths.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
    "loggers": {
        # auth.views emits expected error logs (failed signups/signins, etc.);
        # pin it to ERROR with its own handler and propagate=False so those don't
        # double-log via root. passwd.views deliberately inherits root instead, so
        # its info/debug lines (expired-share deletes, vault saves) aren't muted.
        "apps.auth.views": {
            "handlers": ["console"],
            "level": "ERROR",
            "propagate": False,
        },
    },
}
