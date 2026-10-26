"""
Production settings.

DEBUG is off and all sensitive values are required from the environment (no
fallbacks) so the app fails fast on misconfiguration. TLS is terminated by
nginx, so we trust the X-Forwarded-Proto header it sets and enable HTTPS-only
cookies and HSTS.
"""

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401,F403

DEBUG = False

# Required from the environment. Raises ImproperlyConfigured if missing.
SECRET_KEY = env("SECRET_KEY")  # noqa: F405

# Refuse to boot with a publicly-known placeholder/dev key: such a value makes
# session cookies and every other signed token forgeable. Catches copying the
# .env.example placeholder or the base dev fallback into a real deployment.
INSECURE_SECRET_KEYS = {
    DEV_FALLBACK_SECRET_KEY,  # noqa: F405  (from base via star import)
    "change-me-to-a-long-random-string",  # the .env.example placeholder
}
if SECRET_KEY in INSECURE_SECRET_KEYS:
    raise ImproperlyConfigured(
        "SECRET_KEY is set to a known-insecure placeholder. Generate a unique "
        "value (see .env.example) before deploying with DEBUG off."
    )

ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")  # noqa: F405

# The three tool origins. docs/deployment.md marks all three prod-required,
# but base.py reads them with a localhost fallback, so an unset one used to
# boot fine and then break the host dispatch silently: apps.core.hosts
# compares the request host against these, so a stale NOTE_SITE_URL means
# is_note_site() never matches and the whole note tool disappears (the editor
# at /, /<uuid>/ retrieves, the vault dispatch, every /live/ page 404s), while
# robots.txt and sitemap.xml serve the main-site variant on every host.
#
# Re-read rather than defaulted, and deliberately re-read to the SAME values
# base.py already resolved from the environment: CONTENT_SECURITY_POLICY is
# built at base.py import time from these, so assigning anything different
# here would leave the CSP pointing at the old origins. Single-domain setups
# set all three to the same URL (see docs/deployment.md).
SITE_URL = env("SITE_URL")  # noqa: F405
PASS_SITE_URL = env("PASS_SITE_URL")  # noqa: F405
NOTE_SITE_URL = env("NOTE_SITE_URL")  # noqa: F405

DATABASES = {"default": env.db("DATABASE_URL")}  # noqa: F405
# Reuse DB connections across requests (default 0 opens a new one each time) and
# drop ones that died between requests, so bursts of share traffic don't pay the
# full connect cost every time.
DATABASES["default"]["CONN_MAX_AGE"] = env.int("CONN_MAX_AGE", default=60)  # noqa: F405
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True

# Shared cache so django-ratelimit counters are consistent across Gunicorn
# workers (the LocMemCache from base.py would scope them per-process, effectively
# multiplying every limit by the worker count). REDIS_URL defaults to the bundled
# redis service; set it in the environment to point at an external/managed Redis.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": env("REDIS_URL", default="redis://redis:6379/0"),  # noqa: F405
    }
}

# Channel layer on its own Redis instance (redis-channels service), NOT the
# rate-limit cache above: that instance runs allkeys-lru, which could silently
# evict in-flight channel messages and group registrations (lost WebSocket
# broadcasts, half-dead groups). redis-channels runs noeviction instead; both
# are ephemeral on purpose - after a restart, live-note clients gap-heal via
# their sync cursor (`prev_seq` chaining + HTTP ?since= refetch).
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [
                env(  # noqa: F405
                    "CHANNEL_REDIS_URL", default="redis://redis-channels:6379/0"
                )
            ],
        },
    }
}

# e.g. ["https://share.example.com"] - required by Django for cross-origin POSTs.
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS")  # noqa: F405

# nginx sits in front of the app and appends the real client IP to
# X-Forwarded-For; trust exactly that one hop so rate limiting buckets by real
# client IP instead of the proxy's address. Raise this if you add another proxy
# in front (e.g. a load balancer or Cloudflare).
RATELIMIT_TRUSTED_PROXY_COUNT = env.int(
    "RATELIMIT_TRUSTED_PROXY_COUNT", default=1
)  # noqa: F405

# nginx terminates TLS and forwards the original scheme; enforce HTTPS throughout.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True

# HTTP Strict Transport Security (1 year).
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
