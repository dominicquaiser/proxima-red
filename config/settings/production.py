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

# e.g. ["https://share.example.com"] — required by Django for cross-origin POSTs.
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
