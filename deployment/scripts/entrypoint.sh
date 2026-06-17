#!/bin/sh
# Web container entrypoint: prepare the app, then run the given command (CMD).
#
# Applies any pending migrations on every start (idempotent; safe for the
# single web instance). Collects static files unless SKIP_COLLECTSTATIC=1
# (set in development, where runserver serves static directly from
# STATICFILES_DIRS).
set -e

echo "[entrypoint] Applying migrations..."
python manage.py migrate --noinput

if [ "${SKIP_COLLECTSTATIC:-0}" != "1" ]; then
    echo "[entrypoint] Collecting static files..."
    python manage.py collectstatic --noinput
fi

echo "[entrypoint] Starting: $*"
exec "$@"
