# syntax=docker/dockerfile:1

# --- Build stage: assemble dependency wheels ---
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements/ requirements/
RUN pip wheel --wheel-dir /wheels -r requirements/production.txt


# --- Final stage: lean runtime image ---
FROM python:3.13-slim AS final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DJANGO_SETTINGS_MODULE=config.settings.production

WORKDIR /app

# Install dependencies from the prebuilt wheels (no network, no build tools).
COPY --from=builder /wheels /wheels
COPY requirements/ requirements/
RUN pip install --no-index --find-links=/wheels -r requirements/production.txt \
    && rm -rf /wheels

# Non-root runtime user.
RUN useradd --create-home --uid 1000 app

# Project source.
COPY . .

# Stable entrypoint path; pre-create STATIC_ROOT so a fresh named volume mounted
# there inherits app ownership (Docker seeds empty volumes from the image path).
RUN cp deployment/scripts/entrypoint.sh /entrypoint.sh \
    && chmod +x /entrypoint.sh \
    && mkdir -p /app/staticfiles \
    && chown -R app:app /app

USER app

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
# ASGI entrypoint: gunicorn manages uvicorn workers (worker_class in
# gunicorn.conf.py) so one server carries both HTTP and the /ws/ WebSockets.
CMD ["gunicorn", "config.asgi:application", "-c", "deployment/gunicorn.conf.py"]


# --- Dev stage: production image plus local-only tooling ---
# Adds the development requirements (django-extensions / Werkzeug / pyOpenSSL) so
# `runserver_plus` can serve the dev stack over HTTPS. Built only by
# docker-compose.override.yml; production builds target `final` explicitly, so
# this stage being last never leaks into a production image.
FROM final AS dev

USER root
RUN pip install -r requirements/development.txt
USER app
