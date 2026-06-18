# Deployment Guide

This guide describes how to run **Proxima Red** in both local development and production using Docker Compose.

Production runs six containers behind an nginx reverse proxy with automatic Let's Encrypt TLS, a PostgreSQL database, a Redis cache, a Gunicorn application server, and a scheduled cleanup worker. Everything is configured through a single `.env` file.

---

## Table of contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
  - [Environment variables](#environment-variables)
  - [Settings modules](#settings-modules)
- [Development](#development)
- [Production](#production)
  - [1. Prepare the server](#1-prepare-the-server)
  - [2. Configure the environment](#2-configure-the-environment)
  - [3. Point DNS at the host](#3-point-dns-at-the-host)
  - [4. Issue TLS certificates](#4-issue-tls-certificates)
  - [5. Launch the stack](#5-launch-the-stack)
  - [6. Verify the deployment](#6-verify-the-deployment)
- [Deploying behind an existing host nginx](#deploying-behind-an-existing-host-nginx)
- [Operations](#operations)
  - [Viewing logs](#viewing-logs)
  - [Updating to a new release](#updating-to-a-new-release)
  - [Database backups and restore](#database-backups-and-restore)
  - [Expired share cleanup](#expired-share-cleanup)
  - [TLS certificate renewal](#tls-certificate-renewal)
  - [Running tests](#running-tests)
- [Troubleshooting](#troubleshooting)
- [Security considerations](#security-considerations)
- [Scaling and limitations](#scaling-and-limitations)
- [Command reference](#command-reference)

---

## Architecture

In production the stack is composed of five services on a private Docker network.
Only nginx publishes ports to the host; the application server and database are
never exposed directly.

```
                          :80 / :443
   ┌──────────┐   HTTPS   ┌─────────┐   :8000    ┌───────────────┐   :5432   ┌───────────────┐
   │ Internet │ ────────► │  nginx  │ ─────────► │ web (gunicorn)│ ─────────►│ db (postgres) │
   └──────────┘           └────┬────┘            └───────┬───────┘           └───────┬───────┘
                               │  serves /static         │ :6379                     │
                               │                   ┌─────▼──────┐                    ▲
                          ┌────┴─────┐             │   redis    │             ┌──────┴───────┐
                          │ certbot  │             │(rate-limit)│             │     cron     │
                          └──────────┘             └────────────┘             │delete_expired│
                                                                              │clearsessions │
                                                                              └──────────────┘
```

| Service   | Image                   | Responsibility                                                                 |
| --------- | ----------------------- | ------------------------------------------------------------------------------ |
| `nginx`   | `nginx:1.27-alpine`     | TLS termination, HTTP→HTTPS redirect, serves `/static/`, reverse proxy         |
| `web`     | built from `Dockerfile` | Gunicorn serving the Django app (WSGI)                                         |
| `db`      | `postgres:16-alpine`    | PostgreSQL database                                                            |
| `redis`   | `redis:7-alpine`        | Rate-limit counter cache shared across Gunicorn workers (ephemeral, no volume) |
| `certbot` | `certbot/certbot`       | Obtains and renews Let's Encrypt certificates (HTTP-01)                        |
| `cron`    | built from `Dockerfile` | Runs `delete_expired` every minute; `clearsessions` every hour                 |

**Persistent volumes**

| Volume            | Mounted by         | Contents                          |
| ----------------- | ------------------ | --------------------------------- |
| `pgdata`          | `db`               | PostgreSQL data directory         |
| `static_volume`   | `web`, `nginx`     | Collected static files            |
| `letsencrypt`     | `nginx`, `certbot` | TLS certificates and account data |
| `certbot_webroot` | `nginx`, `certbot` | ACME HTTP-01 challenge files      |

**Compose files**

| File                          | Purpose                                                                  |
| ----------------------------- | ------------------------------------------------------------------------ |
| `docker-compose.yml`          | Base definition (`db` + `web`), shared by all environments               |
| `docker-compose.override.yml` | Development overrides — **merged automatically** by `docker compose`     |
| `docker-compose.prod.yml`     | Production overrides — adds `nginx`, `certbot`, `cron`, restart policies |
| `docker-compose.host.yml`     | Host-nginx overrides — adds `staticproxy` for servers that run their own nginx ([see below](#deploying-behind-an-existing-host-nginx)) |

---

## Prerequisites

- **Docker Engine** 24+ and the **Docker Compose v2** plugin
  (`docker compose version`).
- For production:
  - A host with public IPv4/IPv6 and ports **80** and **443** reachable.
  - A **domain name** with a DNS `A`/`AAAA` record pointing at the host.
  - Outbound HTTPS access so certbot can reach the Let's Encrypt API.

No Python toolchain is required on the host — everything runs inside containers.

---

## Configuration

All configuration is supplied through environment variables, loaded from a `.env`
file in the repository root. Start from the template:

```bash
cp .env.example .env
```

Docker Compose reads `.env` for two purposes: interpolating `${VAR}` references
in the Compose files (e.g. `POSTGRES_*`, `DOMAIN`) and injecting variables into
the `web` and `cron` containers for Django.

### Environment variables

| Variable                        | Required    | Example                                        | Description                                                                                                                                                               |
| ------------------------------- | ----------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SECRET_KEY`                    | **prod**    | _(50+ random chars)_                           | Django cryptographic key. Generate with the command below.                                                                                                                |
| `DEBUG`                         | no          | `False`                                        | Never enable in production. Ignored by the dev settings (always `True`).                                                                                                  |
| `ALLOWED_HOSTS`                 | **prod**    | `proxima.red,pass.proxima.red`                 | Comma-separated hostnames Django will serve.                                                                                                                              |
| `CSRF_TRUSTED_ORIGINS`          | **prod**    | `https://proxima.red,https://pass.proxima.red` | Comma-separated, **scheme-qualified** origins for cross-origin POSTs.                                                                                                     |
| `SITE_URL`                      | **prod**    | `https://proxima.red`                          | Canonical base URL of the main site (no trailing slash). Used in the `Content-Security-Policy` `form-action` directive.                                                   |
| `PASS_SITE_URL`                 | **prod**    | `https://pass.proxima.red`                     | Base URL of the vault subdomain (no trailing slash). Used in CSP `connect-src` and `form-action`. Equal to `SITE_URL` for single-domain.                                  |
| `SESSION_COOKIE_DOMAIN`         | no          | `.proxima.red`                                 | Cookie domain shared across subdomains (leading dot). Required when the vault runs on a different subdomain from the main site.                                           |
| `DATABASE_URL`                  | **prod**    | `postgres://user:pass@db:5432/proximared`      | Django database DSN. Host is the Compose service name `db`.                                                                                                               |
| `POSTGRES_DB`                   | yes         | `proximared`                                   | Database name created by the `db` container.                                                                                                                              |
| `POSTGRES_USER`                 | yes         | `proximared`                                   | Database role.                                                                                                                                                            |
| `POSTGRES_PASSWORD`             | yes         | _(strong password)_                            | Database password. Must match `DATABASE_URL`.                                                                                                                             |
| `CONN_MAX_AGE`                  | no          | `60`                                           | Max age of DB connections in seconds (production only). Defaults to `60`.                                                                                                 |
| `DOMAIN`                        | **prod**    | `proxima.red`                                  | Primary domain; used by nginx for the certificate and default vhost.                                                                                                      |
| `CERTBOT_EMAIL`                 | **prod**    | `admin@example.com`                            | Contact address for Let's Encrypt expiry notices.                                                                                                                         |
| `RATELIMIT_TRUSTED_PROXY_COUNT` | no          | `1`                                            | Trusted reverse-proxy hops for reading the real client IP from `X-Forwarded-For`. Production defaults to `1` (nginx); raise for each additional proxy layer (e.g. a CDN). |
| `GUNICORN_WORKERS`              | no          | `3`                                            | Worker process count. Defaults to `(2 × CPU cores) + 1`.                                                                                                                  |
| `GUNICORN_TIMEOUT`              | no          | `60`                                           | Worker timeout in seconds. Defaults to `60`.                                                                                                                              |
| `STAGING`                       | no (script) | `1`                                            | When set for `init-letsencrypt.sh`, uses the Let's Encrypt staging CA.                                                                                                    |

> `DJANGO_SETTINGS_MODULE` is **not** set in `.env` — each Compose service selects
> the correct settings module itself (development vs production).

Generate a strong secret key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

Protect the file once it contains real secrets:

```bash
chmod 600 .env
```

### Settings modules

Settings are a split package under `config/settings/`:

| Module                        | Used by                          | Notes                                            |
| ----------------------------- | -------------------------------- | ------------------------------------------------ |
| `config.settings.base`        | (imported by the others)         | Shared config, env-driven with dev-safe defaults |
| `config.settings.development` | dev container, local `runserver` | `DEBUG=True`, plain HTTP, SQLite by default      |
| `config.settings.production`  | `web`/`cron` containers, WSGI    | `DEBUG=False`, HTTPS hardening, secrets required |
| `config.settings.testing`     | test suite                       | In-memory SQLite, fast password hasher           |

The default `DJANGO_SETTINGS_MODULE` is `config.settings.development` in
`manage.py` and `config.settings.production` in `wsgi.py`/`asgi.py`.

---

## Development

The development overrides run Django's autoreloading server with the source tree
bind-mounted for live edits, alongside a PostgreSQL container for parity with
production.

```bash
cp .env.example .env          # the defaults are fine for local use
docker compose up --build
```

- Application: <http://localhost:8000/>
- `docker-compose.override.yml` is applied automatically — no extra `-f` flags.
- Database migrations run on container start (via the entrypoint).
- Static files are served directly by `runserver`; `collectstatic` is skipped in
  development so the bind-mounted tree stays clean.

Stop the stack:

```bash
docker compose down            # add -v to also remove the database volume
```

---

## Production

### 1. Prepare the server

Install Docker Engine and the Compose plugin (see the
[official instructions](https://docs.docker.com/engine/install/)), then clone the
repository:

```bash
git clone <your-repository-url> proxima-red
cd proxima-red
```

### 2. Configure the environment

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(50))"   # paste into SECRET_KEY
```

Edit `.env` and set at minimum: `SECRET_KEY`, `ALLOWED_HOSTS`,
`CSRF_TRUSTED_ORIGINS`, `POSTGRES_PASSWORD`, `DATABASE_URL` (matching the Postgres
credentials), `DOMAIN`, and `CERTBOT_EMAIL`. Then `chmod 600 .env`.

### 3. Point DNS at the host

Create an `A` (and optionally `AAAA`) record for `DOMAIN` pointing at the
server's public IP. Verify it resolves before continuing:

```bash
dig +short share.example.com
```

### 4. Issue TLS certificates

Run the one-time bootstrap script. It seeds a temporary self-signed certificate
so nginx can start, then requests a real certificate over HTTP-01 and reloads
nginx:

```bash
./deployment/scripts/init-letsencrypt.sh
```

> **Tip:** Run it first with `STAGING=1 ./deployment/scripts/init-letsencrypt.sh`
> to validate the flow against the Let's Encrypt staging environment and avoid
> the production [rate limits](https://letsencrypt.org/docs/rate-limits/). Once it
> succeeds, re-run without `STAGING` to obtain a trusted certificate.

### 5. Launch the stack

```bash
make up
```

On startup the `web` container applies migrations and runs `collectstatic` into
the shared `static_volume`. nginx then serves those assets and proxies all other
requests to Gunicorn.

### 6. Verify the deployment

```bash
# Containers are running and healthy
docker compose -f docker-compose.yml -f docker-compose.prod.yml ps

# Django's production checklist passes
docker compose -f docker-compose.yml -f docker-compose.prod.yml exec web \
    python manage.py check --deploy
```

Then browse to `https://<DOMAIN>/`, confirm the certificate is valid, and that
`http://<DOMAIN>/` redirects to HTTPS.

---

## Deploying behind an existing host nginx

The standard setup above assumes the project's bundled `nginx` and `certbot`
own ports 80/443. If your server **already runs its own (system) nginx** as the
public reverse proxy — e.g. a multi-app host where nginx fronts several services
— use the **host-nginx model** instead. The bundled `nginx`/`certbot` are not
started; a small `staticproxy` container serves `/static/` and proxies to `web`,
published only on `127.0.0.1:8090`, and the host nginx terminates TLS and proxies
to it.

> **Do not run `init-letsencrypt.sh` in this model.** It starts the bundled
> nginx, which collides with the host nginx on ports 80/443.

```
Internet ─HTTPS─► host nginx (:443, system) ─► staticproxy (127.0.0.1:8090) ─► web (gunicorn :8000) ─► db / redis
                  TLS via the host certbot      serves /static/, proxies                                + cron
```

**Extra files (alongside the standard compose files):**

| File                             | Purpose                                                                                              |
| -------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `docker-compose.host.yml`        | Adds the `staticproxy` container on `127.0.0.1:8090`; the bundled `nginx`/`certbot` are not started  |
| `deployment/nginx/host.conf`     | Plain-HTTP nginx config for `staticproxy` (no TLS; passes `X-Forwarded-Proto` **through** from host)  |
| `deploy.mk` (from `deploy.mk.example`) | Per-host Makefile include that points the standard `make` targets at the host-nginx model      |

This model uses the **same `make` targets** as the bundled setup — the only
difference is the local `deploy.mk` include, which appends
`docker-compose.host.yml` and limits the started services to
`db redis web cron staticproxy`.

**Steps:**

1. Configure `.env` as in [step 2](#2-configure-the-environment). For a single
   domain set `PASS_SITE_URL` equal to `SITE_URL`. Because there are **two**
   proxy hops (host nginx + `staticproxy`), set `RATELIMIT_TRUSTED_PROXY_COUNT=2`.

2. Enable the host-nginx model for `make` (git-ignored, one-time per host):

   ```bash
   cp deploy.mk.example deploy.mk
   ```

3. Start the stack with the usual target:

   ```bash
   make up
   ```

4. Add a host nginx vhost that proxies to `127.0.0.1:8090`, then issue TLS with
   the host's certbot:

   ```nginx
   server {
       listen 80;
       listen [::]:80;
       server_name proxima.red www.proxima.red;

       location / {
           proxy_pass         http://127.0.0.1:8090;
           proxy_http_version 1.1;
           proxy_set_header   Host $host;
           proxy_set_header   X-Real-IP $remote_addr;
           proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header   X-Forwarded-Proto $scheme;
       }
   }
   ```

   ```bash
   sudo ln -s /etc/nginx/sites-available/proxima-red /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   sudo certbot --nginx -d proxima.red -d www.proxima.red
   ```

5. Verify: `curl -sI https://proxima.red | head -1`.

From here, all the usual operations work unchanged: `make up`, `make down`,
`make logs`, `make ps`, `make migrate`, `make shell`. To deploy a new release,
`git pull` then `make up`.

> **Firewall note (Docker + ufw).** If the host hardens Docker with
> `"iptables": false` and a default-deny ufw, container networking breaks in
> several non-obvious ways (forwarding, host↔container, loopback to published
> ports). Prefer letting Docker manage iptables — since every container binds
> `127.0.0.1`, nothing is publicly exposed and ufw still governs the host's
> inbound. If you must keep ufw strict, allow the Docker bridge range with
> `sudo ufw allow from 172.16.0.0/12` and ensure `ufw-before-input` keeps its
> loopback/established accepts.

---

## Operations

Common production operations are available as Makefile targets — run `make help` for a full list. For ad-hoc commands not covered by the Makefile, export the alias below to avoid repeating the `-f` flags:

```bash
alias dcp='docker compose -f docker-compose.yml -f docker-compose.prod.yml'
```

### Viewing logs

Application and access logs are written to stdout/stderr and captured by Docker:

```bash
make logs              # tail all services
dcp logs -f web        # application + Gunicorn access logs only
dcp logs -f nginx      # proxy logs only
dcp logs certbot       # certificate renewal output
```

### Updating to a new release

```bash
git pull
make up
```

Migrations run automatically as the new `web` container starts.

### Database backups and restore

Create a timestamped, gzipped dump in `./backups/`:

```bash
./deployment/scripts/backup.sh
```

Restore a dump into the running database (load `.env` first so the credentials
are available in your shell):

```bash
set -a; . ./.env; set +a
gunzip -c backups/proxima-red-YYYYMMDD-HHMMSS.sql.gz \
  | dcp exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

Schedule regular backups with a host cron entry, for example:

```cron
0 3 * * * cd /path/to/proxima-red && ./deployment/scripts/backup.sh
```

### Expired share cleanup

The `cron` service runs `manage.py delete_expired` every minute and
`manage.py clearsessions` every hour. To run cleanup manually or preview what
would be removed:

```bash
dcp run --rm web python manage.py delete_expired --dry-run
dcp run --rm web python manage.py delete_expired --statistics
```

### TLS certificate renewal

The `certbot` container attempts renewal twice daily and only acts when a
certificate is near expiry; nginx picks up renewed certificates on its next
reload. To force a renewal and reload:

```bash
dcp run --rm --entrypoint "certbot renew --webroot -w /var/www/certbot" certbot
dcp exec nginx nginx -s reload
```

### Running tests

Tests use isolated, fast settings (in-memory SQLite). They can run in any
environment:

```bash
dcp exec web python manage.py test --settings=config.settings.testing
```

---

## Troubleshooting

**`502 Bad Gateway` from nginx**
The `web` container is not ready or crashed during startup. Inspect it with
`dcp logs web` — common causes are a failed migration or a missing required
environment variable (production settings fail fast if `SECRET_KEY`,
`ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, or `DATABASE_URL` are unset).

**Certificate issuance fails**
Confirm DNS for `DOMAIN` resolves to the host and that port 80 is reachable from
the internet (the HTTP-01 challenge is served over plain HTTP). Test with
`STAGING=1` first. Inspect `dcp logs certbot` for the specific ACME error.

**`DisallowedHost` / `400 Bad Request`**
The requested host is not in `ALLOWED_HOSTS`. Ensure `ALLOWED_HOSTS` and `DOMAIN`
match the hostname users actually visit, then recreate `web`.

**`CSRF verification failed` (403) on form submission**
`CSRF_TRUSTED_ORIGINS` must list the scheme-qualified origin, e.g.
`https://share.example.com` (not just the bare hostname).

**Static files return 404 or look unstyled**
Confirm `collectstatic` ran (`dcp logs web` shows "Collecting static files") and
that nginx and web share the same `static_volume`. Re-run manually if needed:
`dcp exec web python manage.py collectstatic --noinput`.

**Database authentication failed**
`POSTGRES_USER`/`POSTGRES_PASSWORD`/`POSTGRES_DB` must be consistent with the
credentials in `DATABASE_URL`. If you change them after the volume was created,
the existing `pgdata` retains the original credentials — reset with
`dcp down -v` (this destroys data) or update the role inside Postgres.

---

## Security considerations

- **Secrets:** never commit `.env`. It is git-ignored; keep it `chmod 600`. Use a
  unique, high-entropy `SECRET_KEY` and a strong `POSTGRES_PASSWORD`.
- **Transport security:** production enables `SECURE_SSL_REDIRECT`, secure session
  and CSRF cookies, and HSTS (`max-age` of one year, including subdomains). nginx
  terminates TLS and forwards `X-Forwarded-Proto`, which Django trusts via
  `SECURE_PROXY_SSL_HEADER`.
- **Network exposure:** only nginx publishes ports. PostgreSQL and Gunicorn are
  reachable only on the internal Docker network.
- **Least privilege:** the application image runs as a non-root user.
- **Rate limiting:** authentication-sensitive endpoints are rate limited via
  `django-ratelimit`.
- **Zero-knowledge design:** encryption keys are derived/generated client-side and
  never sent to the server. Compromise of the database does not reveal shared
  secrets. See the project architecture notes for details.
- **Stay patched:** periodically rebuild to pick up base-image and dependency
  updates (`dcp build --pull`).

---

## Scaling and limitations

- A **single `web` instance** is assumed, so applying migrations on container
  start is safe. To scale horizontally, move `migrate` to a one-shot job and run
  multiple `web` replicas behind nginx.
- There is **no CI/CD pipeline or image registry** wired up; production updates
  are `git pull` + rebuild on the host. Adding a registry-based deploy is
  straightforward if needed later.
- PostgreSQL runs as a container with a local volume. For higher durability
  requirements, point `DATABASE_URL` at a managed database and drop the `db`
  service.

---

## Command reference

```bash
# --- Development ---
docker compose up --build                  # start dev stack (http://localhost:8000)
docker compose down                        # stop (add -v to wipe the database)
docker compose exec web python manage.py <cmd>

# --- Production (Makefile) ---
make up                                    # build images and start all services
make down                                  # stop and remove containers
make logs                                  # tail all service logs
make migrate                               # run migrations in the web container
make shell                                 # open a shell in the web container
make help                                  # list all targets

# --- Production (ad-hoc, alias: dcp) ---
dcp ps                                     # container status
dcp exec web python manage.py check --deploy
dcp logs -f web                            # tail a specific service

# --- Production (host-nginx model) ---
cp deploy.mk.example deploy.mk             # one-time: point `make` at the host-nginx model
make up                                    # then the usual targets work: up/down/logs/ps/migrate/shell

# --- One-time / maintenance ---
./deployment/scripts/init-letsencrypt.sh   # bootstrap TLS certificates (bundled-nginx model only)
./deployment/scripts/backup.sh             # gzipped pg_dump into ./backups/
```
