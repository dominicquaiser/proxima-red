# Development Guide

This guide covers setting up a local development environment for **proxima·red without Docker** — a virtualenv running Django's dev server directly against SQLite.

Prefer containers? Docker-based development (and production deployment) is covered in [deployment.md](./deployment.md). The two are interchangeable; pick whichever
you like.

## Table of contents

- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [Running the development server](#running-the-development-server)
- [Running over HTTPS (auth + vault flow)](#running-over-https-auth--vault-flow)
- [Running tests](#running-tests)
- [Code style](#code-style)

## Prerequisites

- **Python 3.13+**
- **Git**
- **Node.js 20+** — optional, only for the client-side crypto tests and Prettier.
- **[mkcert](https://github.com/FiloSottile/mkcert)** — optional, only for the HTTPS multi-domain flow below (`sudo apt install mkcert libnss3-tools` on Debian).

## Getting started

```bash
# Clone the repository
git clone https://github.com/dominicquaiser/proxima-red.git proxima-red
cd proxima-red

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install development dependencies
pip install -r requirements/development.txt

# Create the local database
python manage.py migrate
```

**No `.env` is required for basic local development.** The settings package (`config/settings/base.py`) ships dev-safe defaults: a fallback `SECRET_KEY`, a local SQLite database, permissive `ALLOWED_HOSTS`, and `http://localhost:8000` as the canonical site URL.

> Don't `cp .env.example .env` for plain local work — that file is the **production** template (it sets `proxima.red` hosts and `SESSION_COOKIE_DOMAIN=.proxima.red`, which breaks cookies on `localhost`). You only need a `.env`, with specific values, for the [HTTPS flow](#running-over-https-auth--vault-flow) below.

## Running the development server

```bash
python manage.py runserver
```

The app is available at <http://localhost:8000/>.

`config.settings.development` is the default settings module for `manage.py`. It enables `DEBUG`, serves SQLite, and runs everything on a single origin — so the sign-in → vault handoff stays on `localhost` and the vault key is kept in the browser's `sessionStorage`. This is all you need for most feature work.

## Running over HTTPS (auth + vault flow)

Plain `runserver` on `localhost` is fine for most work. But the production topology splits the two roles across hosts — **auth is canonical on the main site** (`SITE_URL`, e.g. `proxima.red`) and the **vault lives on the `pass.*` subdomain** (`PASS_SITE_URL`, e.g. `pass.proxima.red`). To exercise that real cross-subdomain flow locally you need HTTPS on a custom domain, for two reasons:

- **Shared session cookie.** The signed-in session must be readable on both the main host and the `pass.*` subdomain. A cookie is only shared across subdomains via `SESSION_COOKIE_DOMAIN` on a real registrable parent domain — `localhost` doesn't qualify (browsers treat it as a public suffix and refuse to share it), so a `localhost`-based split loops endlessly between the two hosts.
- **Web Crypto API.** Client-side key derivation needs `window.crypto.subtle`, which browsers expose only in a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts). `http://localhost` is special-cased as secure; a custom hostname like `proxima.test` over plain HTTP is **not**, so crypto would be disabled.

Serving both hosts over **HTTPS with a locally-trusted certificate** solves both at once. We use `runserver_plus` (from `django-extensions`, already in the dev
requirements) with a cert minted by [mkcert](https://github.com/FiloSottile/mkcert).

**1. Map the hostnames to loopback.** `.test` is RFC 6761-reserved, so it never collides with real DNS. Add to `/etc/hosts` (needs `sudo`):

```
127.0.0.1   proxima.test pass.proxima.test note.proxima.test
```

**2. Mint a locally-trusted certificate** into a `certs/` directory (git-ignored):

```bash
mkcert -install  # one-time: trust the local CA
mkdir -p certs
mkcert -cert-file certs/dev.pem -key-file certs/dev-key.pem proxima.test pass.proxima.test note.proxima.test
```

After `mkcert -install`, **fully restart your browser** so it reloads the trust store and stops warning about the cert.

**3. Create a `.env`** with the HTTPS origins (these override the base defaults; do **not** set `DATABASE_URL`, so the local SQLite default is kept):

```
ALLOWED_HOSTS=proxima.test,pass.proxima.test,note.proxima.test
CSRF_TRUSTED_ORIGINS=https://proxima.test:8000,https://pass.proxima.test:8000,https://note.proxima.test:8000
SITE_URL=https://proxima.test:8000
PASS_SITE_URL=https://pass.proxima.test:8000
NOTE_SITE_URL=https://note.proxima.test:8000
SESSION_COOKIE_DOMAIN=.proxima.test
```

**4. Run the HTTPS dev server**, pointing it at the mkcert files:

```bash
python manage.py runserver_plus 0.0.0.0:8000 \
    --cert-file certs/dev.pem --key-file certs/dev-key.pem
```

Sign in at <https://proxima.test:8000/auth/signin/>; on success you're handed off to the vault at <https://pass.proxima.test:8000/vault/>, with the vault key passed in the redirect URL fragment.

## Running tests

### Python

Tests use an isolated settings module with in-memory SQLite and a fast password hasher. **Always pass `--settings=config.settings.testing`:**

```bash
# Full suite
python manage.py test --settings=config.settings.testing

# A single app
python manage.py test apps.auth --settings=config.settings.testing
python manage.py test apps.passwd --settings=config.settings.testing

# A single test class or method
python manage.py test apps.auth.tests.test_views.SigninViewTests --settings=config.settings.testing
python manage.py test apps.auth.tests.test_views.SigninViewTests.test_signin_post_success --settings=config.settings.testing
```

Tests live in per-app `tests/` packages (`test_models`, `test_services`, `test_forms`, `test_views`, `test_utils`).

### Client-side crypto

The browser encryption code has its own suite. It needs **Node.js 20+** and no npm dependencies — the tests load the real `static/{shared/js/crypto,auth/js/auth-crypto}.js` against Node's built-in WebCrypto:

```bash
node --test tests/js/
```

Run these whenever you touch `static/shared/js/crypto.js` or `static/auth/js/auth-crypto.js`.

## Code style

**Python** — [Ruff](https://docs.astral.sh/ruff/) (100-character lines, double quotes, `E`/`F`/`I` rules; configured in `pyproject.toml`):

```bash
ruff format . # format
ruff check .  # lint
```

**JavaScript** — [Prettier](https://prettier.io/) (100-character lines, double quotes, semicolons; configured in `.prettierrc`):

```bash
npx prettier --write "static/**/js/"
```

Run both before opening a pull request.
