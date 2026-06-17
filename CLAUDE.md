# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the development server
python manage.py runserver

# Run all tests (use the fast, isolated test settings)
python manage.py test --settings=config.settings.testing

# Run tests for a specific app
python manage.py test apps.auth --settings=config.settings.testing
python manage.py test apps.passwd --settings=config.settings.testing

# Run a single test class or method (tests live in per-app tests/ packages:
# test_models, test_services, test_forms, test_views, test_utils)
python manage.py test apps.auth.tests.test_models.UserModelTests --settings=config.settings.testing
python manage.py test apps.auth.tests.test_views.SigninViewTests.test_signin_post_success --settings=config.settings.testing

# Run the client-side crypto tests (Node 20+, no npm dependencies; tests/js/helpers.js
# loads the real static/js/{crypto,auth-crypto}.js against Node's built-in WebCrypto)
node --test tests/js/

# Delete expired password shares (in production the `cron` service runs this every minute)
python manage.py delete_expired
python manage.py delete_expired --dry-run
python manage.py delete_expired --statistics

# Docker — development (merges docker-compose.override.yml automatically)
docker compose up --build                 # app at http://localhost:8000

# Docker — production
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

## Architecture

### Settings & Environments

Settings are a split package, **not** a single module:
`config/settings/{base,development,production,testing}.py`. `base.py` reads config
from environment variables (`.env`, via `django-environ`) with dev-safe defaults;
`production.py` requires the sensitive ones (`SECRET_KEY`, `ALLOWED_HOSTS`,
`DATABASE_URL`, `CSRF_TRUSTED_ORIGINS`) and enables HTTPS hardening.

Default `DJANGO_SETTINGS_MODULE`: `config.settings.development` in `manage.py`,
`config.settings.production` in `wsgi.py`/`asgi.py`. Docker services set it
explicitly. Run tests with `--settings=config.settings.testing` (in-memory SQLite,
fast hasher). Dependencies live under `requirements/{base,production,development}.txt`.
Deployment/Docker details are in `docs/deployment.md`.

### Project Layout

Django project config lives in `config/` (split settings package, root URLs, wsgi/asgi). Apps are in `apps/` with three modules:

- `apps/auth` — custom user authentication (signup, signin, session management, account management)
- `apps/core` — static informational pages (about, imprint, privacy)
- `apps/passwd` — password sharing: create shares, retrieve shares, authenticated vault

Templates are in `templates/{app}/`, static files in `static/{css,js,icons}/`.

### Custom Auth Model — Not Django's AbstractUser

`apps/auth` defines its own `User` model that is **not** a subclass of `AbstractUser` and does **not** replace Django's built-in auth. `django.contrib.auth` is intentionally **not** in `INSTALLED_APPS` (see the comment in `config/settings/base.py`); only its password hashers (`make_password`/`check_password`, Argon2) are imported directly from `django.contrib.auth.hashers`, which works without the app installed. The custom model's DB table is explicitly set to `proxima_user` so the `auth`-named app avoids Django's `auth_user` table naming.

Users have no username or email. The public identifier is an auto-generated 8-digit numeric `user_id`. The server stores `password_hash` (Argon2 via `make_password`, over a **client-derived auth secret** — never the raw password) plus two public KDF salts, `auth_salt` and `vault_salt`, that the browser uses for key derivation (see zero-knowledge section below). The server never sees the account password and never generates the salts.

Session auth is manual: `request.session['authenticated'] = True` and `request.session['user_id'] = user.user_id`. The keys are constants in `apps/auth/constants.py`.

### Zero-Knowledge Design

There are two separate crypto flows, both using AES-256-GCM:

**Anonymous sharing flow** (`static/js/crypto.js` + `apps/passwd/`):

- Browser generates a random AES-256 key
- Encrypts the password client-side, sends `(ciphertext, iv)` to the server
- The optional title is also encrypted client-side under the **same key** but with its **own IV** (`crypto.js` `encryptShare()` — never reuse one IV across both, or AES-GCM breaks)
- The key is never sent to the server — it's embedded in the URL fragment (`/uuid/#base64key`)
- Server stores only `SharedPassword.encrypted_data`/`iv` and `SharedPassword.encrypted_title`/`title_iv` (title fields are blank when no title was given)
- The retrieve page decrypts the title on load (for context) and the secret on demand

**Authenticated vault flow** (`static/js/auth-crypto.js` + `apps/auth/` + `ServiceData` model):

The account password is never sent to the server. The **client** generates two public salts and derives two independent values from the password, each via PBKDF2-SHA256 (100,000 iterations) under its own salt:

- **Auth secret** = `PBKDF2(password, auth_salt)` (with a domain-separation context string, `auth-crypto.js` `deriveAuthSecret()`). This is sent to the server, which Argon2-hashes it into `password_hash`. The server only ever sees this derived secret; holding it does **not** let the server derive the vault key.
- **Vault key** = `PBKDF2(password, vault_salt)` (`auth-crypto.js` `deriveKeyFromPassword()`). This AES-256 key never leaves the browser; the exported key is kept in `sessionStorage` for the session.

- At **signup** the client generates `auth_salt` + `vault_salt`, derives the auth secret, and POSTs `(auth_secret, auth_salt, vault_salt)`; the server stores the Argon2 hash and both salts.
- At **signin** the client POSTs `user_id` to `/auth/salts/`, which returns both public salts (deterministic **decoy** salts for unknown ids, so the endpoint is not an account-existence oracle — `services.generate_decoy_salt`). The client derives the auth secret and submits it; on success it derives + stores the vault key (`establishSecureSession()`).
- The user's vault data (`ServiceData.encrypted_data`) is encrypted with the vault key.
- `ServiceData.iv` is stored as a `BinaryField` (12 bytes); it is base64-encoded before being passed to JavaScript.

**Important consequence**: changing the password rotates both salts and the Argon2 hash, so a new vault key is derived — but the stored vault is still encrypted under the old key. The client therefore migrates the vault during the change (`account.js`): it reads the blob from `/vault-data/` and decrypts it with the _old_ session key, then re-encrypts it under the new vault key and POSTs to `/update-data/` **before** swapping the session key (so a failed save leaves the old key working). Shares themselves are unaffected — each uses its own random key carried in its URL fragment, not the vault key.

### JavaScript Module Structure

`crypto.js` must be loaded before `auth-crypto.js`. The single key import/export
implementations live in `crypto.js`: `exportKeyToBase64` and `importKeyFromBase64`
(the latter takes a `usages` argument, defaulting to decrypt-only for the sharing
flow). `auth-crypto.js` reuses both — re-exposing `exportKeyToBase64` unchanged and
wrapping `importKeyFromBase64` to default to `["encrypt", "decrypt"]` for vault keys
— and exposes them on `window.AuthCrypto`. Both modules export their functions to
`window.PasswordCrypto` and `window.AuthCrypto` respectively — no ES module bundler is used.

### Views Pattern

Class-based views that need authentication inherit `SessionAuthRequiredMixin` from `apps/auth/mixins.py`, which provides the redirect-style auth gate plus `get_authenticated_user()` / `handle_missing_user()`. JSON/API endpoints instead use the `require_session_auth_api` (JSON 401) decorator from `apps/auth/utils.py` (the passwd app imports it directly from there). The public signup/signin pages share an `AuthFormView` base (rate-limited dispatch + redirect-if-authenticated + form render). The Base64 helpers for `ServiceData.iv` are the shared `encode_base64()` / `decode_base64()` in `apps/core/encoding.py`.

Most views support both AJAX (`X-Requested-With: XMLHttpRequest` → JSON response) and non-AJAX (HTML render/redirect). The `is_ajax_request()` helper detects this.

Convention: views modules call their app's service layer through the module namespace (`from . import services` → `services.create_share(...)`), not by importing individual function names — it keeps the view/service boundary visible at call sites. Small single-purpose modules (`mixins.py`, `context_processors.py`) may import the one helper they need directly.

Rate limiting uses `django-ratelimit` applied via `@ratelimit` decorator or `@method_decorator`. Limits are defined in each app's `constants.py`.

### URL Routing

The root URLconf (`config/urls.py`) mounts `apps.passwd.urls` at `/` and `apps.auth.urls` at `/auth/`. Key URLs:

- `/` → create share
- `/<uuid>/` → retrieve share
- `/vault/` → authenticated vault
- `/vault-data/` → AJAX endpoint to read the encrypted vault blob (used by the password-change re-encryption)
- `/update-data/` → AJAX endpoint to save encrypted vault data
- `/auth/salts/` → POST `user_id`, returns the public `auth_salt`/`vault_salt` for signin (decoys for unknown ids)
- `/auth/signup/`, `/auth/signin/`, `/auth/signout/`, `/auth/account/`

### Database Notes

SQLite in development. The `ServiceData.iv` field is a `BinaryField` — always use `encode_base64()` / `decode_base64()` from `apps/core/encoding.py` when passing it to/from JavaScript. `SharedPassword.iv` is a `TextField` storing Base64 directly.
