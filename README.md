<p align="center">
  <img src="./static/icons/proxima-red-wordmark.svg" alt="proxima·red" width="320" />
</p>
<p align="center">
  <a href="./LICENSE.md"><img src="https://img.shields.io/badge/license-AGPL--3.0-red.svg" alt="License: AGPL-3.0" /></a>
  <img src="https://img.shields.io/github/v/release/dominicquaiser/proxima-red?sort=semver" alt="GitHub release (latest SemVer)" />
  <img src="https://img.shields.io/badge/python-3.13-blue.svg" alt="Python 3.13" />
  <img src="https://img.shields.io/badge/django-5.2-green.svg" alt="Django 5.2" />
</p>

---

**[proxima·red](https://proxima.red/)** is a small collection of open-source web tools for secure sharing. The first tool, **[pass·]**, is a zero-knowledge password and secret sharer. No account required. No email. No tracking.

---

## How it works

Encryption and decryption happen entirely in your browser using the Web Crypto API. The server stores only ciphertext — it never sees a key, and it never sees your data in plaintext.

1. Your browser generates a random AES-256 key
2. Your secret is encrypted locally before anything is sent
3. The server receives and stores only the ciphertext
4. The shareable link carries the key in its URL fragment (`#…`) — fragments are never sent in HTTP requests
5. The recipient's browser fetches the ciphertext and decrypts it locally using the key from the fragment

Even a full database compromise yields nothing readable. There is no key to steal.

## Features

**Anonymous sharing — no account needed**

- Paste a password, API key, PGP key, SSH key, or any other secret
- Optional encrypted title
- Expiry: 60 minutes · 24 hours · 7 days · 4 weeks
- Share a single-use link; the secret is gone when it expires

**Authenticated vault — optional, no email required**

- Sign up with just a password; you receive a randomly generated 8-digit ID
- Your vault data is encrypted client-side using a key derived from your password via PBKDF2-SHA256
- The server holds ciphertext only — a forgotten password means data is unrecoverable, by design
- Manage and search your shares across sessions

---

## Tech stack

| Layer            | Technology                                                          |
| ---------------- | ------------------------------------------------------------------- |
| Backend          | Python 3.13, Django 5.2                                             |
| Crypto           | Web Crypto API (AES-256-GCM, PBKDF2-SHA256)                         |
| Password hashing | Argon2 (primary), bcrypt (fallback) via Django's `PASSWORD_HASHERS` |
| Database         | PostgreSQL (production) · SQLite (development)                      |
| Cache            | Redis (rate-limit counters in production)                           |
| App server       | Gunicorn                                                            |
| Reverse proxy    | nginx + Let's Encrypt (certbot)                                     |
| Frontend         | Vanilla JS · no framework · no bundler                              |
| Container        | Docker Compose                                                      |

---

## Self-hosting

The stack runs on Docker Compose. Full instructions are in [docs/deployment.md](./docs/deployment.md). The short version:

**Development**

```bash
git clone https://github.com/dominicquaiser/proxima-red proxima-red
cd proxima-red
cp .env.example .env
docker compose up --build
```

Application at <http://localhost:8000/>.

**Production**

Requires a domain, a server with ports 80 and 443 open, and Docker Engine 24+. TLS is handled automatically via Let's Encrypt.

```bash
cp .env.example .env
# edit .env:  set SECRET_KEY, ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS, DATABASE_URL, POSTGRES_PASSWORD, DOMAIN, CERTBOT_EMAIL
./deployment/scripts/init-letsencrypt.sh
make up
```

See [docs/deployment.md](./docs/deployment.md) for the full configuration reference, backup procedures, and operations guide.

---

## Development

Without Docker:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements/development.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver
```

See [docs/development.md](./docs/development.md) for the full setup guide, test commands, and code style tooling (Ruff + Prettier).

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](./CONTRIBUTING.md) first.

For security issues, do not open a public issue. See [SECURITY.md](./SECURITY.md).

---

## License

Source code is licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](./LICENSE.md).

The AGPL was chosen deliberately: anyone who modifies and deploys proxima·red over a network must publish their source changes under the same terms. The proxima·red name and visual identity are not covered by this license. Forks must use a different name. See [NOTICE.md](./NOTICE.md) for details.

---

## Contact

Questions or support: [signal@proxima.red](mailto:signal@proxima.red)

Security reports: [SECURITY.md](./SECURITY.md)
