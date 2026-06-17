# Development Guide

This guide covers setting up a local development environment for **proxima·red** without Docker.

For Docker-based development and production deployment, see [deployment.md](./deployment.md).

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Getting started](#getting-started)
- [Running the development server](#running-the-development-server)
- [Running tests](#running-tests)
- [Code style](#code-style)

---

## Prerequisites

- **Python 3.13+**
- **Git**
- **Node.js 20+** (optional, needed for the client-side crypto tests and Prettier formatting)

---

## Getting started

```bash
# Clone the repository
git clone <repository-url> proximared
cd proximared

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install development dependencies
pip install -r requirements/development.txt

# Copy the example environment file
cp .env.example .env           # defaults are fine for local development

python manage.py migrate
```

---

## Running the development server

```bash
python manage.py runserver
```

Application available at <http://localhost:8000/>.

The development settings module (`config.settings.development`) is the default for
`manage.py`. It enables `DEBUG`, uses SQLite, and applies permissive ALLOWED_HOSTS — no
changes to `.env` are needed for local use.

---

## Running tests

Tests use an isolated settings module with in-memory SQLite and a fast password hasher.
Always pass `--settings=config.settings.testing`:

```bash
# Full suite
python manage.py test --settings=config.settings.testing

# Single app
python manage.py test apps.auth --settings=config.settings.testing
python manage.py test apps.passwd --settings=config.settings.testing

# Single test class or method
python manage.py test apps.auth.tests.test_views.SigninViewTests --settings=config.settings.testing
python manage.py test apps.auth.tests.test_views.SigninViewTests.test_signin_post_success --settings=config.settings.testing
```

### Client-side crypto tests

The browser encryption code has its own test suite. It needs **Node.js 20+** (no npm
dependencies — the tests load the real `static/js/{crypto,auth-crypto}.js` against Node's
built-in WebCrypto):

```bash
node --test tests/js/
```

Run these whenever you touch `static/js/crypto.js` or `static/js/auth-crypto.js`.

---

## Code style

**Python** — [Ruff](https://docs.astral.sh/ruff/) (100-character lines, double quotes, E/F/I rules):

```bash
ruff format .   # format
ruff check .    # lint
```

**JavaScript** — [Prettier](https://prettier.io/) (100-character lines, double quotes, semicolons):

```bash
npx prettier --write static/js/
```

Please run both before submitting a pull request.
