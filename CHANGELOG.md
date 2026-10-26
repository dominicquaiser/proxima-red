# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] — 2026-10-26

Adds a second tool, **`[note·]`**, on the `note.` subdomain alongside `[pass·]`, and moves the server to ASGI. Existing deployments need the steps under *Upgrading*.

### Upgrading

- **New subdomain**: set `NOTE_SITE_URL`, add the note host to `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS`, create its DNS record, and re-run `deployment/scripts/init-letsencrypt.sh` so the certificate covers it (see `docs/deployment.md`).
- **`SITE_URL`, `PASS_SITE_URL` and `NOTE_SITE_URL` are now required in production**. An unset one used to fall back to `http://localhost:8000` and silently 404 that tool; startup now fails instead.
- **ASGI runtime**: the app runs `config.asgi` under gunicorn with uvicorn workers, and needs a second Redis instance, `redis-channels`, for WebSocket fan-out (bundled in `docker-compose.prod.yml`; override with `CHANNEL_REDIS_URL`).
- **Running your own host nginx**: forward the WebSocket upgrade on `/ws/` (see `deployment/nginx/host.conf`). Without it, live notes fall back to polling.
- The `cron` service now also runs `delete_expired_notes` every minute.

### Added

**`[note·]` encrypted markdown notes**

- Markdown editor with live preview, a formatting rail, syntax-highlighted code blocks and `.md` download.
- Share links encrypted with AES-256-GCM, with the key in the URL fragment and the same expiry options as password shares. A plain-text link is available on request and clearly flagged.
- **Editable links (live notes)**: everyone with the link edits the same document in real time, with coloured cursors and name flags. Edits are merged in the browser (Yjs CRDT); the server stores only an encrypted snapshot and update log. Syncs over WebSockets, with HTTP polling as fallback.
- **Note vault** at `note.…/vault/`: folders, search, rename/move, and a Trash the server empties after 7 days. Content, names and folder structure are encrypted under the account's vault key.
- Images hosted elsewhere are never loaded in rendered notes; a labelled placeholder shows instead, so a note's author can't see who reads it.

**Accounts**

- Sign-in and sign-up take a `tool` parameter, so each tool's Sign In lands on its own vault.
- Changing the password also re-encrypts the note vault, and offers a plaintext recovery download if re-encryption fails.
- The GDPR export covers both vaults and every share, note and live note.

**`[pass·]`**

- Deleting a vault entry takes a confirming second click.
- New favicons.

### Changed

- **Vault access**: the account sign-in now lasts seven days, and each vault has its own access window, replacing the single 30-minute idle timeout. The password vault locks 30 minutes after the password was entered, even while in use; the note vault locks after seven days without use. A locked vault reopens with the password in place.
- The password vault no longer embeds its ciphertext in the page; it is fetched only once the vault is unlocked. The unlock modal can't be dismissed and offers to sign out instead.
- The password vault's size cap rose from 50 KB to 500 KB; single shares stay at 50 KB.
- Static assets moved into per-tool folders (`static/{shared,core,auth,passwd,note}/`).

### Fixed

- A rate-limited or otherwise non-JSON response now shows a readable error instead of `Unexpected token '<'`.

## [1.1.0] — 2026-06-21

### Added

- **Cross-subdomain authentication**: the main site (`proxima.red`) is now the canonical auth origin shared across tools, while the vault is served on the `pass.` subdomain. The derived vault key is handed to the vault origin via the URL fragment.
- **In-place vault unlock**: a tab that lands on the vault without a session key can re-verify the password through an unlock modal instead of signing out and back in.
- **Reveal toggle on the share link**: the decryption key in the fragment is masked by default to prevent shoulder-surfing; the copy button always copies the full, working URL.
- Deployment option for hosts that already run their own nginx as the public reverse proxy and TLS terminator, avoiding a port collision with the bundled nginx/certbot.

### Changed

- Copy actions (share links, secrets, vault entries) now confirm via toast notifications instead of inline button flashes, for consistent feedback.

## [1.0.0] — 2026-06-18

### Added

**Anonymous sharing**

- Zero-knowledge password and secret sharing — encryption and decryption happen entirely in the browser using the Web Crypto API (AES-256-GCM)
- Optional encrypted title per share
- Configurable expiry: 60 minutes, 24 hours, 7 days, 4 weeks
- The decryption key is embedded in the URL fragment and never sent to the server

**Authenticated vault**

- Account signup with a password only — no email, no username; a random 8-digit ID is issued
- Vault data encrypted client-side with a key derived from the account password via PBKDF2-SHA256; the server holds ciphertext only
- Encrypted tags on vault entries
- Revoking a vault entry also deletes the corresponding share
- Password change re-encrypts the vault under the new derived key without data loss

**Infrastructure**

- Host-aware landing page at the root
- Docker Compose setup for both development and production (nginx + Let's Encrypt)
- Automated deletion of expired shares via a management command (`delete_expired`)
- Rate limiting on auth and share endpoints

[Unreleased]: https://github.com/dominicquaiser/proxima-red/compare/2.0.0...HEAD
[2.0.0]: https://github.com/dominicquaiser/proxima-red/compare/1.1.0...2.0.0
[1.1.0]: https://github.com/dominicquaiser/proxima-red/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/dominicquaiser/proxima-red/releases/tag/1.0.0
