# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`[note·]` real-time collaboration**: live notes sync over WebSockets (sub-second, coloured flag-caret cursors with Greek-letter names), with HTTP polling as automatic fallback. Undo moved to Y.UndoManager on the live page. Runtime now serves ASGI (gunicorn + uvicorn workers, Django Channels, dedicated `redis-channels` layer).
- **`[note·]` editable share links (live notes)**: "Editable link" share option creates a collaboratively-editable CRDT (Yjs) document merged client-side; server stores an encrypted snapshot + append-only encrypted update log it can't read. Same expiry model as other shares; swept by `delete_expired_notes`.
- **`[note·]` note vault** at `note.…/vault/`: file manager + editor, folder tree, search, rename/move, Trash. Notes + folder structure encrypted client-side under the vault key — server never learns names or content. Password change transparently re-encrypts the note vault alongside the password vault; GDPR export now includes it.
- **Per-tool sign-in destinations**: signin/signup accept a `tool` param so note sign-ins land on the note vault; `/vault/` is host-dispatched.
- **`[note·]` encrypted note sharing** on the `note.` subdomain: markdown editor with live preview, formatting rail, `.md` download. AES-256-GCM by default (fragment key), with a flagged plain-text link option.
- **`NOTE_SITE_URL`** env var, mirroring `PASS_SITE_URL`.
- **`delete_expired_notes`** management command, run every minute alongside `delete_expired`.

### Fixed

- **`[note·]` live-note sync no longer 500s or drops the socket on a rejected payload**: reading `ValidationError.code` in the update/snapshot endpoints and the WebSocket consumer crashed with `AttributeError` whenever the error came from model field validation (oversized, non-Base64, or bad-IV payloads), whose dict form carries no code. Those now answer a JSON 400 / a recoverable `invalid_frame` error frame as intended.
- **`[note·]` a permanently rejected live update no longer retries forever in silence**: the sync client told transient failures (429, 5xx, network) apart from ones the server will always refuse, and retried both every 60s while showing only an "offline" pill. Permanent rejections now halt syncing with a clear message, keeping the outbox and leaving the editor readable, editable and downloadable so work can be rescued.
- **`[note·]` the live editor warns when a note passes the size limit**: the static editors gate on size at share/save time, but a live note has no submit, so nothing checked it until the server refused an update. Crossing the limit (from local typing, a collaborator's edit, or the loaded document) now warns.

- **`[note·]` a password change no longer tears the note vault in half**: the client re-encrypts the vault in batches, but `/vault/migrate/` allowed only 10/min against the ~29 batches a full vault needs, so the 11th was refused mid-flight. Because the change had already rotated `vault_salt`, the old key survived only in that page's memory and the abandoned rows became unrecoverable — and with the index (written last) still under the old key, the whole vault failed to open. The endpoint now answers a parseable JSON 429, the client retries it, batches are larger, and the limit clears a full vault in one window.

- **`[note·]` the note vault's cross-tab key no longer lingers on disk indefinitely**: the key is mirrored into `localStorage` so sibling tabs can reuse it, but that store is origin-scoped, so only a sign-out on the note host itself cleared it — signing out on the main site or the pass subdomain left it behind. It now carries an expiry tied to `SESSION_COOKIE_AGE` (refreshed on use, server-supplied so the two can't drift) and is cleared on any 401 from a vault API.
- **Production requires `SITE_URL`, `PASS_SITE_URL` and `NOTE_SITE_URL`**: `docs/deployment.md` already marked all three prod-required, but an unset one silently fell back to `http://localhost:8000`, and since host dispatch compares the request host against them the affected tool simply vanished — the note editor, `/<uuid>/` retrieves, the vault dispatch and every `/live/` page 404ing, with `robots.txt`/`sitemap.xml` serving the main-site variant everywhere. Deployments now fail fast instead.

### Changed

- Static assets reorganized into per-tool folders (`static/{shared,core,auth,passwd,note}/{css,js}/`).
- Note editor's shared machinery extracted into `editor-core.js` / `share.js`, reused by the public editor and vault.

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

[Unreleased]: https://github.com/dominicquaiser/proxima-red/compare/1.1.0...HEAD
[1.1.0]: https://github.com/dominicquaiser/proxima-red/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/dominicquaiser/proxima-red/releases/tag/1.0.0
