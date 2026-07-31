# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`[note·]` named collaborators on live notes**: owners can restrict an editable note to specific accounts. Doc key is wrapped per-collaborator (ECDH P-256 → HKDF → AES-GCM, client-side) instead of riding the URL; server relays wrapped keys it can't open. Revoking a collaborator rotates the key, re-snapshots, and re-wraps to survivors. Anonymous link notes unchanged.
- **`[note·]` real-time collaboration**: live notes sync over WebSockets (sub-second, coloured flag-caret cursors with Greek-letter names), with HTTP polling as automatic fallback. Undo moved to Y.UndoManager on the live page. Runtime now serves ASGI (gunicorn + uvicorn workers, Django Channels, dedicated `redis-channels` layer).
- **`[note·]` editable share links (live notes)**: "Editable link" share option creates a collaboratively-editable CRDT (Yjs) document merged client-side; server stores an encrypted snapshot + append-only encrypted update log it can't read. Same expiry model as other shares; swept by `delete_expired_notes`.
- **`[note·]` note vault** at `note.…/vault/`: file manager + editor, folder tree, search, rename/move, Trash. Notes + folder structure encrypted client-side under the vault key — server never learns names or content. Password change transparently re-encrypts the note vault alongside the password vault; GDPR export now includes it.
- **Per-tool sign-in destinations**: signin/signup accept a `tool` param so note sign-ins land on the note vault; `/vault/` is host-dispatched.
- **`[note·]` encrypted note sharing** on the `note.` subdomain: markdown editor with live preview, formatting rail, `.md` download. AES-256-GCM by default (fragment key), with a flagged plain-text link option.
- **`NOTE_SITE_URL`** env var, mirroring `PASS_SITE_URL`.
- **`delete_expired_notes`** management command, run every minute alongside `delete_expired`.

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
