# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`[note·]` — encrypted note sharing** on the new `note.` subdomain: a full-bleed markdown editor with live preview, a formatting tool rail, and `.md` download. Notes are encrypted client-side with AES-256-GCM by default (the key rides in the URL fragment, exactly like password shares); a **plain-text link** option is also offered for non-sensitive notes and is clearly flagged as server-readable. The retrieve page decrypts and renders markdown entirely in the browser. Editable/real-time links are reserved for a later CRDT-based milestone.
- **`NOTE_SITE_URL`** environment variable for the note tool's origin, mirroring `PASS_SITE_URL` (host-based dispatch, robots/sitemap, CSP `form-action`).
- **`delete_expired_notes`** management command, run every minute by the `cron` service alongside `delete_expired`.

### Changed

- **Static assets reorganized into per-tool folders** (`static/{shared,core,auth,passwd,note}/{css,js}/`) so each tool owns its CSS/JS. Site-wide assets (`icons`, `fonts`, `images`) are unchanged.

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
