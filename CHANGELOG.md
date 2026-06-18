# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
