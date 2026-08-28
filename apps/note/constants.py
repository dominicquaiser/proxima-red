"""
Constants for the note sharing application.

This module centralizes all magic strings, configuration values, and
constants used throughout the note app to maintain consistency
and make updates easier.

The note tool deliberately does not import from ``apps.passwd``: the two
tools share conventions, not code, so either can diverge (e.g. different
expiry defaults or caps) without touching the other.
"""

from datetime import timedelta
from typing import Final

# Expiry time options mapping for note shares (same semantics as the passwd
# tool's EXPIRY_MAP; duplicated on purpose, see module docstring).
EXPIRY_MAP: Final[dict[str, timedelta]] = {
    "1hour": timedelta(hours=1),
    "1day": timedelta(days=1),
    "1week": timedelta(weeks=1),
    "1month": timedelta(weeks=4),
}

# Default expiry time if none specified or invalid key provided
DEFAULT_EXPIRY: Final[str] = "1day"

# A note is a document, but the create endpoint is anonymous, so the cap must
# stay well under the authenticated 500KB vault blob. 200,000 chars of stored
# content fits the Base64 ciphertext of a 128KiB markdown document (131,072
# plaintext bytes + 16-byte GCM tag Base64-encode to 174,784 chars) with
# headroom, and bounds abuse at ~6MB/hour/IP together with RATE_LIMIT_CREATE.
# Cross-runtime contract: MAX_NOTE_PLAINTEXT_BYTES in
# static/note/js/editor-core.js is derived from this cap and must shrink if
# this shrinks.
MAX_NOTE_CONTENT_LENGTH: Final[int] = 200_000

# Cross-runtime contract: must match GCM_IV_LENGTH_BYTES in static/shared/js/crypto.js.
GCM_IV_LENGTH_BYTES: Final[int] = 12
# AES-GCM uses a 12-byte IV -> 16 Base64 chars; 24 leaves generous headroom
# without accepting absurdly long values.
MAX_IV_LENGTH: Final[int] = 24

# Dummy UUID for URL template generation
DUMMY_NOTE_ID: Final[str] = "00000000-0000-0000-0000-000000000000"

# Rate limiting configuration. Creation is half the passwd tool's 60/h: note
# payloads are up to 4x larger, so the byte budget per IP stays comparable.
RATE_LIMIT_CREATE: Final[str] = "30/h"  # 30 notes per hour per IP
RATE_LIMIT_RETRIEVE: Final[str] = "120/h"  # 120 retrievals per hour per IP

# ── Note vault (authenticated) ─────────────────────────────────────────────

# A vault note is the same kind of document as a shared note, so it shares the
# derivation of MAX_NOTE_CONTENT_LENGTH (Base64 ciphertext of a 128KiB
# markdown document with headroom). Cross-runtime contract:
# MAX_NOTE_PLAINTEXT_BYTES in static/note/js/editor-core.js.
MAX_VAULT_NOTE_CONTENT_LENGTH: Final[int] = 200_000

# The encrypted vault index (folder tree + note names) is small JSON; this
# mirrors the passwd tool's 500KB vault blob cap and is far above any
# realistic index size, so hitting it means a client bug or abuse.
MAX_VAULT_INDEX_LENGTH: Final[int] = 500_000

# Per-user row quota: bounds worst-case storage at ~40MB of ciphertext per
# account (200 x 200,000 chars) while being far above realistic use.
MAX_VAULT_NOTES_PER_USER: Final[int] = 200

# How long a note stays in the vault's Trash before the expiry sweep deletes
# it for good. Single source of truth: the vault page hands this to the client
# so the UI cannot drift from what the server actually enforces.
VAULT_TRASH_RETENTION_DAYS: Final[int] = 7

# Vault rate limits are per-IP like the anonymous ones. Reads are generous
# (the vault UI lists + fetches notes on load); writes and the password-change
# migration are tighter because they are user-initiated one-at-a-time actions.
RATE_LIMIT_VAULT: Final[str] = "100/h"  # vault page views
RATE_LIMIT_VAULT_READ: Final[str] = "120/m"  # index/note reads
RATE_LIMIT_VAULT_WRITE: Final[str] = "30/m"  # index/note writes + deletes
# Sized against the worst case rather than a typical one: a full vault (200
# notes at the 200,000-char cap) re-encrypts in ~29 batches, because the
# client's per-POST character budget splits them well before its note count
# does. At 10/m the 11th batch was refused and the password change tore the
# vault in half, so this has to clear the whole migration inside one window.
RATE_LIMIT_VAULT_MIGRATE: Final[str] = "60/m"  # password-change re-encryption

# ── Live notes (editable share links) ──────────────────────────────────────

# A live note is stored as an encrypted Yjs snapshot plus an append-only log
# of encrypted Yjs updates; clients merge (the server can't read anything).
# The snapshot encodes the full CRDT state (the 128KiB plaintext document,
# same editor bound as shared notes, plus Yjs structural overhead), so its
# cap is deliberately larger than MAX_NOTE_CONTENT_LENGTH.
MAX_LIVE_SNAPSHOT_LENGTH: Final[int] = 1_000_000

# One update row is a client's merged flush; its worst case is a full-document
# paste, so it shares the shared-note ciphertext derivation.
MAX_LIVE_UPDATE_LENGTH: Final[int] = 200_000

# Anti-bloat bounds on the pending update tail (rows newer than the snapshot).
# Clients compact long before these (COMPACT_PENDING_THRESHOLD in
# static/note/js/live-sync.js); hitting them returns 409 pending_tail_full,
# which tells the client to write a snapshot first. Together they bound a
# doc's worst-case tail at ~4MB of ciphertext.
MAX_LIVE_PENDING_UPDATES: Final[int] = 512
MAX_LIVE_PENDING_LENGTH: Final[int] = 4_000_000

# Live-note rate limits (per IP). Creation matches note shares. Reads cover
# the sync poll (~2.5s cadence = 24/m per open tab, so 240/m tolerates several
# tabs behind one NAT); writes cover the debounced update flushes while
# typing. Snapshots are rare, large-bodied compactions, kept tight. The JSON
# endpoints return 429 (block=False pattern) so the sync client backs off
# instead of choking on an HTML 403.
RATE_LIMIT_LIVE_CREATE: Final[str] = "30/h"
RATE_LIMIT_LIVE_PAGE: Final[str] = "120/h"
RATE_LIMIT_LIVE_READ: Final[str] = "240/m"
RATE_LIMIT_LIVE_WRITE: Final[str] = "120/m"
RATE_LIMIT_LIVE_SNAPSHOT: Final[str] = "12/m"

# ── Live-note WebSocket transport (apps/note/consumers.py) ─────────────────

# One encrypted y-protocols awareness update (cursor + selection + name/color
# for the clients sharing a doc). Far above any honest payload (a single
# client's state is well under 1KB); the cap exists to bound relay abuse.
MAX_LIVE_AWARENESS_LENGTH: Final[int] = 16_384

# Consumer-side limits, enforced against the default cache (the same store
# django-ratelimit uses, so multi-worker consistent) with the same fail-open
# posture. django-ratelimit itself needs an HttpRequest, which a WebSocket
# scope doesn't have.
RATE_LIMIT_LIVE_WS_CONNECT: Final[int] = 60  # socket opens per minute per IP
MAX_LIVE_WS_PER_NOTE: Final[int] = 32  # concurrent sockets per document

# Per-connection token bucket for inbound frames: a WS_MSG_BURST allowance
# refilling at WS_MSG_RATE/s. Over budget, awareness frames drop silently
# (ephemeral), update frames get a rate_limited error frame, and a persistent
# offender is closed with WS_CLOSE_ABUSE.
WS_MSG_BURST: Final[int] = 30
WS_MSG_RATE: Final[float] = 15.0
WS_ABUSE_STREAK: Final[int] = 120  # consecutive over-budget frames before close

# Close codes (4xxx = application-defined). NOT_FOUND covers unknown and
# expired alike (indistinguishable on purpose, mirroring the HTTP 404) and is
# terminal client-side. ABUSE means the client should not reconnect.
WS_CLOSE_NOT_FOUND: Final[int] = 4404
WS_CLOSE_ABUSE: Final[int] = 4429

# Error-frame codes ({"type": "error", "code": ...}); recoverable conditions
# are frames (the socket stays open), terminal ones are close codes above.
WS_ERROR_INVALID_FRAME: Final[str] = "invalid_frame"
WS_ERROR_UPDATE_TOO_LARGE: Final[str] = "update_too_large"
WS_ERROR_AWARENESS_TOO_LARGE: Final[str] = "awareness_too_large"
WS_ERROR_TAIL_FULL: Final[str] = "pending_tail_full"
WS_ERROR_RATE_LIMITED: Final[str] = "rate_limited"
WS_ERROR_SERVER: Final[str] = "server_error"

# Template paths
TEMPLATE_EDITOR: Final[str] = "note/editor.html"
TEMPLATE_RETRIEVE: Final[str] = "note/retrieve.html"
TEMPLATE_EXPIRED: Final[str] = "note/expired.html"
TEMPLATE_VAULT: Final[str] = "note/vault.html"
TEMPLATE_LIVE: Final[str] = "note/live.html"

# Error messages
ERROR_MISSING_FIELDS: Final[str] = "Missing required fields: note content is required."
ERROR_CREATE_FAILED: Final[str] = "Failed to create note. Please try again."
ERROR_UNEXPECTED: Final[str] = "An unexpected error occurred"
ERROR_INVALID_JSON: Final[str] = "Invalid JSON payload."
ERROR_VAULT_MISSING_FIELDS: Final[str] = (
    "Missing required fields: encrypted content and IV are required."
)
ERROR_USER_NOT_FOUND: Final[str] = "User not found"
ERROR_NOTE_NOT_FOUND: Final[str] = "Note not found"
# Duplicated from apps.auth.constants on purpose (conventions, not code): the
# live-note JSON endpoints answer 429 themselves instead of blocking to an
# HTML 403 like the vault APIs, because the sync client must parse the reply.
ERROR_RATE_LIMITED: Final[str] = "Too many requests. Please try again later."
ERROR_LIVE_MISSING_FIELDS: Final[str] = (
    "Missing required fields: encrypted data and IV are required."
)
ERROR_LIVE_INVALID_SINCE: Final[str] = (
    "Invalid 'since' parameter: a non-negative integer is required."
)
ERROR_LIVE_TAIL_FULL: Final[str] = (
    "Update log is full. Save a compacted snapshot, then retry."
)
ERROR_LIVE_STALE_SNAPSHOT: Final[str] = (
    "A newer snapshot already exists; the compaction was discarded."
)
ERROR_LIVE_COVERS_UNKNOWN: Final[str] = (
    "The snapshot claims to cover updates that do not exist."
)

# Success messages
SUCCESS_DATA_SAVED: Final[str] = "Data saved successfully."

# Logging messages
LOG_CREATE_FAILED: Final[str] = "Failed to create note (%s)"
LOG_EXPIRED_DELETED: Final[str] = "Deleted expired note: %s"
LOG_VAULT_SAVE_FAILED: Final[str] = "Failed to save vault data for user (%s)"
LOG_VAULT_MIGRATE_FAILED: Final[str] = "Failed to migrate vault data for user (%s)"
LOG_LIVE_CREATE_FAILED: Final[str] = "Failed to create live note (%s)"
LOG_LIVE_EXPIRED_DELETED: Final[str] = "Deleted expired live note: %s"
LOG_LIVE_APPEND_FAILED: Final[str] = "Failed to append live note update (%s)"
LOG_LIVE_SNAPSHOT_FAILED: Final[str] = "Failed to save live note snapshot (%s)"
LOG_LIVE_WS_APPEND_FAILED: Final[str] = "Failed to append live note update over WS (%s)"
