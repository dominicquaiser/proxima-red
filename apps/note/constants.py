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
# Cross-runtime contract: MAX_NOTE_PLAINTEXT_BYTES in static/note/js/editor.js
# is derived from this cap and must shrink if this shrinks.
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

# Template paths
TEMPLATE_EDITOR: Final[str] = "note/editor.html"
TEMPLATE_RETRIEVE: Final[str] = "note/retrieve.html"
TEMPLATE_EXPIRED: Final[str] = "note/expired.html"

# Error messages
ERROR_MISSING_FIELDS: Final[str] = "Missing required fields: note content is required."
ERROR_CREATE_FAILED: Final[str] = "Failed to create note. Please try again."
ERROR_UNEXPECTED: Final[str] = "An unexpected error occurred"

# Logging messages
LOG_CREATE_FAILED: Final[str] = "Failed to create note (%s)"
LOG_EXPIRED_DELETED: Final[str] = "Deleted expired note: %s"
