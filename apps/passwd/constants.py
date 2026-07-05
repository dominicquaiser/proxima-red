"""
Constants for the password sharing application.

This module centralizes all magic strings, configuration values, and
constants used throughout the passwd app to maintain consistency
and make updates easier.
"""

from datetime import timedelta
from typing import Final

# Expiry time options mapping for password shares
EXPIRY_MAP: Final[dict[str, timedelta]] = {
    "1hour": timedelta(hours=1),
    "1day": timedelta(days=1),
    "1week": timedelta(weeks=1),
    "1month": timedelta(weeks=4),
}

# Default expiry time if none specified or invalid key provided
DEFAULT_EXPIRY: Final[str] = "1day"

# Maximum field lengths for security and database constraints
MAX_ENCRYPTED_DATA_LENGTH: Final[int] = 50000  # ~50KB cap for a single anonymous share
# The authenticated vault is one encrypted blob holding ALL of a user's shares
# (share id + per-share key + title/tags), so it gets a far larger cap than the
# one-secret anonymous share flow. ~500KB of Base64 ciphertext.
MAX_VAULT_DATA_LENGTH: Final[int] = 500000  # ~500KB encrypted vault blob
# Cross-runtime contract: must match GCM_IV_LENGTH_BYTES in static/js/crypto.js.
GCM_IV_LENGTH_BYTES: Final[int] = 12
# AES-GCM uses a 12-byte IV -> 16 Base64 chars; 24 leaves generous headroom
# without accepting absurdly long values.
MAX_IV_LENGTH: Final[int] = 24
MAX_ENCRYPTED_TITLE_LENGTH: Final[int] = (
    4000  # Base64 ciphertext bound for a 500-char title (incl. multibyte)
)

# Dummy UUID for URL template generation
DUMMY_SHARE_ID: Final[str] = "00000000-0000-0000-0000-000000000000"

# Rate limiting configuration
RATE_LIMIT_CREATE: Final[str] = "60/h"  # 60 shares per hour per IP
RATE_LIMIT_RETRIEVE: Final[str] = "120/h"  # 120 retrievals per hour per IP
RATE_LIMIT_UPDATE_DATA: Final[str] = "20/m"  # 20 updates per minute per IP
RATE_LIMIT_DELETE_SHARE: Final[str] = "30/m"  # 30 share deletions per minute per IP
RATE_LIMIT_VAULT: Final[str] = "100/h"  # 100 vault page loads per hour per IP
RATE_LIMIT_EXPORT: Final[str] = "10/h"  # 10 data exports per hour per IP

# Template paths
TEMPLATE_CREATE: Final[str] = "passwd/create.html"
TEMPLATE_SUCCESS: Final[str] = "passwd/success.html"
TEMPLATE_RETRIEVE: Final[str] = "passwd/retrieve.html"
TEMPLATE_EXPIRED: Final[str] = "passwd/expired.html"
TEMPLATE_VAULT: Final[str] = "passwd/vault.html"

# Error messages
ERROR_MISSING_FIELDS: Final[str] = (
    "Missing required fields: encrypted data and IV are required."
)
ERROR_CREATE_FAILED: Final[str] = "Failed to create secure share. Please try again."
ERROR_MISSING_REQUIRED: Final[str] = "Missing required fields"
ERROR_INVALID_IV: Final[str] = "Invalid IV format."
ERROR_INVALID_SHARE_ID: Final[str] = "Invalid share identifier."
ERROR_USER_NOT_FOUND: Final[str] = "User not found"
ERROR_INVALID_JSON: Final[str] = "Invalid JSON data"
ERROR_UNEXPECTED: Final[str] = "An unexpected error occurred"

# Success messages
SUCCESS_DATA_SAVED: Final[str] = "Your data has been saved securely."
SUCCESS_SHARE_DELETED: Final[str] = "The secure share has been revoked."

# Logging messages
LOG_CREATE_FAILED: Final[str] = "Failed to create share (%s)"
LOG_EXPIRED_DELETED: Final[str] = "Deleted expired share: %s"
LOG_UPDATE_DATA: Final[str] = "Updated service data for user %s"
LOG_UPDATE_DATA_ERROR: Final[str] = "Update service data failed (%s)"
LOG_SHARE_DELETED: Final[str] = "Deleted share %s for user %s"
LOG_DELETE_SHARE_ERROR: Final[str] = "Delete share failed (%s)"
