"""
Constants for the authentication application.

This module centralizes all magic strings, configuration values, and
constants used throughout the authentication app to maintain consistency
and make updates easier.
"""

from typing import Final

# User ID generation
USER_ID_LENGTH: Final[int] = 8

# Password and salt configuration. These byte lengths are a cross-runtime
# contract with the browser KDF and must stay in lockstep with the JS:
#   SALT_LENGTH_BYTES        <-> KDF_SALT_LENGTH_BYTES (static/auth/js/auth-crypto.js)
#   AUTH_SECRET_LENGTH_BYTES <-> the 256-bit AES_KEY_LENGTH_BITS (static/shared/js/crypto.js)
SALT_LENGTH_BYTES: Final[int] = 32  # 32 bytes = 256 bits
AUTH_SECRET_LENGTH_BYTES: Final[int] = 32  # PBKDF2-derived authentication secret size

# Form validation
ACCOUNT_DELETION_CONFIRMATION_TEXT: Final[str] = "DELETE"

# Rate limiting configuration
RATE_LIMIT_SIGNUP: Final[str] = "5/m"  # 5 signups per minute per IP
RATE_LIMIT_SIGNIN: Final[str] = "10/m"  # 10 signin attempts per minute per IP
RATE_LIMIT_ACCOUNT: Final[str] = "20/m"  # 20 account operations per minute per IP

# Session keys
SESSION_KEY_USER_ID: Final[str] = "user_id"
SESSION_KEY_AUTHENTICATED: Final[str] = "authenticated"

# Vault destinations the signin flow may redirect to, selected by the vetted
# ``tool`` request parameter (see ``views.vault_url``). Auth is canonical on
# the main site, so each tool's signin links carry its own tool key; anything
# not in this allowlist falls back to the default.
VAULT_TOOL_PASS: Final[str] = "pass"
VAULT_TOOL_NOTE: Final[str] = "note"
VAULT_TOOLS: Final[tuple[str, ...]] = (VAULT_TOOL_PASS, VAULT_TOOL_NOTE)
DEFAULT_VAULT_TOOL: Final[str] = VAULT_TOOL_PASS

# Template paths
TEMPLATE_SIGNUP: Final[str] = "auth/signup.html"
TEMPLATE_SIGNIN: Final[str] = "auth/signin.html"
TEMPLATE_ACCOUNT: Final[str] = "auth/account.html"

# Error messages
ERROR_INVALID_CREDENTIALS: Final[str] = (
    "The User ID or password you entered is incorrect."
)
ERROR_INCORRECT_PASSWORD: Final[str] = "Incorrect current password."
ERROR_INCORRECT_PASSWORD_DELETION: Final[str] = "Incorrect password."
ERROR_INVALID_USER_ID: Final[str] = "User ID must be exactly 8 digits."
ERROR_CONFIRMATION_TEXT: Final[str] = (
    f"You must type {ACCOUNT_DELETION_CONFIRMATION_TEXT} to confirm account removal."
)
ERROR_UNEXPECTED: Final[str] = "An unexpected error occurred. Please try again."
ERROR_RATE_LIMITED: Final[str] = (
    "Too many attempts. Please wait a minute and try again."
)
ERROR_USER_CREATION_FAILED: Final[str] = (
    "Unable to create your account at this time. Please try again in a few moments."
)
ERROR_SESSION_EXPIRED: Final[str] = "Your session has expired. Please sign in again."
ERROR_ACCOUNT_DELETION_FAILED: Final[str] = (
    "Unable to delete your account right now. Please try again later."
)
ERROR_NOT_AUTHENTICATED: Final[str] = "Not authenticated"
ERROR_INVALID_SESSION: Final[str] = "Invalid session"

# Success messages
SUCCESS_ACCOUNT_CREATED: Final[str] = "Account created! Your User ID is: {user_id}"
SUCCESS_USER_CREATED: Final[str] = "User account created successfully!"
SUCCESS_SIGNIN: Final[str] = "Signed in successfully!"
SUCCESS_SIGNOUT: Final[str] = "You have been signed out successfully."
SUCCESS_PASSWORD_CHANGED: Final[str] = "Password updated successfully."
SUCCESS_ACCOUNT_DELETED: Final[str] = (
    "Your account has been deleted. We hope to see you again."
)
SUCCESS_PLEASE_SIGNIN: Final[str] = "Please sign in to manage your account."

# Logging messages
LOG_INTEGRITY_ERROR: Final[str] = (
    "IntegrityError on user creation, attempt {attempt}. Retrying."
)
LOG_USER_CREATION_FAILED: Final[str] = (
    "Could not create user after multiple retries due to IntegrityError."
)
LOG_SESSION_MISSING_USER: Final[str] = "Session references missing user %s"
LOG_ACCOUNT_DELETE_ERROR: Final[str] = "Failed to delete account %s (%s)"
LOG_SIGNIN_ERROR: Final[str] = "Unexpected error in SigninView (%s)"
LOG_SIGNUP_ERROR: Final[str] = "Unexpected error in SignupView (%s)"

# Retry configuration
MAX_USER_CREATION_RETRIES: Final[int] = 5
