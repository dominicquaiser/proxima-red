"""
Custom exceptions for the authentication app.

This module defines custom exception classes for handling specific
error scenarios in the authentication flow.
"""


class UserCreationError(Exception):
    """
    Exception raised when user creation fails after maximum retries.

    This exception is raised when the system cannot generate a unique user_id
    after the maximum number of retry attempts, indicating a potential system
    issue or extremely high collision rate.
    """

    pass
