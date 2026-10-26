"""
Authentication-specific view helpers.

These encode the session-auth contract: reading the authenticated user's id
from the session, gating API views with a JSON 401, and turning a rate-limit
block into an on-brand response. Generic JSON/AJAX/form helpers (with no auth
dependency) live in ``apps.core.http``.
"""

from functools import wraps
from typing import Callable

from django.contrib import messages
from django.http import HttpRequest, HttpResponse

from apps.core.http import ajax_or_html, flash_and_redirect, json_error

from .constants import (
    ERROR_INVALID_SESSION,
    ERROR_NOT_AUTHENTICATED,
    ERROR_RATE_LIMITED,
    SESSION_KEY_AUTHENTICATED,
    SESSION_KEY_CREDENTIAL_VERSION,
    SESSION_KEY_USER_ID,
)
from .models import User
from .vault_sessions import access_state, credential_version, identity


# Request attribute caching the session's ``User`` so the auth gates and the
# view behind them share one lookup per request.
_SESSION_USER_ATTR = "_proxima_session_user"


def _session_user(request: HttpRequest) -> User | None:
    """Return the ``User`` the session names, querying at most once per request."""
    user_id = request.session.get(SESSION_KEY_USER_ID)
    user = getattr(request, _SESSION_USER_ATTR, None)
    if user is None or user.user_id != user_id:
        user = User.objects.filter(user_id=user_id).first()
        setattr(request, _SESSION_USER_ATTR, user)
    return user


def get_authenticated_user_id(request: HttpRequest) -> str | None:
    """
    Get the authenticated user's ID from the session.

    Args:
        request: The Django request object

    Returns:
        User ID string if authenticated, None otherwise
    """
    if not request.session.get(SESSION_KEY_AUTHENTICATED):
        return None
    version = request.session.get(SESSION_KEY_CREDENTIAL_VERSION)
    if version:
        user = _session_user(request)
        if not user or version != credential_version(user):
            request.session.flush()
            return None
    return request.session.get(SESSION_KEY_USER_ID)


def get_authenticated_user(request: HttpRequest) -> User | None:
    """Return the authenticated session's ``User`` (``None`` when unresolved)."""
    if not get_authenticated_user_id(request):
        return None
    return _session_user(request)


def require_session_auth_api(view_func: Callable) -> Callable:
    """
    Decorator to require session-based authentication for API views.

    Returns JSON error responses instead of redirects, suitable for AJAX/API
    endpoints. (The redirect-style gate for HTML pages is the
    ``SessionAuthRequiredMixin`` in ``apps/auth/mixins.py``.)

    Args:
        view_func: The view function to decorate

    Returns:
        Decorated function that enforces authentication for API calls

    Example:
        @require_session_auth_api
        def my_api_view(request):
            # API logic here
            pass
    """

    @wraps(view_func)
    def wrapped_view(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not request.session.get(SESSION_KEY_AUTHENTICATED):
            return json_error(ERROR_NOT_AUTHENTICATED, status=401)

        user_id = get_authenticated_user_id(request)
        if not user_id:
            return json_error(ERROR_INVALID_SESSION, status=401)

        return view_func(request, *args, **kwargs)

    return wrapped_view


def require_tool_auth_api(tool):
    """Check a vault grant on every origin, including account/export routes."""

    def decorate(view_func):
        @require_session_auth_api
        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            user = get_authenticated_user(request)
            if not user:
                return json_error(ERROR_INVALID_SESSION, status=401)
            expected = request.headers.get("X-Vault-Identity")
            if expected and expected != identity(user):
                return json_error(
                    "Your account or password changed. Reload to continue.",
                    status=409,
                    code="vault_identity_changed",
                )
            if not access_state(request, user, tool)["unlocked"]:
                return json_error(
                    "Enter your password to unlock this vault.",
                    status=423,
                    code="vault_locked",
                    tool=tool,
                )
            response = view_func(request, *args, **kwargs)
            response["Cache-Control"] = "no-store"
            return response

        return wrapped

    return decorate


def ratelimited_response(request: HttpRequest, *, redirect_to: str) -> HttpResponse:
    """
    Build the response for a request blocked by ``django-ratelimit``.

    The rate-limit decorators run with ``block=False`` so views can return a
    helpful, on-brand response instead of Django's generic 403 page. Call this
    when ``request.limited`` is set.

    AJAX callers (the JS forms) get a JSON 429 so ``window.Http.postForm`` can
    parse it and surface the message; non-AJAX callers get a flash message and a
    redirect to a GET page.

    Args:
        request: The Django request object.
        redirect_to: URL name or path to redirect non-AJAX requests to.

    Returns:
        A JSON 429 response (AJAX) or a redirect carrying a flash message.
    """
    return ajax_or_html(
        request,
        ajax=lambda: json_error(ERROR_RATE_LIMITED, status=429),
        html=lambda: flash_and_redirect(
            request, ERROR_RATE_LIMITED, redirect_to, level=messages.error
        ),
    )
