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
    SESSION_KEY_AUTHENTICATED,
    SESSION_KEY_USER_ID,
    ERROR_NOT_AUTHENTICATED,
    ERROR_INVALID_SESSION,
    ERROR_RATE_LIMITED,
)


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
    return request.session.get(SESSION_KEY_USER_ID)


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

        user_id = request.session.get(SESSION_KEY_USER_ID)
        if not user_id:
            return json_error(ERROR_INVALID_SESSION, status=401)

        return view_func(request, *args, **kwargs)

    return wrapped_view


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
