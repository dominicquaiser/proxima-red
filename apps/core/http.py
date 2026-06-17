"""
Generic HTTP request/response helpers shared across apps.

These are deliberately free of any auth- or app-specific dependencies, so every
app (auth, passwd, and future apps) can detect AJAX requests and build a
consistent JSON envelope without reaching into ``apps.auth``. Auth-specific
gates live in ``apps.auth.utils`` / ``apps.auth.mixins``.
"""

from collections.abc import Callable

from django.conf import settings
from django.contrib import messages
from django.forms.forms import NON_FIELD_ERRORS, BaseForm
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect

# AJAX detection: jQuery/fetch set this request header on XML HTTP requests.
AJAX_HEADER_NAME = "X-Requested-With"
AJAX_HEADER_VALUE = "XMLHttpRequest"

# Fallback message for get_first_form_error when a form has no specific error.
DEFAULT_FORM_ERROR = "Invalid form data"


def exception_type(error: Exception) -> str:
    """
    Return a non-sensitive exception label for request-path logs.

    Views log the exception *class name* rather than ``str(error)`` because an
    exception message can echo request data; the class name alone is safe.
    """
    return error.__class__.__name__


def get_client_ip(request: HttpRequest) -> str:
    """
    Resolve the real client IP, honouring a trusted reverse-proxy chain.

    ``REMOTE_ADDR`` is the address of whatever opened the connection to the app
    server. In production that is the reverse proxy (nginx), so keying anything
    on ``REMOTE_ADDR`` collapses every external client into one address. When
    ``RATELIMIT_TRUSTED_PROXY_COUNT`` is set, the client IP is read from
    ``X-Forwarded-For`` instead.

    Only the rightmost ``N`` entries of ``X-Forwarded-For`` are trustworthy: each
    trusted proxy appends the address it received the connection from, so a client
    can spoof the leading entries but not the suffix our own proxies add. With
    ``N`` trusted proxies the client IP is the ``N``-th entry counted from the
    right. Falls back to ``REMOTE_ADDR`` when no proxy is trusted or the header is
    absent / shorter than expected.

    Args:
        request: The Django request object.

    Returns:
        The resolved client IP string (may be empty if entirely unavailable).
    """
    trusted = getattr(settings, "RATELIMIT_TRUSTED_PROXY_COUNT", 0)
    if trusted > 0:
        forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(parts) >= trusted:
            return parts[-trusted]
    return request.META.get("REMOTE_ADDR", "")


def client_ip_key(group: str, request: HttpRequest) -> str:
    """
    ``django-ratelimit`` key function that buckets by real client IP.

    Drop-in replacement for the built-in ``key="ip"``, which buckets by
    ``REMOTE_ADDR`` and therefore groups every client behind a reverse proxy into
    a single bucket (making per-IP limits global and trivially abusable for
    lockout). See :func:`get_client_ip` for the proxy-chain handling.
    """
    return get_client_ip(request)


def is_ajax_request(request: HttpRequest) -> bool:
    """
    Check if a request is an AJAX request.

    Args:
        request: The Django request object

    Returns:
        True if the request is AJAX, False otherwise
    """
    return request.headers.get(AJAX_HEADER_NAME) == AJAX_HEADER_VALUE


def ajax_or_html(
    request: HttpRequest,
    *,
    ajax: Callable[[], HttpResponse],
    html: Callable[[], HttpResponse],
) -> HttpResponse:
    """Return the AJAX response factory for XHR requests, otherwise the HTML one."""
    if is_ajax_request(request):
        return ajax()
    return html()


def flash_and_redirect(
    request: HttpRequest, message: str, to: str, *, level=messages.success
) -> HttpResponse:
    """
    Flash a message and redirect - the non-AJAX branch shared by many views.

    ``level`` is a ``django.contrib.messages`` adder (``messages.success`` by
    default, ``messages.error`` for failures). ``to`` is a URL name or path
    handed straight to ``redirect``.
    """
    level(request, message)
    return redirect(to)


def get_first_form_error(form: BaseForm) -> str:
    """
    Extract the first error message from a Django form.

    Args:
        form: Django form with errors

    Returns:
        First error message string, or generic message if no errors
    """
    if form.errors:
        return next(iter(form.errors.values()))[0]
    return DEFAULT_FORM_ERROR


def get_form_errors(form: BaseForm) -> dict[str, list[str]]:
    """
    Return Django form errors as ``{field: [messages...]}`` for AJAX clients.

    Django stores non-field errors under ``__all__`` internally. The JSON
    contract exposes those as ``non_field_errors`` because that is the key the
    frontend expects.
    """
    errors = {}
    # ``field_messages`` is named to avoid shadowing the module-level
    # ``django.contrib.messages`` import.
    for field_name, field_messages in form.errors.items():
        key = "non_field_errors" if field_name == NON_FIELD_ERRORS else field_name
        errors[key] = [str(message) for message in field_messages]
    return errors


def json_ok(message: str | None = None, *, status: int = 200, **data) -> JsonResponse:
    """
    Build a standard success JSON response: ``{"success": True, ...}``.

    Args:
        message: Optional human-readable message included under ``message``.
        status: HTTP status code (default 200).
        **data: Extra fields merged into the response body.

    Returns:
        JsonResponse with ``success=True`` plus any provided fields.
    """
    payload = {"success": True}
    if message is not None:
        payload["message"] = message
    payload.update(data)
    return JsonResponse(payload, status=status)


def json_error(error: str, *, status: int = 400, **data) -> JsonResponse:
    """
    Build a standard error JSON response: ``{"success": False, "error": ...}``.

    Args:
        error: Human-readable error message.
        status: HTTP status code (default 400).
        **data: Extra fields merged into the response body (mirrors
            :func:`json_ok`).

    Returns:
        JsonResponse with ``success=False``, the given error, plus any
        provided fields.
    """
    payload = {"success": False, "error": error}
    payload.update(data)
    return JsonResponse(payload, status=status)


def json_form_error(form: BaseForm, *, status: int = 400) -> JsonResponse:
    """
    Build an error JSON response from a form's first validation error.

    Convenience wrapper combining :func:`get_first_form_error` and
    :func:`json_error`, since views repeat this on the AJAX invalid-form path.

    Args:
        form: Django form with errors.
        status: HTTP status code (default 400).

    Returns:
        JsonResponse with ``success=False``, the first form error under
        ``error``, and all field errors under ``errors``.
    """
    return json_error(
        get_first_form_error(form),
        status=status,
        errors=get_form_errors(form),
    )
