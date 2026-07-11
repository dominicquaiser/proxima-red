"""
Views for the note sharing application.

Creating and retrieving shared markdown notes. All cryptographic operations
occur client-side; the server only stores what the browser sends. Encrypted
notes (the default) are opaque ciphertext; plain-text notes are an explicit
user choice recorded in ``is_encrypted``.

Requests reach these views through the host dispatchers in ``apps.core.views``
(``index`` and ``retrieve_dispatch``): the note tool shares the ``/`` and
``/<uuid>/`` URL space with the passwd tool, split by request host.
"""

import logging

from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import View

from django_ratelimit.decorators import ratelimit

from apps.auth.models import User
from apps.auth.services import get_user_by_id
from apps.auth.utils import get_authenticated_user_id
from apps.core.http import (
    ajax_or_html,
    client_ip_key,
    exception_type,
    json_error,
    json_ok,
)

from . import services
from .constants import (
    DEFAULT_EXPIRY,
    DUMMY_NOTE_ID,
    ERROR_CREATE_FAILED,
    ERROR_MISSING_FIELDS,
    LOG_CREATE_FAILED,
    LOG_EXPIRED_DELETED,
    RATE_LIMIT_CREATE,
    RATE_LIMIT_RETRIEVE,
    TEMPLATE_EDITOR,
    TEMPLATE_EXPIRED,
    TEMPLATE_RETRIEVE,
)
from .models import SharedNote

logger = logging.getLogger(__name__)


def _validation_error_message(error: ValidationError) -> str:
    """Flatten a Django validation error into a user-facing message.

    Args:
        error (ValidationError): Error containing one or more messages.

    Returns:
        str: Messages joined with spaces in their original order.
    """
    return " ".join(str(message) for message in error.messages)


def _create_note_payload(request: HttpRequest) -> dict:
    """Extract the note form payload from the POST body.

    ``is_encrypted`` arrives as ``"1"``/``"0"`` from the editor; anything but
    an explicit ``"0"`` is treated as encrypted, so a buggy client fails
    closed (toward the zero-knowledge default).

    Args:
        request (HttpRequest): Incoming note creation request.

    Returns:
        dict[str, str | bool]: Normalized service-layer arguments.
    """
    return {
        "content": request.POST.get("content", "").strip(),
        "iv": request.POST.get("iv", "").strip(),
        "is_encrypted": request.POST.get("is_encrypted", "1") != "0",
        "expiry_key": request.POST.get("expiry_time", DEFAULT_EXPIRY),
    }


def _authenticated_note_owner(request: HttpRequest) -> User | None:
    """Resolve the optional owner of a newly created note.

    Args:
        request (HttpRequest): Request whose session may identify a user.

    Returns:
        User | None: Authenticated user, or ``None`` for an anonymous request
            or a session whose user no longer exists.
    """
    user_id = get_authenticated_user_id(request)
    return get_user_by_id(user_id) if user_id else None


def _editor_context(request: HttpRequest, **extra) -> dict:
    """Build the editor context used for client-side share URL construction.

    Args:
        request (HttpRequest): Request used to construct an absolute URL.
        **extra (Any): Additional template context values.

    Returns:
        dict[str, Any]: Editor template context.
    """
    retrieval_url_base = request.build_absolute_uri(
        reverse("note:retrieve", args=[DUMMY_NOTE_ID])
    )
    return {
        "retrieval_url_base": retrieval_url_base,
        "dummy_note_id": DUMMY_NOTE_ID,
        **extra,
    }


def _create_error_response(
    request: HttpRequest, message: str, *, status: int = 400
) -> HttpResponse:
    """Build an editor error response for AJAX or HTML callers.

    Args:
        request (HttpRequest): Request used to select the response format.
        message (str): User-facing error message.
        status (int): HTTP status code for the response.

    Returns:
        HttpResponse: JSON for AJAX requests or rendered editor HTML otherwise.
    """
    return ajax_or_html(
        request,
        ajax=lambda: json_error(message, status=status),
        html=lambda: render(
            request,
            TEMPLATE_EDITOR,
            _editor_context(request, error=message),
            status=status,
        ),
    )


def _note_json_response(note: SharedNote) -> JsonResponse:
    """Build the AJAX success response for a newly created note.

    Args:
        note (SharedNote): Persisted note to serialize.

    Returns:
        JsonResponse: Public note metadata required by the editor.
    """
    return json_ok(
        note_id=str(note.id),
        is_encrypted=note.is_encrypted,
        expires_at=note.expires_at.isoformat(),
        created_at=note.created_at.isoformat(),
    )


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_CREATE, method="POST", block=True),
    name="dispatch",
)
class CreateNoteView(View):
    """Create a new shared note.

    Handles GET (display the markdown editor) and POST (create a note).
    The editor is fetch-driven, so POST is normally AJAX and answers JSON;
    the non-AJAX branch re-renders the editor for robustness.

    POST requests are limited to ``RATE_LIMIT_CREATE`` per client IP.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the Markdown editor.

        Args:
            request (HttpRequest): Incoming GET request.

        Returns:
            HttpResponse: Rendered editor page.
        """
        return render(request, TEMPLATE_EDITOR, _editor_context(request))

    def post(self, request: HttpRequest) -> HttpResponse:
        """Validate and persist a note creation request.

        Args:
            request (HttpRequest): Incoming POST request containing note data.

        Returns:
            HttpResponse: JSON metadata for AJAX callers, rendered editor HTML
            for form callers, or an error in the matching response format.
        """
        payload = _create_note_payload(request)

        if not payload["content"]:
            return _create_error_response(request, ERROR_MISSING_FIELDS)

        try:
            note = services.create_note(
                **payload,
                created_by=_authenticated_note_owner(request),
            )
        except ValidationError as e:
            return _create_error_response(request, _validation_error_message(e))
        except Exception as e:
            logger.error(LOG_CREATE_FAILED, exception_type(e))
            return _create_error_response(request, ERROR_CREATE_FAILED, status=500)

        return ajax_or_html(
            request,
            ajax=lambda: _note_json_response(note),
            html=lambda: render(
                request, TEMPLATE_EDITOR, _editor_context(request, created_note=note)
            ),
        )


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_RETRIEVE, method="GET", block=True),
    name="dispatch",
)
class RetrieveNoteView(View):
    """Retrieve and display a shared note if valid and not expired.

    Passes the stored body to the template for client-side handling: encrypted
    notes are decrypted in the browser with the key from the URL fragment
    (which never reaches the server); markdown is always rendered client-side.

    GET requests are limited to ``RATE_LIMIT_RETRIEVE`` per client IP. Expired
    notes are deleted on access, while active notes have their access counter
    incremented atomically. The server never sees encrypted-note plaintext.
    """

    def get(self, request: HttpRequest, pk: str) -> HttpResponse:
        """Render an active note or the expiry page.

        Args:
            request (HttpRequest): Incoming GET request.
            pk (str | uuid.UUID): UUID of the requested note.

        Returns:
            HttpResponse: Retrieval page for an active note or expiry page for
            an expired note.

        Raises:
            Http404: If no note exists for ``pk``.
        """
        note = get_object_or_404(SharedNote, pk=pk)

        # Delete just this note if it has expired. The global sweep of all
        # expired rows is handled out-of-band by the `delete_expired_notes`
        # cron job, so it doesn't belong on this hot path; deleting the
        # specific note that was opened after expiry removes it immediately,
        # regardless of cron timing.
        if note.is_expired():
            note.delete()
            logger.info(LOG_EXPIRED_DELETED, pk)
            return render(request, TEMPLATE_EXPIRED)

        # Increment access count atomically to avoid lost updates under concurrency
        services.register_note_access(pk)

        # Note data for the client: decrypted (if needed) and rendered in the
        # browser; the page HTML itself never contains the plaintext of an
        # encrypted note.
        note_data_for_js = {
            "content": note.content,
            "iv": note.iv,
            "is_encrypted": note.is_encrypted,
            "expires_at": note.expires_at.isoformat(),
        }

        context = {"note": note, "note_data_json": note_data_for_js}
        return render(request, TEMPLATE_RETRIEVE, context)
