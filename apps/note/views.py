"""
Views for the note sharing application.

All cryptographic operations occur client-side; the server only stores what
the browser sends. Encrypted notes (the default) are opaque ciphertext;
plain-text notes are an explicit user choice recorded in ``is_encrypted``.

The module covers three surfaces, in this order:

1. shared notes: the public markdown editor and the retrieve page;
2. the note vault: authenticated JSON APIs over the user's encrypted notes
   and index;
3. live notes: the anonymous JSON sync endpoints and page for editable share
   links.

Requests reach the shared-note views through the host dispatchers in
``apps.core.views`` (``index`` and ``retrieve_dispatch``): the note tool
shares the ``/`` and ``/<uuid>/`` URL space with the passwd tool, split by
request host. The vault and live endpoints use collision-free literal paths
and answer on every host instead (``LiveNotePageView`` host-gates itself).
"""

import json
import logging

from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import View

from django_ratelimit.decorators import ratelimit

from apps.auth.constants import SESSION_KEY_USER_ID
from apps.auth.mixins import SessionAuthRequiredMixin
from apps.auth.models import User
from apps.auth.services import get_user_by_id
from apps.auth.utils import get_authenticated_user_id, require_session_auth_api
from apps.core.hosts import is_note_site
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
    ERROR_INVALID_JSON,
    ERROR_LIVE_COVERS_UNKNOWN,
    ERROR_LIVE_INVALID_SINCE,
    ERROR_LIVE_MISSING_FIELDS,
    ERROR_LIVE_STALE_SNAPSHOT,
    ERROR_LIVE_TAIL_FULL,
    ERROR_MISSING_FIELDS,
    ERROR_NOTE_NOT_FOUND,
    ERROR_RATE_LIMITED,
    ERROR_UNEXPECTED,
    ERROR_USER_NOT_FOUND,
    ERROR_VAULT_MISSING_FIELDS,
    LOG_CREATE_FAILED,
    LOG_EXPIRED_DELETED,
    LOG_LIVE_APPEND_FAILED,
    LOG_LIVE_CREATE_FAILED,
    LOG_LIVE_EXPIRED_DELETED,
    LOG_LIVE_SNAPSHOT_FAILED,
    LOG_VAULT_MIGRATE_FAILED,
    LOG_VAULT_SAVE_FAILED,
    MAX_VAULT_NOTES_PER_USER,
    RATE_LIMIT_CREATE,
    RATE_LIMIT_LIVE_CREATE,
    RATE_LIMIT_LIVE_PAGE,
    RATE_LIMIT_LIVE_READ,
    RATE_LIMIT_LIVE_SNAPSHOT,
    RATE_LIMIT_LIVE_WRITE,
    RATE_LIMIT_RETRIEVE,
    RATE_LIMIT_VAULT,
    RATE_LIMIT_VAULT_MIGRATE,
    RATE_LIMIT_VAULT_READ,
    RATE_LIMIT_VAULT_WRITE,
    SUCCESS_DATA_SAVED,
    TEMPLATE_EDITOR,
    TEMPLATE_EXPIRED,
    TEMPLATE_LIVE,
    TEMPLATE_RETRIEVE,
    TEMPLATE_VAULT,
    VAULT_TRASH_RETENTION_DAYS,
)
from .models import LiveNote, SharedNote

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
    live_url_base = request.build_absolute_uri(
        reverse("note:live", args=[DUMMY_NOTE_ID])
    )
    return {
        "retrieval_url_base": retrieval_url_base,
        "live_url_base": live_url_base,
        "dummy_note_id": DUMMY_NOTE_ID,
        # Handed to the vault UI so its Trash copy cannot drift from the window
        # the sweep actually enforces.
        "trash_retention_days": VAULT_TRASH_RETENTION_DAYS,
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


# --- Note vault (authenticated) ---
#
# The JSON helpers below replicate the shapes of their passwd counterparts
# (``_session_user_or_error``, ``_decode_vault_payload``) rather than importing
# them: the tools share conventions, not code (see ``apps.note.constants``).


def _vault_session_user_or_error(
    request: HttpRequest,
) -> tuple[User | None, JsonResponse | None]:
    """Resolve the current session user for the vault JSON APIs.

    Args:
        request (HttpRequest): Authenticated request (already gated by
            ``require_session_auth_api``).

    Returns:
        tuple[User | None, JsonResponse | None]: The user, or a JSON 404 when
        the session references a deleted account.
    """
    user = get_user_by_id(request.session.get(SESSION_KEY_USER_ID))
    if not user:
        return None, json_error(ERROR_USER_NOT_FOUND, status=404)
    return user, None


def _json_body_or_error(
    request: HttpRequest,
) -> tuple[dict | None, JsonResponse | None]:
    """Parse the request body as a JSON object.

    Args:
        request (HttpRequest): Request whose body should be JSON.

    Returns:
        tuple[dict | None, JsonResponse | None]: The parsed dict, or a JSON
        400 when the body is not valid JSON or not an object.
    """
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return None, json_error(ERROR_INVALID_JSON)
    if not isinstance(data, dict):
        return None, json_error(ERROR_INVALID_JSON)
    return data, None


def _string_fields_or_error(
    data: dict, *names: str, missing_message: str = ERROR_VAULT_MISSING_FIELDS
) -> tuple[list[str], JsonResponse | None]:
    """Extract required non-empty string fields from a JSON payload.

    Args:
        data (dict): Parsed JSON payload.
        *names (str): Keys that must each hold a non-blank string.
        missing_message (str): Error message for an absent or blank field
            (the vault wording by default; the live endpoints pass their own).

    Returns:
        tuple[list[str], JsonResponse | None]: The stripped values in ``names``
        order, or a JSON 400 naming the first problem.
    """
    values = []
    for name in names:
        value = data.get(name)
        if value is None:
            return [], json_error(missing_message)
        if not isinstance(value, str):
            return [], json_error(ERROR_INVALID_JSON)
        if not value.strip():
            return [], json_error(missing_message)
        values.append(value.strip())
    return values, None


def _rate_limited_json(request: HttpRequest) -> JsonResponse | None:
    """Answer a rate-limited request with a JSON 429.

    The counterpart of ``apps.auth.utils.ratelimited_response`` (conventions,
    not code): JSON-only, no redirect branch. Used by every endpoint whose
    client has to *parse* the refusal rather than merely notice it: the live
    sync loop, which backs off, and the password-change migration, which
    retries the batch. The ``block=True`` path those would otherwise take
    hands back an HTML 403 that a fetch caller cannot tell apart from a
    rejected CSRF token.

    Args:
        request (HttpRequest): Request annotated by a ``block=False`` limiter.

    Returns:
        JsonResponse | None: A JSON 429 when the limit was exceeded, else
        ``None``.
    """
    if getattr(request, "limited", False):
        return json_error(ERROR_RATE_LIMITED, status=429)
    return None


def _save_or_error(save: callable, log_message: str) -> JsonResponse:
    """Run a vault persistence callable and map failures to JSON errors.

    Args:
        save (callable): Zero-argument callable performing the write.
        log_message (str): Log format string used for unexpected failures.

    Returns:
        JsonResponse: The callable's response on success, a JSON 400 for
        validation errors, or a JSON 500 for unexpected failures.
    """
    try:
        return save()
    except ValidationError as e:
        return json_error(_validation_error_message(e))
    except Exception as e:
        logger.error(log_message, exception_type(e))
        return json_error(ERROR_UNEXPECTED, status=500)


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_VAULT, method="GET", block=True),
    name="dispatch",
)
class NoteVaultView(SessionAuthRequiredMixin, View):
    """
    The note vault: an authenticated file manager + editor for vault notes.

    Renders only the vault shell (mirroring the passwd ``VaultView``): the page
    fetches the encrypted index and notes via the JSON APIs after the browser
    has established its vault key, so a logged-in-but-locked tab never receives
    ciphertext in the page HTML.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """Render the vault shell (no encrypted data embedded).

        Args:
            request (HttpRequest): Incoming GET request.

        Returns:
            HttpResponse: Rendered vault page.
        """
        user = self.get_authenticated_user(request)
        user_id = user.user_id if user else request.session.get(SESSION_KEY_USER_ID)
        return render(
            request,
            TEMPLATE_VAULT,
            _editor_context(
                request,
                user_id=user_id,
                # The note vault mirrors the derived vault key into
                # localStorage so sibling tabs on this origin can reuse it
                # (the passwd vault keeps it per-tab in sessionStorage only).
                # That copy has to age out, and the session's own lifetime is
                # the honest bound: the key is useless once the session it
                # depends on has lapsed. Handed over rather than hardcoded in
                # JS so the two cannot drift apart.
                session_max_age_seconds=settings.SESSION_COOKIE_AGE,
            ),
        )


class VaultIndexView(View):
    """
    Read or save the user's encrypted vault index (folder tree + note names).

    JSON API gated by ``require_session_auth_api`` (JSON 401, not a redirect).
    The index is opaque ciphertext to the server; an empty GET payload (just
    ``success``) means the user has no vault index yet.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_READ, method="GET", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def get(self, request: HttpRequest) -> JsonResponse:
        """Return the current user's encrypted index (empty when unset)."""
        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response
        return json_ok(**(services.get_vault_index(user) or {}))

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_WRITE, method="POST", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest) -> JsonResponse:
        """Create or replace the current user's encrypted index."""
        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response

        values, error_response = _string_fields_or_error(data, "encrypted_data", "iv")
        if error_response:
            return error_response
        encrypted_data, iv = values

        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response

        def save() -> JsonResponse:
            services.save_vault_index(user, encrypted_data, iv)
            return json_ok(SUCCESS_DATA_SAVED)

        return _save_or_error(save, LOG_VAULT_SAVE_FAILED)


class VaultNoteCollectionView(View):
    """
    List the user's vault notes or create a new one.

    GET returns metadata only by default (``id``, timestamps, ciphertext
    size); ``?content=1`` includes each note's ciphertext + IV, which the
    password-change migration and the vault's orphan recovery use. POST
    creates a note and enforces the per-user quota.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_READ, method="GET", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def get(self, request: HttpRequest) -> JsonResponse:
        """Return all of the current user's vault notes."""
        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response
        include_content = request.GET.get("content") == "1"
        return json_ok(
            notes=services.list_vault_notes(user, include_content=include_content)
        )

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_WRITE, method="POST", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest) -> JsonResponse:
        """Create a vault note from an encrypted payload."""
        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response

        values, error_response = _string_fields_or_error(data, "content", "iv")
        if error_response:
            return error_response
        content, iv = values

        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response

        def save() -> JsonResponse:
            note = services.create_vault_note(user, content=content, iv=iv)
            return json_ok(
                note_id=str(note.id),
                created_at=note.created_at.isoformat(),
                updated_at=note.updated_at.isoformat(),
            )

        return _save_or_error(save, LOG_VAULT_SAVE_FAILED)


class VaultNoteDetailView(View):
    """
    Read or overwrite a single vault note.

    Lookups are owner-scoped: a foreign or unknown id answers a JSON 404, so
    the endpoint reveals nothing about other users' note ids.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_READ, method="GET", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def get(self, request: HttpRequest, pk) -> JsonResponse:
        """Return one of the current user's vault notes."""
        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response

        note = services.get_vault_note(user, pk)
        if note is None:
            return json_error(ERROR_NOTE_NOT_FOUND, status=404)
        return json_ok(**services.serialize_vault_note(note))

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_WRITE, method="POST", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest, pk) -> JsonResponse:
        """Overwrite one of the current user's vault notes."""
        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response

        values, error_response = _string_fields_or_error(data, "content", "iv")
        if error_response:
            return error_response
        content, iv = values

        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response

        def save() -> JsonResponse:
            note = services.update_vault_note(user, pk, content=content, iv=iv)
            if note is None:
                return json_error(ERROR_NOTE_NOT_FOUND, status=404)
            return json_ok(SUCCESS_DATA_SAVED, updated_at=note.updated_at.isoformat())

        return _save_or_error(save, LOG_VAULT_SAVE_FAILED)


class VaultNoteDeleteView(View):
    """
    Permanently delete a vault note.

    Owner-scoped and idempotent like the passwd ``DeleteShareView``: deleting
    an unknown, foreign, or already-deleted note still reports success, so the
    client's trash flow can safely retry.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_WRITE, method="POST", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest, pk) -> JsonResponse:
        """Delete the named note if it belongs to the current user."""
        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response

        def save() -> JsonResponse:
            services.delete_vault_note(user, pk)
            return json_ok(SUCCESS_DATA_SAVED)

        return _save_or_error(save, LOG_VAULT_SAVE_FAILED)


class VaultNoteTrashView(View):
    """
    Move vault notes to Trash, or restore them, in one call.

    Trash state itself lives in the encrypted index; this endpoint records only
    the flag that lets ``delete_expired_notes`` enforce the retention window
    server-side (see :class:`~apps.note.models.VaultNote`).

    Deliberately bulk: deleting a folder trashes every note inside it in one
    gesture, and a per-note endpoint would spend one write of the vault rate
    limit per note. Owner-scoped and idempotent, so the client can retry.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_WRITE, method="POST", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest) -> JsonResponse:
        """Set or clear the Trash flag on a batch of the user's notes."""
        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response

        ids = data.get("ids")
        if not isinstance(ids, list) or len(ids) > MAX_VAULT_NOTES_PER_USER:
            return json_error(ERROR_INVALID_JSON)
        if any(not isinstance(note_id, str) for note_id in ids):
            return json_error(ERROR_INVALID_JSON)

        trashed = data.get("trashed")
        if not isinstance(trashed, bool):
            return json_error(ERROR_INVALID_JSON)

        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response

        def save() -> JsonResponse:
            updated = services.set_vault_notes_trashed(user, ids, trashed=trashed)
            return json_ok(SUCCESS_DATA_SAVED, updated=updated)

        return _save_or_error(save, LOG_VAULT_SAVE_FAILED)


class VaultMigrateView(View):
    """
    Re-write vault note ciphertexts (and optionally the index) in one batch.

    Backs the password-change flow in ``static/auth/js/account.js``: notes are
    re-encrypted client-side under the new vault key and submitted in batches;
    each batch is transactional, so a failure can never leave the batch half-
    migrated across two keys.
    """

    # block=False + JSON 429, unlike the other vault APIs: a password change
    # is the one flow that MUST finish. Once the change commits the server has
    # replaced vault_salt, so the old key exists only in the changing page's
    # memory -- a batch abandoned here leaves rows under two keys and no way
    # back. The client therefore retries a 429, which means it has to be able
    # to tell one from a rejected CSRF token; an HTML 403 is indistinguishable.
    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_VAULT_MIGRATE, method="POST", block=False
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest) -> JsonResponse:
        """Atomically apply a batch of re-encrypted notes and/or the index."""
        limited = _rate_limited_json(request)
        if limited:
            return limited

        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response

        notes = data.get("notes", [])
        if not isinstance(notes, list):
            return json_error(ERROR_INVALID_JSON)
        for item in notes:
            if not isinstance(item, dict):
                return json_error(ERROR_INVALID_JSON)
            _values, error_response = _string_fields_or_error(
                item, "id", "content", "iv"
            )
            if error_response:
                return error_response

        index_payload = data.get("index")
        if index_payload is not None:
            if not isinstance(index_payload, dict):
                return json_error(ERROR_INVALID_JSON)
            _values, error_response = _string_fields_or_error(
                index_payload, "encrypted_data", "iv"
            )
            if error_response:
                return error_response

        user, error_response = _vault_session_user_or_error(request)
        if error_response:
            return error_response

        def save() -> JsonResponse:
            migrated = services.migrate_vault_data(
                user,
                notes=notes,
                index_payload=index_payload,
            )
            return json_ok(SUCCESS_DATA_SAVED, migrated=migrated)

        return _save_or_error(save, LOG_VAULT_MIGRATE_FAILED)


# --- Live notes (editable share links) ---
#
# Anonymous JSON endpoints for the polling CRDT sync: anyone holding the link
# may read and append (the fragment key gates *understanding* the ciphertext,
# not reaching the endpoint, which is the same trust model as "anyone with the
# link can edit"). Unlike the vault APIs these use block=False + a JSON 429, since
# a polling client must be able to parse the reply and back off; the vault's
# block=True path would hand it an HTML 403.


def _live_note_or_404_json(pk) -> tuple[LiveNote | None, JsonResponse | None]:
    """Fetch a live note for the JSON endpoints, deleting it if expired.

    Expired and unknown ids are deliberately indistinguishable (both 404): the
    sync client treats any 404 as the terminal "this document is gone" state.

    Args:
        pk (uuid.UUID | str): Primary key of the requested live note.

    Returns:
        tuple[LiveNote | None, JsonResponse | None]: The active note, or a
        JSON 404.
    """
    note = services.get_active_live_note(pk)
    if note is None:
        return None, json_error(ERROR_NOTE_NOT_FOUND, status=404)
    return note, None


def _non_negative_int(value) -> int | None:
    """Coerce a query-string or JSON value to a non-negative int.

    Args:
        value (Any): Raw value: an ``int`` from a JSON body or a ``str`` from
            a query parameter. Booleans are rejected (they are ints to
            ``isinstance`` but never a valid cursor).

    Returns:
        int | None: The value as an int, or ``None`` when it isn't one.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = int(value, 10)
        except ValueError:
            return None
    if not isinstance(value, int) or value < 0:
        return None
    return value


@method_decorator(
    ratelimit(
        key=client_ip_key, rate=RATE_LIMIT_LIVE_CREATE, method="POST", block=False
    ),
    name="dispatch",
)
class CreateLiveNoteView(View):
    """Create a live note from a client-encrypted seed snapshot.

    Anonymous like ``CreateNoteView``, but JSON-bodied: the live flow is
    JS-only by nature (a CRDT editor cannot degrade to a noscript form), so
    there is no form-encoded branch.
    """

    def post(self, request: HttpRequest) -> JsonResponse:
        """Validate and persist a live note creation request."""
        limited = _rate_limited_json(request)
        if limited:
            return limited

        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response
        values, error_response = _string_fields_or_error(
            data, "snapshot", "snapshot_iv", missing_message=ERROR_LIVE_MISSING_FIELDS
        )
        if error_response:
            return error_response
        snapshot, snapshot_iv = values

        expiry_key = data.get("expiry_time", DEFAULT_EXPIRY)
        if not isinstance(expiry_key, str):
            return json_error(ERROR_INVALID_JSON)

        try:
            note = services.create_live_note(
                snapshot=snapshot,
                snapshot_iv=snapshot_iv,
                expiry_key=expiry_key,
                created_by=_authenticated_note_owner(request),
            )
        except ValidationError as e:
            return json_error(_validation_error_message(e))
        except Exception as e:
            logger.error(LOG_LIVE_CREATE_FAILED, exception_type(e))
            return json_error(ERROR_CREATE_FAILED, status=500)

        return json_ok(note_id=str(note.id), expires_at=note.expires_at.isoformat())


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_LIVE_PAGE, method="GET", block=True),
    name="dispatch",
)
class LiveNotePageView(View):
    """Serve the live editor page for an active live note.

    HTML like ``RetrieveNoteView`` (block=True, expired page, delete-on-
    access), and host-gated: live links belong to the note tool, so the page
    404s on any other host, the same "the tools' share spaces are separate"
    rule the ``/<uuid>/`` dispatch enforces. The page is a shell: like the
    vaults, it embeds no ciphertext; the client fetches the state over JSON
    once it holds the fragment key.
    """

    def get(self, request: HttpRequest, pk) -> HttpResponse:
        """Render the live editor shell or the expiry page."""
        if not is_note_site(request):
            raise Http404
        note = get_object_or_404(LiveNote, pk=pk)

        if note.is_expired():
            note.delete()
            logger.info(LOG_LIVE_EXPIRED_DELETED, pk)
            return render(request, TEMPLATE_EXPIRED)

        services.register_live_note_access(pk)

        # Only for the header chrome (Vault vs Sign In); the live document
        # itself is anonymous.
        session_user_id = get_authenticated_user_id(request)

        context = {
            "live_note_id": str(note.id),
            "state_url": reverse("note:live_state", args=[note.id]),
            "updates_url": reverse("note:live_updates", args=[note.id]),
            "snapshot_url": reverse("note:live_snapshot", args=[note.id]),
            # Not reverse(): websocket routes live in apps/note/routing.py,
            # outside the HTTP URLconf. The literal must match its pattern.
            "ws_path": f"/ws/live/{note.id}/",
            "is_authenticated": bool(session_user_id),
            "expires_at": note.expires_at.isoformat(),
        }
        return render(request, TEMPLATE_LIVE, context)


class LiveNoteStateView(View):
    """Bootstrap payload for a joining client: snapshot plus pending tail."""

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_LIVE_READ, method="GET", block=False
        )
    )
    def get(self, request: HttpRequest, pk) -> JsonResponse:
        """Return the full encrypted sync state."""
        limited = _rate_limited_json(request)
        if limited:
            return limited
        note, error_response = _live_note_or_404_json(pk)
        if error_response:
            return error_response
        return json_ok(**services.live_note_state(note))


class LiveNoteUpdatesView(View):
    """The sync loop: poll updates after a cursor, append merged updates."""

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_LIVE_READ, method="GET", block=False
        )
    )
    def get(self, request: HttpRequest, pk) -> JsonResponse:
        """Return updates newer than ``?since=``, resyncing pruned cursors."""
        limited = _rate_limited_json(request)
        if limited:
            return limited
        note, error_response = _live_note_or_404_json(pk)
        if error_response:
            return error_response
        since = _non_negative_int(request.GET.get("since"))
        if since is None:
            return json_error(ERROR_LIVE_INVALID_SINCE)

        return json_ok(**services.live_updates_since(note, since))

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_LIVE_WRITE, method="POST", block=False
        )
    )
    def post(self, request: HttpRequest, pk) -> JsonResponse:
        """Append one client-merged encrypted update to the note's log."""
        limited = _rate_limited_json(request)
        if limited:
            return limited
        note, error_response = _live_note_or_404_json(pk)
        if error_response:
            return error_response
        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response
        values, error_response = _string_fields_or_error(
            data, "payload", "iv", missing_message=ERROR_LIVE_MISSING_FIELDS
        )
        if error_response:
            return error_response
        payload, iv = values

        try:
            row, pending, prev_seq = services.append_live_update(
                pk, payload=payload, iv=iv
            )
        except LiveNote.DoesNotExist:
            # The expiry sweep can delete the note between the fetch above and
            # the locked re-fetch inside the service; same terminal 404.
            return json_error(ERROR_NOTE_NOT_FOUND, status=404)
        except ValidationError as e:
            # services.validation_code, not e.code: model field validation
            # arrives here in ValidationError's dict form, which has no code
            # attribute at all (see the helper's docstring).
            if services.validation_code(e) == "pending_tail_full":
                return json_error(
                    ERROR_LIVE_TAIL_FULL, status=409, code="pending_tail_full"
                )
            return json_error(_validation_error_message(e))
        except Exception as e:
            logger.error(LOG_LIVE_APPEND_FAILED, exception_type(e))
            return json_error(ERROR_UNEXPECTED, status=500)

        # prev_seq mirrors the WebSocket ack shape; the polling client ignores
        # it (its cursor only advances from GETs) but the shapes stay aligned.
        return json_ok(seq=row.pk, pending=pending, prev_seq=prev_seq)


class LiveNoteSnapshotView(View):
    """Accept a client's compacted snapshot and prune the covered log."""

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_LIVE_SNAPSHOT, method="POST", block=False
        )
    )
    def post(self, request: HttpRequest, pk) -> JsonResponse:
        """Store the re-encrypted snapshot; first valid compactor wins."""
        limited = _rate_limited_json(request)
        if limited:
            return limited
        note, error_response = _live_note_or_404_json(pk)
        if error_response:
            return error_response
        data, error_response = _json_body_or_error(request)
        if error_response:
            return error_response
        values, error_response = _string_fields_or_error(
            data, "snapshot", "snapshot_iv", missing_message=ERROR_LIVE_MISSING_FIELDS
        )
        if error_response:
            return error_response
        snapshot, snapshot_iv = values

        covers_seq = _non_negative_int(data.get("covers_seq"))
        if covers_seq is None:
            return json_error(ERROR_INVALID_JSON)

        try:
            deleted = services.save_live_snapshot(
                pk,
                snapshot=snapshot,
                snapshot_iv=snapshot_iv,
                covers_seq=covers_seq,
            )
        except LiveNote.DoesNotExist:
            return json_error(ERROR_NOTE_NOT_FOUND, status=404)
        except ValidationError as e:
            # See the note in LiveNoteUpdatesView.post: an oversized or
            # non-Base64 snapshot raises the code-less dict form here.
            code = services.validation_code(e)
            if code == "stale_snapshot":
                return json_error(ERROR_LIVE_STALE_SNAPSHOT, status=409)
            if code == "covers_unknown_updates":
                return json_error(ERROR_LIVE_COVERS_UNKNOWN, status=409)
            return json_error(_validation_error_message(e))
        except Exception as e:
            logger.error(LOG_LIVE_SNAPSHOT_FAILED, exception_type(e))
            return json_error(ERROR_UNEXPECTED, status=500)

        return json_ok(snapshot_seq=covers_seq, deleted_updates=deleted)
