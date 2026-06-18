"""
Views for the password sharing application.

This module provides views for creating, retrieving, and managing encrypted
password shares, as well as the user vault for managing shares.
All cryptographic operations occur client-side; the server only handles
encrypted data storage and retrieval.
"""

import json
import logging
import uuid

from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse, JsonResponse
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
from apps.core.encoding import decode_base64
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
    DUMMY_SHARE_ID,
    RATE_LIMIT_CREATE,
    RATE_LIMIT_EXPORT,
    RATE_LIMIT_RETRIEVE,
    RATE_LIMIT_UPDATE_DATA,
    RATE_LIMIT_DELETE_SHARE,
    RATE_LIMIT_VAULT,
    TEMPLATE_CREATE,
    TEMPLATE_SUCCESS,
    TEMPLATE_RETRIEVE,
    TEMPLATE_EXPIRED,
    TEMPLATE_VAULT,
    ERROR_MISSING_FIELDS,
    ERROR_CREATE_FAILED,
    ERROR_MISSING_REQUIRED,
    ERROR_INVALID_IV,
    ERROR_INVALID_SHARE_ID,
    ERROR_USER_NOT_FOUND,
    ERROR_INVALID_JSON,
    ERROR_UNEXPECTED,
    SUCCESS_DATA_SAVED,
    SUCCESS_SHARE_DELETED,
    LOG_CREATE_FAILED,
    LOG_EXPIRED_DELETED,
    LOG_NO_SERVICE_DATA,
    LOG_UPDATE_DATA,
    LOG_UPDATE_DATA_ERROR,
    LOG_SHARE_DELETED,
    LOG_DELETE_SHARE_ERROR,
)
from .models import SharedPassword

logger = logging.getLogger(__name__)


def _validation_error_message(error: ValidationError) -> str:
    """Flatten a Django ValidationError into a user-facing message string."""
    return " ".join(str(message) for message in error.messages)


def _create_share_payload(request: HttpRequest) -> dict:
    """Extract the encrypted share form payload from the POST body."""
    return {
        "encrypted_data": request.POST.get("encrypted_data", "").strip(),
        "iv": request.POST.get("iv", "").strip(),
        "encrypted_title": request.POST.get("encrypted_title", "").strip(),
        "title_iv": request.POST.get("title_iv", "").strip(),
        "expiry_key": request.POST.get("expiry_time", DEFAULT_EXPIRY),
    }


def _authenticated_share_owner(request: HttpRequest) -> User | None:
    """Return the current authenticated user for owned shares, if any."""
    user_id = get_authenticated_user_id(request)
    return get_user_by_id(user_id) if user_id else None


def _create_error_response(
    request: HttpRequest, message: str, *, status: int = 400
) -> HttpResponse:
    """Return the create-page error shape for AJAX and non-AJAX callers."""
    return ajax_or_html(
        request,
        ajax=lambda: json_error(message, status=status),
        html=lambda: render(
            request, TEMPLATE_CREATE, {"error": message}, status=status
        ),
    )


def _share_json_response(share: SharedPassword) -> JsonResponse:
    """Return the AJAX success payload for a newly-created share."""
    return json_ok(
        share_id=str(share.id),
        encrypted_title=share.encrypted_title,
        title_iv=share.title_iv,
        expires_at=share.expires_at.isoformat(),
        created_at=share.created_at.isoformat(),
    )


def _success_page_context(request: HttpRequest, share: SharedPassword) -> dict:
    """Build the non-AJAX success page context for a newly-created share."""
    retrieval_url_base = request.build_absolute_uri(
        reverse("passwd:retrieve", args=[DUMMY_SHARE_ID])
    )
    return {
        "share": share,
        "retrieval_url_base": retrieval_url_base,
        "dummy_share_id": DUMMY_SHARE_ID,
    }


def _decode_vault_payload(data: dict) -> tuple[str, bytes, JsonResponse | None]:
    """Validate required vault payload keys and decode the Base64 IV."""
    if not isinstance(data, dict):
        return "", b"", json_error(ERROR_INVALID_JSON)

    encrypted_data = data.get("encrypted_data")
    iv_base64 = data.get("iv")

    if encrypted_data is None or iv_base64 is None:
        return "", b"", json_error(ERROR_MISSING_REQUIRED)

    if not isinstance(encrypted_data, str) or not isinstance(iv_base64, str):
        return "", b"", json_error(ERROR_INVALID_JSON)

    if not encrypted_data.strip() or not iv_base64.strip():
        return "", b"", json_error(ERROR_MISSING_REQUIRED)

    try:
        return encrypted_data, decode_base64(iv_base64), None
    except ValueError:
        return "", b"", json_error(ERROR_INVALID_IV)


def _session_user_or_error(
    request: HttpRequest,
) -> tuple[User | None, JsonResponse | None]:
    """Resolve the current session user for JSON APIs."""
    user = get_user_by_id(request.session.get(SESSION_KEY_USER_ID))
    if not user:
        return None, json_error(ERROR_USER_NOT_FOUND, status=404)
    return user, None


def _save_vault_payload(
    user: User, encrypted_data: str, iv_binary: bytes
) -> JsonResponse:
    """Persist a decoded vault payload and map validation/storage errors."""
    try:
        services.save_user_vault_data(user, encrypted_data, iv_binary)
    except ValidationError as e:
        return json_error(_validation_error_message(e))
    except Exception as e:
        logger.error(LOG_UPDATE_DATA_ERROR, exception_type(e))
        return json_error(ERROR_UNEXPECTED, status=500)
    logger.info(LOG_UPDATE_DATA, user.user_id)
    return json_ok(SUCCESS_DATA_SAVED)


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_CREATE, method="POST", block=True),
    name="dispatch",
)
class CreateShareView(View):
    """
    Create a new encrypted password share.

    Handles GET (display the share creation form) and POST (create a new
    share). Supports both AJAX and traditional form submissions.

    On successful creation:
    - AJAX requests receive a JSON response with share details
    - Non-AJAX requests are redirected to a success page

    Rate Limiting:
        Limited to RATE_LIMIT_CREATE per IP address
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        # GET request - display the create form
        return render(request, TEMPLATE_CREATE)

    def post(self, request: HttpRequest) -> HttpResponse:
        payload = _create_share_payload(request)

        if not payload["encrypted_data"] or not payload["iv"]:
            return _create_error_response(request, ERROR_MISSING_FIELDS)

        try:
            share = services.create_share(
                **payload,
                created_by=_authenticated_share_owner(request),
            )
        except ValidationError as e:
            return _create_error_response(request, _validation_error_message(e))
        except Exception as e:
            logger.error(LOG_CREATE_FAILED, exception_type(e))
            return _create_error_response(request, ERROR_CREATE_FAILED, status=500)

        return ajax_or_html(
            request,
            ajax=lambda: _share_json_response(share),
            html=lambda: render(
                request, TEMPLATE_SUCCESS, _success_page_context(request, share)
            ),
        )


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_RETRIEVE, method="GET", block=True),
    name="dispatch",
)
class RetrieveShareView(View):
    """
    Retrieve and display a shared password if valid and not expired.

    Fetches the encrypted password data and passes it to the template for
    client-side decryption. The encryption key is never sent to the server -
    it remains in the URL fragment (after #).

    Rate Limiting:
        Limited to RATE_LIMIT_RETRIEVE per IP address

    Security Notes:
        - Expired shares are automatically deleted
        - Access count is incremented on each retrieval
        - Server never sees the plaintext password
    """

    def get(self, request: HttpRequest, pk: str) -> HttpResponse:
        share = get_object_or_404(SharedPassword, pk=pk)

        # Delete just this share if it has expired. The global sweep of all
        # expired rows is handled out-of-band by the `delete_expired` cron job, so
        # it doesn't belong on this hot path; deleting the specific share that was
        # opened after expiry removes that secret immediately, regardless of cron
        # timing.
        if share.is_expired():
            share.delete()
            logger.info(LOG_EXPIRED_DELETED, pk)
            return render(request, TEMPLATE_EXPIRED)

        # Increment access count atomically to avoid lost updates under concurrency
        services.register_share_access(pk)

        # Prepare share data for JavaScript decryption. The title ciphertext is
        # decrypted in the browser with the key from the URL fragment.
        share_data_for_js = {
            "ciphertext": share.encrypted_data,
            "iv": share.iv,
            "encrypted_title": share.encrypted_title,
            "title_iv": share.title_iv,
            "expires_at": share.expires_at.isoformat(),
        }

        context = {"share": share, "share_data_json": share_data_for_js}
        return render(request, TEMPLATE_RETRIEVE, context)


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_VAULT, method="GET", block=True),
    name="dispatch",
)
class VaultView(SessionAuthRequiredMixin, View):
    """
    Vault view for managing password shares.

    This view displays the user's vault where they can view their
    saved shares and create new ones. Requires authentication via
    session-based auth (the redirect-style ``SessionAuthRequiredMixin``).
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        """
        Display the vault with the user's encrypted share data.

        The vault blob is fetched and passed to the client still encrypted (an
        empty vault when none exists); the master key for decryption lives only
        in the browser's session storage.
        """
        user = self.get_authenticated_user(request)
        user_data = services.get_user_vault_data(user) if user else None
        user_id = user.user_id if user else request.session.get(SESSION_KEY_USER_ID)

        if not user_data:
            # User has no saved data yet (or no matching user)
            logger.debug(LOG_NO_SERVICE_DATA, user_id)

        return render(
            request,
            TEMPLATE_VAULT,
            {
                "user_id": user_id,
                "user_data_json": user_data or {},
            },
        )


class UpdateEncryptedDataView(View):
    """
    API view to create or update encrypted user data for the sharing service.

    This view handles AJAX requests to save the user's encrypted vault data.
    The data is encrypted client-side before being sent to the server.

    Unlike the redirect-style views (which use ``SessionAuthRequiredMixin``),
    this JSON API gate uses ``require_session_auth_api`` so unauthenticated
    callers get a JSON 401 instead of an HTML redirect.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_UPDATE_DATA, method="POST", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest) -> JsonResponse:
        """Save or update the authenticated user's encrypted vault blob."""
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return json_error(ERROR_INVALID_JSON)

        encrypted_data, iv_binary, error_response = _decode_vault_payload(data)
        if error_response:
            return error_response

        user, error_response = _session_user_or_error(request)
        if error_response:
            return error_response

        return _save_vault_payload(user, encrypted_data, iv_binary)


class VaultDataView(View):
    """
    Return the authenticated user's encrypted vault blob as JSON.

    The account page uses this to migrate the vault when the password changes:
    a new password derives a new vault key, so the stored blob must be read,
    re-encrypted under the new key, and saved again (see ``static/js/account.js``).
    Like ``UpdateEncryptedDataView`` this is a JSON API, so it gates with
    ``require_session_auth_api`` (JSON 401) rather than the redirect mixin. The
    returned ``encrypted_data``/``iv`` are ciphertext the server cannot read; an
    empty payload (just ``success``) means the user has no stored vault yet.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_UPDATE_DATA, method="GET", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def get(self, request: HttpRequest) -> JsonResponse:
        """Return the current user's encrypted vault blob (empty when unset)."""
        user, error_response = _session_user_or_error(request)
        if error_response:
            return error_response

        return json_ok(**(services.get_user_vault_data(user) or {}))


class DeleteShareView(View):
    """
    API view to revoke a share owned by the authenticated user.

    The vault calls this when an entry is removed so the underlying
    ``SharedPassword`` is deleted server-side (the ``/<uuid>/`` link stops
    working immediately) rather than lingering until it expires. Like the other
    vault JSON APIs it gates with ``require_session_auth_api`` (JSON 401). The
    delete is owner-scoped and idempotent: revoking an unknown, foreign, or
    already-deleted share still reports success.
    """

    @method_decorator(
        ratelimit(
            key=client_ip_key, rate=RATE_LIMIT_DELETE_SHARE, method="POST", block=True
        )
    )
    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest) -> JsonResponse:
        """Delete the named share if it belongs to the authenticated user."""
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return json_error(ERROR_INVALID_JSON)

        if not isinstance(data, dict):
            return json_error(ERROR_INVALID_JSON)

        share_id = data.get("share_id")
        if not share_id or not isinstance(share_id, str):
            return json_error(ERROR_MISSING_REQUIRED)

        # Filtering a UUIDField with a non-UUID string raises, so validate first.
        try:
            uuid.UUID(share_id)
        except (ValueError, TypeError):
            return json_error(ERROR_INVALID_SHARE_ID)

        user, error_response = _session_user_or_error(request)
        if error_response:
            return error_response

        try:
            deleted = services.delete_user_share(user, share_id)
        except Exception as e:
            logger.error(LOG_DELETE_SHARE_ERROR, exception_type(e))
            return json_error(ERROR_UNEXPECTED, status=500)

        if deleted:
            logger.info(LOG_SHARE_DELETED, share_id, user.user_id)
        return json_ok(SUCCESS_SHARE_DELETED)


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_EXPORT, method="GET", block=True),
    name="dispatch",
)
class DataExportView(SessionAuthRequiredMixin, View):
    """
    GDPR-compliant data export view. Returns a JSON file containing all
    personal data held for the authenticated user.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        user = self.get_authenticated_user(request)
        if not user:
            return self.handle_missing_user(request)

        export = services.build_user_export(user)

        payload = json.dumps(export, indent=2)
        filename = f"proximared-export-{user.user_id}.json"
        response = HttpResponse(payload, content_type="application/json")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response
