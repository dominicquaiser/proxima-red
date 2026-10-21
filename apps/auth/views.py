"""
Authentication views for user signup, signin, signout, and account management.

This module provides class-based views for handling user authentication
and account operations with support for both traditional form submissions
and AJAX requests.
"""

import logging

from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import View
from django_ratelimit.decorators import ratelimit

from apps.core.http import (
    ajax_or_html,
    client_ip_key,
    exception_type,
    flash_and_redirect,
    json_error,
    json_form_error,
    json_ok,
)

from . import services
from .constants import (
    DEFAULT_VAULT_TOOL,
    ERROR_ACCOUNT_DELETION_FAILED,
    ERROR_INVALID_CREDENTIALS,
    ERROR_INVALID_USER_ID,
    ERROR_UNEXPECTED,
    ERROR_USER_CREATION_FAILED,
    LOG_ACCOUNT_DELETE_ERROR,
    LOG_SIGNIN_ERROR,
    LOG_SIGNUP_ERROR,
    RATE_LIMIT_ACCOUNT,
    RATE_LIMIT_SIGNIN,
    RATE_LIMIT_SIGNUP,
    RATE_LIMIT_VAULT_SESSION,
    SUCCESS_ACCOUNT_CREATED,
    SUCCESS_ACCOUNT_DELETED,
    SUCCESS_PASSWORD_CHANGED,
    SUCCESS_SIGNIN,
    SUCCESS_SIGNOUT,
    SUCCESS_USER_CREATED,
    TEMPLATE_ACCOUNT,
    TEMPLATE_SIGNIN,
    TEMPLATE_SIGNUP,
    VAULT_TOOL_NOTE,
    VAULT_TOOLS,
)
from .exceptions import UserCreationError
from .forms import (
    AccountDeletionForm,
    PasswordChangeForm,
    SigninForm,
    SignupForm,
)
from .mixins import (
    MainSiteRedirectMixin,
    RatelimitGateMixin,
    SessionAuthRequiredMixin,
)
from .models import is_valid_user_id
from .utils import (
    get_authenticated_user,
    get_authenticated_user_id,
    require_session_auth_api,
    require_tool_auth_api,
)
from .vault_sessions import access_state, grant_access, renew_note_access

logger = logging.getLogger(__name__)


def vault_url(tool: str = DEFAULT_VAULT_TOOL) -> str:
    """Absolute URL of a tool's vault on its canonical subdomain.

    Each vault is served on its tool's host (``PASS_SITE_URL`` /
    ``NOTE_SITE_URL``, split by core's ``vault_dispatch``). Auth flows live on
    the main site, so they must send users to the subdomain explicitly rather
    than to a relative ``/vault/`` that would keep them on whatever host they
    signed in on. When the sites share a host (local dev, tests) this is just
    that host.

    Args:
        tool: A key from ``VAULT_TOOLS``; the ``tool`` request parameter is
            vetted against the allowlist, so an unknown value falls back to the
            pass vault (fail closed; never interpolated into the redirect).

    Returns:
        str: Absolute vault URL for the tool.
    """
    if tool == VAULT_TOOL_NOTE:
        return f"{settings.NOTE_SITE_URL}{reverse('note:vault')}"
    return f"{settings.PASS_SITE_URL}{reverse('passwd:vault')}"


class AuthFormView(MainSiteRedirectMixin, RatelimitGateMixin, View):
    """
    Shared scaffolding for the public signup and signin pages.

    Both views are rate limited on POST, redirect already-authenticated users
    straight to the vault, and render their form on GET. Subclasses set
    ``template_name``, ``form_class`` and ``ratelimit_redirect``, and implement
    ``post``. The rate-limit decorator stays on each subclass's ``dispatch``
    because the per-view limits differ; the ``handle_ratelimited`` gate comes
    from ``RatelimitGateMixin``.
    """

    form_class = None

    def requested_tool(self, request: HttpRequest) -> str:
        """Return the vetted vault tool requested by the ``tool`` parameter.

        The signin/signup links on each tool's pages carry ``?tool=<key>`` so
        the flow can land the user back on that tool's vault. POST wins over
        GET (the form re-submits the value it was rendered with); anything not
        in the allowlist falls back to the default.
        """
        tool = request.POST.get("tool") or request.GET.get("tool") or ""
        return tool if tool in VAULT_TOOLS else DEFAULT_VAULT_TOOL

    def redirect_if_authenticated(self, request: HttpRequest):
        """Return a redirect to the vault for an already-authenticated session, else None."""
        if get_authenticated_user_id(request):
            return redirect(vault_url(self.requested_tool(request)))
        return None

    def get(self, request: HttpRequest) -> HttpResponse:
        """Display the form, or redirect to the vault when already authenticated."""
        return self.redirect_if_authenticated(request) or render(
            request,
            self.template_name,
            {"form": self.form_class(), "tool": self.requested_tool(request)},
        )

    def render_form(
        self, request: HttpRequest, form=None, *, status: int | None = None
    ) -> HttpResponse:
        """Render this view's form template with an optional bound form."""
        kwargs = {"status": status} if status is not None else {}
        return render(
            request,
            self.template_name,
            {"form": form or self.form_class(), "tool": self.requested_tool(request)},
            **kwargs,
        )

    def form_error_response(
        self, request: HttpRequest, form, *, status: int | None = None
    ) -> HttpResponse:
        """Return a validation-error response for AJAX and non-AJAX callers."""
        return ajax_or_html(
            request,
            ajax=lambda: json_form_error(form, status=status or 400),
            html=lambda: self.render_form(request, form, status=status),
        )

    def exception_response(self, request: HttpRequest, message: str) -> HttpResponse:
        """Return an unexpected-error response for AJAX and non-AJAX callers."""
        return ajax_or_html(
            request,
            ajax=lambda: json_error(message, status=500),
            html=lambda: self._html_exception_response(request, message),
        )

    def _html_exception_response(self, request: HttpRequest, message: str) -> HttpResponse:
        """Flash an error message and render the unbound form."""
        messages.error(request, message)
        return self.render_form(request)


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_SIGNUP, method="POST", block=False),
    name="dispatch",
)
class SignupView(AuthFormView):
    """
    Zero-knowledge signup view for creating a new user account.

    Supports both traditional form submission and AJAX requests.
    Rate limited to prevent abuse.
    """

    template_name = TEMPLATE_SIGNUP
    form_class = SignupForm
    ratelimit_redirect = "auth:signup"

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle signup form submission."""
        already_authenticated = self.redirect_if_authenticated(request)
        if already_authenticated:
            return already_authenticated

        form = SignupForm(request.POST)

        if not form.is_valid():
            return self.form_error_response(request, form)

        user = self._create_user_or_error(request, form)
        if isinstance(user, HttpResponse):
            return user

        return self._success_response(request, user)

    def _create_user_or_error(self, request: HttpRequest, form: SignupForm):
        """Create a user or return an error response."""
        try:
            return services.create_user_with_auth_secret(
                form.cleaned_data["auth_secret"],
                auth_salt=form.cleaned_data["auth_salt"],
                vault_salt=form.cleaned_data["vault_salt"],
            )
        except UserCreationError as e:
            logger.error(LOG_SIGNUP_ERROR, exception_type(e))
            return self.exception_response(request, ERROR_USER_CREATION_FAILED)
        except Exception as e:
            logger.error(LOG_SIGNUP_ERROR, exception_type(e))
            return self.exception_response(request, ERROR_UNEXPECTED)

    def _success_response(self, request: HttpRequest, user) -> HttpResponse:
        """Return the signup success response for AJAX and non-AJAX callers."""
        return ajax_or_html(
            request,
            ajax=lambda: json_ok(
                SUCCESS_USER_CREATED,
                user_id=user.user_id,
                auth_salt=user.auth_salt,
                vault_salt=user.vault_salt,
            ),
            html=lambda: flash_and_redirect(
                request,
                SUCCESS_ACCOUNT_CREATED.format(user_id=user.user_id),
                "auth:signin",
            ),
        )


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_SIGNIN, method="POST", block=False),
    name="dispatch",
)
class AuthSaltsView(RatelimitGateMixin, View):
    """
    Return public derivation salts for the signin flow.

    The browser needs the authentication salt to derive the auth secret and the
    vault salt to unlock encrypted vault data. Both are public KDF inputs, not
    secrets. Unknown users receive deterministic decoy salts (stable per user_id,
    see ``generate_decoy_salt``) so the endpoint cannot be used as an
    account-existence oracle - neither directly nor by comparing repeated calls.
    """

    ratelimit_redirect = "auth:signin"

    def post(self, request: HttpRequest) -> HttpResponse:
        user_id = (request.POST.get("user_id") or "").strip()
        if not is_valid_user_id(user_id):
            return json_error(ERROR_INVALID_USER_ID)

        user = services.get_user_by_id(user_id)
        if not user or not user.auth_salt:
            return json_ok(
                auth_salt=services.generate_decoy_salt(user_id, purpose="auth"),
                vault_salt=services.generate_decoy_salt(user_id, purpose="vault"),
            )

        return json_ok(auth_salt=user.auth_salt, vault_salt=user.vault_salt)


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_SIGNIN, method="POST", block=False),
    name="dispatch",
)
class ReauthView(RatelimitGateMixin, View):
    """
    Verify the current account password and renew the selected vault grant.

    The account preflight grants both tools so password rotation can recover
    both vaults before changing credentials. Verification always uses the session
    user; a posted user ID cannot select another account.
    """

    ratelimit_redirect = "auth:signin"

    @method_decorator(require_session_auth_api)
    def post(self, request: HttpRequest) -> HttpResponse:
        auth_secret = (request.POST.get("auth_secret") or "").strip()
        if not auth_secret:
            return json_error(ERROR_INVALID_CREDENTIALS, status=400)

        user_id = get_authenticated_user_id(request)
        tool = request.POST.get("tool", "pass")
        if tool not in (*VAULT_TOOLS, "account"):
            return json_error("Invalid vault tool.")
        expected_user = request.POST.get("expected_user")
        if expected_user and expected_user != user_id:
            return json_error("The signed-in account changed. Reload to continue.", status=409)
        user = services.authenticate_user(user_id, auth_secret)
        if not user:
            return json_error(ERROR_INVALID_CREDENTIALS, status=401)

        grant_access(request, user, VAULT_TOOLS if tool == "account" else (tool,))
        response = json_ok(
            auth_salt=user.auth_salt,
            vault_salt=user.vault_salt,
            state=access_state(request, user, "pass" if tool == "account" else tool),
        )
        response["Cache-Control"] = "no-store"
        return response


@method_decorator(
    ratelimit(
        key=client_ip_key, rate=RATE_LIMIT_VAULT_SESSION, method=["GET", "POST"], block=False
    ),
    name="dispatch",
)
class VaultSessionView(RatelimitGateMixin, View):
    """Read deadlines without renewal; explicitly record foreground note activity."""

    ratelimit_redirect = "auth:signin"

    @method_decorator(require_session_auth_api)
    def get(self, request):
        tool = request.GET.get("tool", "pass")
        if tool not in VAULT_TOOLS:
            return json_error("Invalid vault tool.")
        user = get_authenticated_user(request)
        if not user:
            return json_error(ERROR_INVALID_CREDENTIALS, status=401)
        response = json_ok(state=access_state(request, user, tool))
        response["Cache-Control"] = "no-store"
        return response

    @method_decorator(require_tool_auth_api("note"))
    def post(self, request):
        renew_note_access(request)
        return json_ok(state=access_state(request, get_authenticated_user(request), "note"))


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_SIGNIN, method="POST", block=False),
    name="dispatch",
)
class SigninView(AuthFormView):
    """
    Zero-knowledge signin view for user authentication.

    Authenticates users with their user_id and password. Supports both
    traditional form submission and AJAX requests. Rate limited to
    prevent brute-force attacks.
    """

    template_name = TEMPLATE_SIGNIN
    form_class = SigninForm
    ratelimit_redirect = "auth:signin"

    def post(self, request: HttpRequest) -> HttpResponse:
        """Handle signin form submission."""
        already_authenticated = self.redirect_if_authenticated(request)
        if already_authenticated:
            return already_authenticated

        form = SigninForm(request.POST)
        if not form.is_valid():
            request.session.flush()
            return self.form_error_response(request, form)

        user = self._authenticate_or_error(request, form)
        if isinstance(user, HttpResponse):
            return user
        if not user:
            return self._invalid_credentials_response(request, form)

        return self._create_session_response(request, user)

    def _authenticate_or_error(self, request: HttpRequest, form):
        """Authenticate form credentials or return an unexpected-error response."""
        try:
            return services.authenticate_user(
                form.cleaned_data["user_id"], form.cleaned_data["auth_secret"]
            )
        except Exception as e:
            logger.error(LOG_SIGNIN_ERROR, exception_type(e))
            return self.exception_response(request, ERROR_UNEXPECTED)

    def _invalid_credentials_response(self, request: HttpRequest, form) -> HttpResponse:
        """Return the invalid-credentials response and clear any session state."""
        request.session.flush()
        form.add_error(None, ERROR_INVALID_CREDENTIALS)
        return ajax_or_html(
            request,
            ajax=lambda: json_form_error(form, status=401),
            html=lambda: self.render_form(request, form),
        )

    def _create_session_response(self, request: HttpRequest, user) -> HttpResponse:
        """Create the session and return the signin success response."""
        try:
            services.create_user_session(request, user)
        except Exception as e:
            logger.error(LOG_SIGNIN_ERROR, exception_type(e))
            return self.exception_response(request, ERROR_UNEXPECTED)

        tool = self.requested_tool(request)
        return ajax_or_html(
            request,
            ajax=lambda: json_ok(
                SUCCESS_SIGNIN,
                auth_salt=user.auth_salt,
                vault_salt=user.vault_salt,
                state=access_state(request, user, tool),
                redirect_url=vault_url(tool),
            ),
            html=lambda: redirect(vault_url(tool)),
        )


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_ACCOUNT, method="POST", block=False),
    name="dispatch",
)
class SignoutView(RatelimitGateMixin, View):
    """
    Sign out view to destroy user session.

    POST-only: signing out flushes the server session, so it must be a
    CSRF-protected state change - a GET handler would let any third-party
    page sign the user out (logout CSRF). The header "Sign Out" buttons
    submit a small POST form.
    """

    ratelimit_redirect = "auth:signin"

    def post(self, request: HttpRequest) -> HttpResponse:
        """Destroy the session and return the AJAX or redirect response."""
        services.destroy_user_session(request)
        return ajax_or_html(
            request,
            ajax=lambda: json_ok(SUCCESS_SIGNOUT),
            html=lambda: flash_and_redirect(request, SUCCESS_SIGNOUT, "auth:signin"),
        )


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_ACCOUNT, method="POST", block=False),
    name="dispatch",
)
class AccountBaseView(MainSiteRedirectMixin, RatelimitGateMixin, SessionAuthRequiredMixin, View):
    """
    Shared authentication gate, rate limiting, and helpers for the account
    pages (view page, password change, account deletion).

    The session auth gate and user resolution come from
    ``SessionAuthRequiredMixin``; the POST rate-limit gate from
    ``RatelimitGateMixin`` layers on top. ``RatelimitGateMixin`` sits first in
    the MRO, so its ``dispatch`` checks the rate limit before deferring to the
    authentication gate.
    """

    template_name = TEMPLATE_ACCOUNT
    ratelimit_redirect = "auth:account"

    def _account_context(self, user, password_form, deletion_form) -> dict:
        """Build the shared template context for the account page."""
        return {
            "user_obj": user,
            "password_form": password_form,
            "deletion_form": deletion_form,
            "auth_data_json": {
                "user_id": user.user_id,
                "auth_salt": user.auth_salt,
                "vault_salt": user.vault_salt,
            },
        }

    def render_account(
        self, request: HttpRequest, user, password_form, deletion_form, *, status=200
    ) -> HttpResponse:
        """Render the account page with both forms in one consistent shape."""
        return render(
            request,
            self.template_name,
            self._account_context(user, password_form, deletion_form),
            status=status,
        )

    def account_form_error_response(
        self,
        request: HttpRequest,
        user,
        password_form,
        deletion_form,
        *,
        errored: str,
        status=400,
    ) -> HttpResponse:
        """Return account-form validation errors for AJAX and non-AJAX callers.

        ``errored`` selects which bound form (``"password"`` or ``"deletion"``)
        supplies the AJAX validation message; both forms are always rendered
        back into the HTML account page regardless.
        """
        form = password_form if errored == "password" else deletion_form
        return ajax_or_html(
            request,
            ajax=lambda: json_form_error(form, status=status),
            html=lambda: self.render_account(
                request, user, password_form, deletion_form, status=status
            ),
        )


class AccountView(AccountBaseView):
    """
    Display the account management page.

    Requires authentication. Shows the password change and account deletion
    forms; the form submissions are handled by their own views.
    """

    def get(self, request: HttpRequest) -> HttpResponse:
        user = self.get_authenticated_user(request)
        if not user:
            return self.handle_missing_user(request)

        return self.render_account(
            request,
            user,
            PasswordChangeForm(user=user),
            AccountDeletionForm(user=user),
        )


class PasswordChangeView(AccountBaseView):
    """
    Handle password changes with automatic session regeneration.

    Requires authentication. Supports both AJAX and traditional submissions.
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        user = self.get_authenticated_user(request)
        if not user:
            return self.handle_missing_user(request)

        password_form = PasswordChangeForm(user=user, data=request.POST)
        deletion_form = AccountDeletionForm(user=user)

        if password_form.is_valid():
            _, new_auth_salt, new_vault_salt = services.change_user_auth_secret(
                user,
                new_auth_secret=password_form.cleaned_data["new_auth_secret"],
                auth_salt=password_form.cleaned_data["auth_salt"],
                vault_salt=password_form.cleaned_data["vault_salt"],
            )

            # Regenerate session to prevent session fixation
            services.regenerate_session_after_password_change(request, user)

            return ajax_or_html(
                request,
                ajax=lambda: json_ok(
                    SUCCESS_PASSWORD_CHANGED,
                    auth_salt=new_auth_salt,
                    vault_salt=new_vault_salt,
                    state=access_state(request, user, "pass"),
                ),
                html=lambda: flash_and_redirect(request, SUCCESS_PASSWORD_CHANGED, "auth:account"),
            )

        return self.account_form_error_response(
            request, user, password_form, deletion_form, errored="password"
        )


class AccountDeletionView(AccountBaseView):
    """
    Handle account deletion with confirmation.

    Requires authentication. Supports both AJAX and traditional submissions.
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        user = self.get_authenticated_user(request)
        if not user:
            return self.handle_missing_user(request)

        deletion_form = AccountDeletionForm(user=user, data=request.POST)
        password_form = PasswordChangeForm(user=user)

        if not deletion_form.is_valid():
            return self.account_form_error_response(
                request, user, password_form, deletion_form, errored="deletion"
            )

        try:
            services.delete_user_account(user)
        except Exception as exc:
            logger.error(LOG_ACCOUNT_DELETE_ERROR, user.user_id, exception_type(exc))
            return ajax_or_html(
                request,
                ajax=lambda: json_error(ERROR_ACCOUNT_DELETION_FAILED, status=500),
                html=lambda: self._render_deletion_error(
                    request, user, password_form, deletion_form
                ),
            )

        request.session.flush()
        return ajax_or_html(
            request,
            ajax=lambda: json_ok(SUCCESS_ACCOUNT_DELETED, redirect_url=reverse("auth:signup")),
            html=lambda: flash_and_redirect(request, SUCCESS_ACCOUNT_DELETED, "auth:signup"),
        )

    def _render_deletion_error(self, request, user, password_form, deletion_form) -> HttpResponse:
        """Flash deletion failure and render the account page."""
        messages.error(request, ERROR_ACCOUNT_DELETION_FAILED)
        return self.render_account(request, user, password_form, deletion_form, status=500)
