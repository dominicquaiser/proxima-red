"""
Authentication views for user signup, signin, signout, and account management.

This module provides class-based views for handling user authentication
and account operations with support for both traditional form submissions
and AJAX requests.
"""

import logging

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

from .exceptions import UserCreationError
from .mixins import RatelimitGateMixin, SessionAuthRequiredMixin
from .models import is_valid_user_id
from .forms import (
    SignupForm,
    SigninForm,
    PasswordChangeForm,
    AccountDeletionForm,
)
from . import services
from .constants import (
    RATE_LIMIT_SIGNUP,
    RATE_LIMIT_SIGNIN,
    RATE_LIMIT_ACCOUNT,
    SESSION_KEY_AUTHENTICATED,
    TEMPLATE_SIGNUP,
    TEMPLATE_SIGNIN,
    TEMPLATE_ACCOUNT,
    ERROR_UNEXPECTED,
    ERROR_USER_CREATION_FAILED,
    ERROR_ACCOUNT_DELETION_FAILED,
    ERROR_INVALID_CREDENTIALS,
    ERROR_INVALID_USER_ID,
    SUCCESS_ACCOUNT_CREATED,
    SUCCESS_USER_CREATED,
    SUCCESS_SIGNIN,
    SUCCESS_SIGNOUT,
    SUCCESS_PASSWORD_CHANGED,
    SUCCESS_ACCOUNT_DELETED,
    LOG_ACCOUNT_DELETE_ERROR,
    LOG_SIGNIN_ERROR,
    LOG_SIGNUP_ERROR,
)

logger = logging.getLogger(__name__)


class AuthFormView(RatelimitGateMixin, View):
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

    def redirect_if_authenticated(self, request: HttpRequest):
        """Return a redirect to the vault for an already-authenticated session, else None."""
        if request.session.get(SESSION_KEY_AUTHENTICATED):
            return redirect("passwd:vault")
        return None

    def get(self, request: HttpRequest) -> HttpResponse:
        """Display the form, or redirect to the vault when already authenticated."""
        return self.redirect_if_authenticated(request) or render(
            request, self.template_name, {"form": self.form_class()}
        )

    def render_form(
        self, request: HttpRequest, form=None, *, status: int | None = None
    ) -> HttpResponse:
        """Render this view's form template with an optional bound form."""
        kwargs = {"status": status} if status is not None else {}
        return render(
            request,
            self.template_name,
            {"form": form or self.form_class()},
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

    def _html_exception_response(
        self, request: HttpRequest, message: str
    ) -> HttpResponse:
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

        user = self._create_user_or_error(request, form.cleaned_data)
        if isinstance(user, HttpResponse):
            return user

        return self._success_response(request, user)

    def _create_user_or_error(self, request: HttpRequest, cleaned_data: dict):
        """Create a user or return the appropriate error response."""
        try:
            return services.create_user_with_auth_secret(
                cleaned_data["auth_secret"],
                auth_salt=cleaned_data["auth_salt"],
                vault_salt=cleaned_data["vault_salt"],
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
    account-existence oracle — neither directly nor by comparing repeated calls.
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

        return ajax_or_html(
            request,
            ajax=lambda: json_ok(
                SUCCESS_SIGNIN,
                auth_salt=user.auth_salt,
                vault_salt=user.vault_salt,
                redirect_url=reverse("passwd:vault"),
            ),
            html=lambda: redirect("passwd:vault"),
        )


@method_decorator(
    ratelimit(key=client_ip_key, rate=RATE_LIMIT_ACCOUNT, method="POST", block=False),
    name="dispatch",
)
class SignoutView(RatelimitGateMixin, View):
    """
    Sign out view to destroy user session.

    POST-only: signing out flushes the server session, so it must be a
    CSRF-protected state change — a GET handler would let any third-party
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
class AccountBaseView(RatelimitGateMixin, SessionAuthRequiredMixin, View):
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
            services.regenerate_session_after_password_change(request)

            return ajax_or_html(
                request,
                ajax=lambda: json_ok(
                    SUCCESS_PASSWORD_CHANGED,
                    auth_salt=new_auth_salt,
                    vault_salt=new_vault_salt,
                ),
                html=lambda: flash_and_redirect(
                    request, SUCCESS_PASSWORD_CHANGED, "auth:account"
                ),
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
            ajax=lambda: json_ok(
                SUCCESS_ACCOUNT_DELETED, redirect_url=reverse("auth:signup")
            ),
            html=lambda: flash_and_redirect(
                request, SUCCESS_ACCOUNT_DELETED, "auth:signup"
            ),
        )

    def _render_deletion_error(
        self, request, user, password_form, deletion_form
    ) -> HttpResponse:
        """Flash deletion failure and render the account page."""
        messages.error(request, ERROR_ACCOUNT_DELETION_FAILED)
        return self.render_account(
            request, user, password_form, deletion_form, status=500
        )
