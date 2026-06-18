"""
Reusable class-based-view mixins for session authentication.

These centralize the "require an authenticated session and resolve its user"
pattern shared by the account pages and the passwd data-export view, so the
gate logic lives in one place instead of being duplicated per view.
"""

import logging
from urllib.parse import urlparse

from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect

from .constants import (
    ERROR_SESSION_EXPIRED,
    LOG_SESSION_MISSING_USER,
    SESSION_KEY_AUTHENTICATED,
    SUCCESS_PLEASE_SIGNIN,
)
from .services import get_user_by_id
from .utils import get_authenticated_user_id, ratelimited_response

logger = logging.getLogger(__name__)


class PassSubdomainRedirectMixin:
    """Send safe-method requests to the pass subdomain when one is configured.

    The authenticated vault is served on ``PASS_SITE_URL``. Its AES key is
    derived from the password at sign-in and held in ``sessionStorage``, which is
    scoped to a single origin and cannot be shared across subdomains. So the
    whole authenticated flow (sign in, sign up, account) must run on the pass
    origin, or the vault page won't see the key the user just established and
    reports "Secure session expired".

    This mixin redirects a GET/HEAD auth page reached on the main host to the
    same path on the pass host, *before* any key is derived. POSTs are left
    alone (the form already loaded on, and posts back to, the pass origin).
    """

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        return self._redirect_to_pass_subdomain(request) or super().dispatch(
            request, *args, **kwargs
        )

    @staticmethod
    def _redirect_to_pass_subdomain(request: HttpRequest):
        """Return a redirect to the pass host for off-host GETs, else ``None``."""
        if request.method not in ("GET", "HEAD"):
            return None
        pass_host = urlparse(settings.PASS_SITE_URL).hostname
        main_host = urlparse(settings.SITE_URL).hostname
        # No distinct subdomain configured (single-domain / dev / tests).
        if not pass_host or pass_host == main_host:
            return None
        if request.get_host().split(":")[0] == pass_host:
            return None
        return redirect(f"{settings.PASS_SITE_URL}{request.get_full_path()}")


class SessionAuthRequiredMixin:
    """
    Enforce session authentication for a class-based view.

    - ``dispatch`` redirects unauthenticated requests to the signin page.
    - ``get_authenticated_user`` resolves the session's user (or ``None`` when
      the session is unauthenticated or references a missing user).
    - ``handle_missing_user`` flushes the session and redirects when the session
      is authenticated but its user no longer exists in the database.

    Subclasses that need extra ``dispatch`` behaviour (e.g. rate limiting) can
    override ``dispatch`` and call ``super().dispatch(...)``.
    """

    signin_url = "auth:signin"

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not request.session.get(SESSION_KEY_AUTHENTICATED):
            messages.info(request, SUCCESS_PLEASE_SIGNIN)
            return redirect(self.signin_url)
        return super().dispatch(request, *args, **kwargs)

    def get_authenticated_user(self, request: HttpRequest):
        """Return the session's ``User``, or ``None`` if unresolved."""
        user_id = get_authenticated_user_id(request)
        if not user_id:
            return None

        user = get_user_by_id(user_id)
        if not user:
            logger.warning(LOG_SESSION_MISSING_USER, user_id)
        return user

    def handle_missing_user(self, request: HttpRequest) -> HttpResponse:
        """Flush the session and redirect when the session has no valid user."""
        request.session.flush()
        messages.error(request, ERROR_SESSION_EXPIRED)
        return redirect(self.signin_url)


class RatelimitGateMixin:
    """
    Translate a ``django-ratelimit`` block into an on-brand response in
    ``dispatch``.

    The rate-limit decorators run with ``block=False`` so the view can return a
    helpful JSON 429 / redirect instead of Django's generic 403. A view applies
    the ``@ratelimit`` decorator at the class level with ``name="dispatch"`` (the
    rates/methods differ per view, so the decorator stays per-view) and sets
    ``ratelimit_redirect`` to the URL name for the non-AJAX redirect::

        @method_decorator(
            ratelimit(key=client_ip_key, rate=..., method="POST", block=False),
            name="dispatch",
        )
        class MyView(RatelimitGateMixin, View):
            ratelimit_redirect = "auth:signin"

    This mixin's ``dispatch`` then short-circuits to the rate-limited response
    when ``request.limited`` is set and otherwise defers to ``super().dispatch``,
    so subclasses no longer reimplement that wiring. See
    :func:`apps.auth.utils.ratelimited_response` for the response shape.
    """

    # URL name for the non-AJAX redirect; concrete views set this.
    ratelimit_redirect = None

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        """Return the rate-limited response when blocked, else dispatch normally."""
        return self.handle_ratelimited(request) or super().dispatch(
            request, *args, **kwargs
        )

    def handle_ratelimited(self, request: HttpRequest):
        """Return a 429/redirect response when the request was rate limited, else None."""
        if getattr(request, "limited", False):
            return ratelimited_response(request, redirect_to=self.ratelimit_redirect)
        return None
