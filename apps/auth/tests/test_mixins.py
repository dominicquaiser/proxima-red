"""Tests for the session-auth view mixins in ``apps.auth.mixins``.

The dispatch gate and the missing-user recovery path are exercised end-to-end
through the account views in ``test_views``; this covers the direct
``get_authenticated_user`` contract for sessions that cannot be resolved.
"""

from django.test import RequestFactory, SimpleTestCase

from apps.auth.mixins import SessionAuthRequiredMixin


class GetAuthenticatedUserTests(SimpleTestCase):
    """get_authenticated_user resolves the session's user or returns None."""

    def setUp(self):
        self.factory = RequestFactory()
        self.mixin = SessionAuthRequiredMixin()

    def test_returns_none_when_session_has_no_user_id(self):
        """An authenticated session without a user_id resolves to None."""
        request = self.factory.get("/")
        request.session = {"authenticated": True}
        self.assertIsNone(self.mixin.get_authenticated_user(request))
