"""Tests for the auth template context processor (``current_user``)."""

from django.test import RequestFactory, TestCase

from apps.auth.context_processors import current_user
from apps.auth.tests.factories import create_user_with_password


class CurrentUserContextProcessorTests(TestCase):
    """current_user resolves the session's User, or is falsy otherwise."""

    def setUp(self):
        self.factory = RequestFactory()

    def _request(self, session):
        request = self.factory.get("/")
        request.session = session
        return request

    def test_anonymous_session_has_no_current_user(self):
        """An unauthenticated session yields a falsy current_user."""
        context = current_user(self._request({}))
        self.assertFalse(context["current_user"])

    def test_authenticated_session_resolves_user(self):
        """An authenticated session resolves to the matching User."""
        user = create_user_with_password("TestPassword123!")
        session = {"authenticated": True, "user_id": user.user_id}

        context = current_user(self._request(session))

        self.assertEqual(context["current_user"].user_id, user.user_id)

    def test_session_pointing_at_missing_user_is_falsy(self):
        """An authenticated session for a deleted user yields a falsy value."""
        session = {"authenticated": True, "user_id": "99999999"}
        context = current_user(self._request(session))
        self.assertFalse(context["current_user"])
