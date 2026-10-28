"""Tests for the auth template context processors."""

from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from apps.auth.context_processors import current_user, host_tool
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


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    NOTE_SITE_URL="https://note.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "note.proxima.red"],
)
class HostToolContextProcessorTests(SimpleTestCase):
    """host_tool names the vault the shared header's auth links land on."""

    def setUp(self):
        self.factory = RequestFactory()

    def _host_tool(self, host):
        return host_tool(self.factory.get("/", HTTP_HOST=host))["host_tool"]

    def test_note_host_lands_on_the_note_vault(self):
        self.assertEqual(self._host_tool("note.proxima.red"), "note")

    def test_other_hosts_land_on_the_default_vault(self):
        self.assertEqual(self._host_tool("pass.proxima.red"), "pass")
        self.assertEqual(self._host_tool("proxima.red"), "pass")

    def test_disallowed_host_falls_back_instead_of_raising(self):
        """The error page for a junk Host header renders the same header."""
        self.assertEqual(self._host_tool("evil.example"), "pass")
