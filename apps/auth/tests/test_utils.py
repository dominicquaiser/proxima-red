"""Tests for the auth-specific view helpers in ``apps.auth.utils``.

These cover the session-auth contract (reading the user id, the API auth gate,
and the rate-limit response). The generic JSON/AJAX helpers moved to
``apps.core.http`` and are tested in ``apps.core.tests.test_http``.
"""

import json

from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import JsonResponse
from django.test import RequestFactory, SimpleTestCase

from apps.auth.constants import (
    ERROR_INVALID_SESSION,
    ERROR_NOT_AUTHENTICATED,
    ERROR_RATE_LIMITED,
)
from apps.auth.utils import (
    get_authenticated_user_id,
    ratelimited_response,
    require_session_auth_api,
)

AJAX_HEADERS = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}


def _body(response):
    """Decode a raw ``JsonResponse`` body into a dict."""
    return json.loads(response.content)


class GetAuthenticatedUserIdTests(SimpleTestCase):
    """get_authenticated_user_id returns the id only for an authenticated session."""

    def setUp(self):
        self.factory = RequestFactory()

    def _request(self, session):
        request = self.factory.get("/")
        request.session = session
        return request

    def test_returns_none_when_not_authenticated(self):
        request = self._request({"user_id": "12345678"})
        self.assertIsNone(get_authenticated_user_id(request))

    def test_returns_user_id_when_authenticated(self):
        request = self._request({"authenticated": True, "user_id": "12345678"})
        self.assertEqual(get_authenticated_user_id(request), "12345678")


class RequireSessionAuthApiTests(SimpleTestCase):
    """The API auth decorator returns JSON 401s instead of redirects."""

    def setUp(self):
        self.factory = RequestFactory()

        @require_session_auth_api
        def view(request):
            return JsonResponse({"success": True, "reached": True})

        self.view = view

    def _request(self, session):
        request = self.factory.get("/")
        request.session = session
        return request

    def test_unauthenticated_returns_401(self):
        response = self.view(self._request({}))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(_body(response)["error"], ERROR_NOT_AUTHENTICATED)

    def test_authenticated_without_user_id_returns_401(self):
        response = self.view(self._request({"authenticated": True}))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(_body(response)["error"], ERROR_INVALID_SESSION)

    def test_authenticated_calls_wrapped_view(self):
        request = self._request({"authenticated": True, "user_id": "12345678"})
        response = self.view(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(_body(response)["reached"])


class RatelimitedResponseTests(SimpleTestCase):
    """ratelimited_response answers AJAX with 429 JSON and others with a redirect."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_ajax_returns_429_json(self):
        request = self.factory.get("/", **AJAX_HEADERS)
        response = ratelimited_response(request, redirect_to="/after/")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(_body(response)["error"], ERROR_RATE_LIMITED)

    def test_non_ajax_redirects_with_flash_message(self):
        request = self.factory.get("/")
        request.session = {}
        request._messages = FallbackStorage(request)
        response = ratelimited_response(request, redirect_to="/after/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/after/")
        self.assertIn(ERROR_RATE_LIMITED, [str(m) for m in request._messages])
