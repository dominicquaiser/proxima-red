"""Tests for the shared HTTP helpers in ``apps.core.http``.

These are pure request/response helpers (no database access), so the tests
build lightweight requests with ``RequestFactory`` and use ``SimpleTestCase``.
The ``json_*`` helpers return raw ``JsonResponse`` objects, so their bodies are
decoded with :func:`_body` rather than the test client's ``.json()``.
"""

import json

from django import forms
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.core.http import (
    ajax_or_html,
    client_ip_key,
    get_client_ip,
    get_first_form_error,
    get_form_errors,
    is_ajax_request,
    json_error,
    json_form_error,
    json_ok,
)

AJAX_HEADERS = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}


class _RequiredFieldForm(forms.Form):
    """Minimal form with one required field, used to drive the error helpers."""

    name = forms.CharField()


def _body(response):
    """Decode a raw ``JsonResponse`` body into a dict."""
    return json.loads(response.content)


class IsAjaxRequestTests(SimpleTestCase):
    """is_ajax_request keys off the X-Requested-With header."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_true_for_xhr_header(self):
        request = self.factory.get("/", **AJAX_HEADERS)
        self.assertTrue(is_ajax_request(request))

    def test_false_without_header(self):
        request = self.factory.get("/")
        self.assertFalse(is_ajax_request(request))


class AjaxOrHtmlTests(SimpleTestCase):
    """ajax_or_html selects the response factory from the request type."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_uses_ajax_factory_for_xhr(self):
        request = self.factory.get("/", **AJAX_HEADERS)

        response = ajax_or_html(
            request,
            ajax=lambda: HttpResponse("ajax", status=202),
            html=lambda: HttpResponse("html"),
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.content, b"ajax")

    def test_uses_html_factory_without_xhr(self):
        request = self.factory.get("/")

        response = ajax_or_html(
            request,
            ajax=lambda: HttpResponse("ajax"),
            html=lambda: HttpResponse("html", status=203),
        )

        self.assertEqual(response.status_code, 203)
        self.assertEqual(response.content, b"html")


class GetClientIpTests(SimpleTestCase):
    """get_client_ip resolves the real client IP honouring trusted proxies."""

    def setUp(self):
        self.factory = RequestFactory()

    @override_settings(RATELIMIT_TRUSTED_PROXY_COUNT=0)
    def test_no_trusted_proxy_uses_remote_addr(self):
        """With no trusted proxy, REMOTE_ADDR is authoritative and XFF ignored."""
        request = self.factory.get(
            "/", REMOTE_ADDR="10.0.0.5", HTTP_X_FORWARDED_FOR="1.2.3.4"
        )
        self.assertEqual(get_client_ip(request), "10.0.0.5")

    @override_settings(RATELIMIT_TRUSTED_PROXY_COUNT=1)
    def test_one_trusted_proxy_uses_last_xff_entry(self):
        """One proxy: the real client is the entry the proxy appended (rightmost)."""
        request = self.factory.get(
            "/",
            REMOTE_ADDR="172.18.0.2",  # the nginx container
            HTTP_X_FORWARDED_FOR="203.0.113.7",
        )
        self.assertEqual(get_client_ip(request), "203.0.113.7")

    @override_settings(RATELIMIT_TRUSTED_PROXY_COUNT=1)
    def test_spoofed_leading_xff_entry_is_ignored(self):
        """A client-supplied (spoofed) leading XFF entry doesn't change the bucket."""
        request = self.factory.get(
            "/",
            REMOTE_ADDR="172.18.0.2",
            # Attacker sent "1.1.1.1"; nginx appended the true client address.
            HTTP_X_FORWARDED_FOR="1.1.1.1, 203.0.113.7",
        )
        self.assertEqual(get_client_ip(request), "203.0.113.7")

    @override_settings(RATELIMIT_TRUSTED_PROXY_COUNT=2)
    def test_two_trusted_proxies_use_second_from_right(self):
        """Two proxies: skip both appended hops to reach the real client."""
        request = self.factory.get(
            "/",
            REMOTE_ADDR="172.18.0.2",
            HTTP_X_FORWARDED_FOR="203.0.113.7, 198.51.100.9",
        )
        self.assertEqual(get_client_ip(request), "203.0.113.7")

    @override_settings(RATELIMIT_TRUSTED_PROXY_COUNT=1)
    def test_missing_xff_falls_back_to_remote_addr(self):
        """A trusted proxy is configured but no XFF arrived: fall back safely."""
        request = self.factory.get("/", REMOTE_ADDR="172.18.0.2")
        self.assertEqual(get_client_ip(request), "172.18.0.2")

    @override_settings(RATELIMIT_TRUSTED_PROXY_COUNT=1)
    def test_client_ip_key_delegates_to_get_client_ip(self):
        """The ratelimit key function returns the resolved client IP."""
        request = self.factory.get(
            "/", REMOTE_ADDR="172.18.0.2", HTTP_X_FORWARDED_FOR="203.0.113.7"
        )
        self.assertEqual(client_ip_key("group", request), "203.0.113.7")


class FormErrorHelperTests(SimpleTestCase):
    """get_first_form_error surfaces the first message, with a generic fallback."""

    def test_returns_first_error_message(self):
        form = _RequiredFieldForm(data={})
        self.assertEqual(get_first_form_error(form), "This field is required.")

    def test_fallback_when_no_errors(self):
        form = _RequiredFieldForm(data={"name": "ok"})
        self.assertEqual(get_first_form_error(form), "Invalid form data")

    def test_get_form_errors_returns_field_lists(self):
        form = _RequiredFieldForm(data={})
        self.assertEqual(get_form_errors(form), {"name": ["This field is required."]})


class JsonResponseHelperTests(SimpleTestCase):
    """json_ok / json_error / json_form_error build the standard envelopes."""

    def test_json_ok_minimal(self):
        response = json_ok()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(_body(response), {"success": True})

    def test_json_ok_with_message_and_extra_fields(self):
        response = json_ok("Saved", salt="abc", status=201)
        self.assertEqual(response.status_code, 201)
        body = _body(response)
        self.assertTrue(body["success"])
        self.assertEqual(body["message"], "Saved")
        self.assertEqual(body["salt"], "abc")

    def test_json_error_defaults_to_400(self):
        response = json_error("Boom")
        self.assertEqual(response.status_code, 400)
        body = _body(response)
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], "Boom")

    def test_json_error_custom_status(self):
        response = json_error("Nope", status=500)
        self.assertEqual(response.status_code, 500)

    def test_json_form_error_uses_first_error(self):
        response = json_form_error(_RequiredFieldForm(data={}))
        self.assertEqual(response.status_code, 400)
        body = _body(response)
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], "This field is required.")
        self.assertEqual(body["errors"], {"name": ["This field is required."]})
