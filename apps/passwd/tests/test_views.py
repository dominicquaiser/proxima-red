"""
Tests for the passwd app views.

Covers share creation/retrieval (anonymous, AJAX + non-AJAX), the
authenticated vault, the encrypted-data update endpoint, and the GDPR export.
All cryptography happens client-side, so these tests exercise the server's
storage/auth/expiry behaviour using opaque ciphertext stand-ins.
"""

import base64
import json
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.passwd.constants import (
    ERROR_CREATE_FAILED,
    ERROR_INVALID_JSON,
    ERROR_INVALID_IV,
    ERROR_MISSING_REQUIRED,
    ERROR_UNEXPECTED,
    ERROR_USER_NOT_FOUND,
    GCM_IV_LENGTH_BYTES,
    MAX_ENCRYPTED_DATA_LENGTH,
    RATE_LIMIT_EXPORT,
    RATE_LIMIT_VAULT,
)
from apps.passwd.models import ServiceData, SharedPassword

AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}


def make_share(**overrides):
    """Create a stored SharedPassword with sensible defaults."""
    data = {
        "encrypted_data": "ZW5jcnlwdGVk",
        "iv": "AAAAAAAAAAAAAAAA",
        "expires_at": timezone.now() + timedelta(days=1),
    }
    data.update(overrides)
    return SharedPassword.objects.create(**data)


class CreateShareViewTests(TestCase):
    """Test cases for CreateShareView."""

    def setUp(self):
        cache.clear()  # reset per-IP rate-limit counters between tests
        self.client = Client()
        self.url = reverse("passwd:create")

    def test_get_renders_form(self):
        """GET returns the create form."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/create.html")
        self.assertContains(response, 'name="encrypted_data"')
        self.assertNotContains(response, 'name="password"')

    def test_post_success_non_ajax_renders_success(self):
        """A valid non-AJAX POST stores the share and renders success."""
        response = self.client.post(
            self.url,
            {"encrypted_data": "Y2lwaGVy", "iv": "AAAAAAAAAAAAAAAA"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/success.html")
        self.assertEqual(SharedPassword.objects.count(), 1)
        self.assertIsNone(SharedPassword.objects.get().created_by)

    def test_post_success_ajax_returns_json(self):
        """A valid AJAX POST returns share details as JSON."""
        response = self.client.post(
            self.url,
            {
                "encrypted_data": "Y2lwaGVy",
                "iv": "AAAAAAAAAAAAAAAA",
                "encrypted_title": "dGl0bGU=",
                "title_iv": "BBBBBBBBBBBBBBBB",
            },
            **AJAX,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertIn("share_id", payload)
        self.assertEqual(payload["encrypted_title"], "dGl0bGU=")

        share = SharedPassword.objects.get(pk=payload["share_id"])
        self.assertEqual(share.encrypted_title, "dGl0bGU=")

    def test_post_missing_fields_ajax_errors(self):
        """A POST missing encrypted data/IV is rejected without storing."""
        response = self.client.post(self.url, {"encrypted_data": ""}, **AJAX)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(SharedPassword.objects.count(), 0)

    def test_post_legacy_password_field_is_rejected(self):
        """The visible plaintext field name is not accepted as ciphertext."""
        response = self.client.post(
            self.url,
            {"password": "plaintext secret", "iv": "AAAAAAAAAAAAAAAA"},
            **AJAX,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(SharedPassword.objects.count(), 0)

    def test_post_invalid_ciphertext_ajax_errors(self):
        """A malformed Base64 ciphertext is rejected before storage."""
        response = self.client.post(
            self.url,
            {"encrypted_data": "not base64!!", "iv": "AAAAAAAAAAAAAAAA"},
            **AJAX,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(SharedPassword.objects.count(), 0)

    def test_post_oversized_ciphertext_ajax_errors(self):
        """Payloads over the encrypted-data cap are rejected before storage."""
        response = self.client.post(
            self.url,
            {
                "encrypted_data": "A" * (MAX_ENCRYPTED_DATA_LENGTH + 1),
                "iv": "AAAAAAAAAAAAAAAA",
            },
            **AJAX,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(SharedPassword.objects.count(), 0)

    def test_post_wrong_iv_length_ajax_errors(self):
        """An IV must decode to exactly the AES-GCM IV length."""
        short_iv = base64.b64encode(b"\x00" * (GCM_IV_LENGTH_BYTES - 1)).decode("utf-8")
        response = self.client.post(
            self.url, {"encrypted_data": "Y2lwaGVy", "iv": short_iv}, **AJAX
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(SharedPassword.objects.count(), 0)

    def test_post_expiry_is_applied(self):
        """The chosen expiry option determines expires_at (~1 hour)."""
        before = timezone.now()
        response = self.client.post(
            self.url,
            {
                "encrypted_data": "Y2lwaGVy",
                "iv": "AAAAAAAAAAAAAAAA",
                "expiry_time": "1hour",
            },
            **AJAX,
        )
        self.assertEqual(response.status_code, 200)
        share = SharedPassword.objects.get(pk=response.json()["share_id"])
        delta = share.expires_at - before
        self.assertGreater(delta, timedelta(minutes=55))
        self.assertLess(delta, timedelta(minutes=65))

    def test_storage_errors_are_logged_without_raw_exception_details(self):
        """An unexpected storage failure returns a generic 500 and sanitized logs."""
        raw_detail = "INSERT INTO passwd_sharedpassword failed"
        with self.assertLogs("apps.passwd.views", level="ERROR") as logs:
            with patch(
                "apps.passwd.views.services.create_share",
                side_effect=RuntimeError(raw_detail),
            ):
                response = self.client.post(
                    self.url,
                    {"encrypted_data": "Y2lwaGVy", "iv": "AAAAAAAAAAAAAAAA"},
                    **AJAX,
                )

        self.assertEqual(response.status_code, 500)
        body = response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], ERROR_CREATE_FAILED)
        self.assertEqual(SharedPassword.objects.count(), 0)
        log_output = "\n".join(logs.output)
        self.assertIn("RuntimeError", log_output)
        self.assertNotIn(raw_detail, log_output)
        self.assertNotIn("Traceback", log_output)

    def test_storage_error_non_ajax_renders_create_page_with_error(self):
        """A non-AJAX storage failure re-renders the create form with the error."""
        with self.assertLogs("apps.passwd.views", level="ERROR"):
            with patch(
                "apps.passwd.views.services.create_share",
                side_effect=RuntimeError("boom"),
            ):
                response = self.client.post(
                    self.url,
                    {"encrypted_data": "Y2lwaGVy", "iv": "AAAAAAAAAAAAAAAA"},
                )

        self.assertEqual(response.status_code, 500)
        self.assertTemplateUsed(response, "passwd/create.html")
        self.assertEqual(response.context["error"], ERROR_CREATE_FAILED)

    def test_authenticated_create_sets_share_owner(self):
        """Shares created during an authenticated session are linked to the user."""
        user = create_user_with_password("TestPassword123!")
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = user.user_id
        session.save()

        response = self.client.post(
            self.url,
            {"encrypted_data": "Y2lwaGVy", "iv": "AAAAAAAAAAAAAAAA"},
            **AJAX,
        )

        self.assertEqual(response.status_code, 200)
        share = SharedPassword.objects.get(pk=response.json()["share_id"])
        self.assertEqual(share.created_by, user)


class RetrieveShareViewTests(TestCase):
    """Test cases for RetrieveShareView."""

    def setUp(self):
        cache.clear()
        self.client = Client()

    def _url(self, pk):
        return reverse("passwd:retrieve", args=[pk])

    def test_retrieve_valid_share(self):
        """A valid share renders the retrieve template with its data."""
        share = make_share()
        response = self.client.get(self._url(share.id))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/retrieve.html")

    def test_retrieve_increments_access_count(self):
        """Each retrieval increments the access counter atomically."""
        share = make_share()
        self.client.get(self._url(share.id))
        self.client.get(self._url(share.id))

        share.refresh_from_db()
        self.assertEqual(share.access_count, 2)

    def test_retrieve_expired_deletes_only_that_share_and_renders_expired(self):
        """Opening an expired share deletes that share and shows the expired page.

        Other expired rows are left for the out-of-band ``delete_expired`` cron
        sweep — they are not pruned on this request path.
        """
        share = make_share(expires_at=timezone.now() - timedelta(minutes=1))
        other_expired = make_share(expires_at=timezone.now() - timedelta(minutes=1))
        live = make_share(expires_at=timezone.now() + timedelta(minutes=1))
        response = self.client.get(self._url(share.id))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/expired.html")
        self.assertFalse(SharedPassword.objects.filter(pk=share.id).exists())
        self.assertTrue(SharedPassword.objects.filter(pk=other_expired.id).exists())
        self.assertTrue(SharedPassword.objects.filter(pk=live.id).exists())

    def test_retrieve_live_share_leaves_other_expired_rows(self):
        """A live retrieval does not prune unrelated expired shares.

        Bulk cleanup is the cron job's responsibility, kept off this hot path;
        the retrieved share is served and other rows are left untouched.
        """
        share = make_share()
        expired = make_share(expires_at=timezone.now() - timedelta(minutes=1))

        response = self.client.get(self._url(share.id))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/retrieve.html")
        self.assertTrue(SharedPassword.objects.filter(pk=share.id).exists())
        self.assertTrue(SharedPassword.objects.filter(pk=expired.id).exists())

    def test_retrieve_unknown_returns_404(self):
        """An unknown share id returns 404."""
        response = self.client.get(self._url(uuid.uuid4()))
        self.assertEqual(response.status_code, 404)


class VaultViewTests(TestCase):
    """Test cases for VaultView (session-authenticated)."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.url = reverse("passwd:vault")
        self.user = create_user_with_password("TestPassword123!")

    def _authenticate(self):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = self.user.user_id
        session.save()

    def test_requires_authentication(self):
        """Unauthenticated requests are redirected to signin."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)

    def test_authenticated_without_data_renders_empty_vault(self):
        """An authenticated user with no stored data sees the vault."""
        self._authenticate()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/vault.html")

    def test_authenticated_with_data_passes_encrypted_blob(self):
        """Stored ServiceData is surfaced (with Base64-encoded IV) to the page."""
        ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        self._authenticate()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        user_data = response.context["user_data_json"]
        self.assertEqual(user_data["encrypted_data"], "ZW5jcnlwdGVk")
        self.assertEqual(user_data["iv"], "AAAAAAAAAAAAAAAA")  # b"\x00" * 12 in base64

    def test_rate_limited_returns_403(self):
        """Requests past RATE_LIMIT_VAULT in one window are blocked with 403."""
        self._authenticate()
        limit = int(RATE_LIMIT_VAULT.split("/")[0])
        for _ in range(limit):
            self.client.get(self.url)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)


class VaultDataViewTests(TestCase):
    """Test cases for VaultDataView (the JSON read endpoint used by migration)."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.url = reverse("passwd:vault_data")
        self.user = create_user_with_password("TestPassword123!")

    def _authenticate(self):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = self.user.user_id
        session.save()

    def test_requires_authentication(self):
        """Unauthenticated requests get a JSON 401."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["success"])

    def test_returns_empty_when_no_data(self):
        """An authenticated user with no stored vault gets success and no blob."""
        self._authenticate()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertNotIn("encrypted_data", payload)

    def test_returns_encrypted_blob(self):
        """Stored ServiceData is returned with a Base64-encoded IV."""
        ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        self._authenticate()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertEqual(payload["encrypted_data"], "ZW5jcnlwdGVk")
        self.assertEqual(payload["iv"], "AAAAAAAAAAAAAAAA")  # b"\x00" * 12 in base64

    def test_session_for_deleted_user_returns_404(self):
        """A session whose user was deleted mid-session gets a JSON 404."""
        self._authenticate()
        self.user.delete()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)
        body = response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], ERROR_USER_NOT_FOUND)


class UpdateEncryptedDataViewTests(TestCase):
    """Test cases for UpdateEncryptedDataView."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.url = reverse("passwd:update_data")
        self.user = create_user_with_password("TestPassword123!")

    def _authenticate(self):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = self.user.user_id
        session.save()

    def _post(self, body):
        return self.client.post(
            self.url, data=json.dumps(body), content_type="application/json"
        )

    def test_requires_authentication(self):
        """Unauthenticated requests get a JSON 401."""
        response = self._post({"encrypted_data": "x", "iv": "AAAAAAAAAAAAAAAA"})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["success"])

    def test_creates_service_data(self):
        """A valid POST creates the user's ServiceData."""
        self._authenticate()
        response = self._post(
            {"encrypted_data": "ZW5jcnlwdGVk", "iv": "AAAAAAAAAAAAAAAA"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])

        data = ServiceData.objects.get(user=self.user)
        self.assertEqual(data.encrypted_data, "ZW5jcnlwdGVk")
        self.assertEqual(bytes(data.iv), b"\x00" * 12)

    def test_updates_existing_service_data(self):
        """A second POST updates rather than duplicates ServiceData."""
        ServiceData.objects.create(
            user=self.user, encrypted_data="b2xk", iv=b"\x01" * 12
        )
        self._authenticate()
        response = self._post({"encrypted_data": "bmV3", "iv": "AAAAAAAAAAAAAAAA"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ServiceData.objects.filter(user=self.user).count(), 1)
        self.assertEqual(ServiceData.objects.get(user=self.user).encrypted_data, "bmV3")

    def test_missing_fields_rejected(self):
        """A POST missing required fields is rejected."""
        self._authenticate()
        response = self._post({"encrypted_data": "ZW5jcnlwdGVk"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])

    def test_whitespace_only_fields_rejected(self):
        """Fields that are present but blank count as missing."""
        self._authenticate()
        for body in (
            {"encrypted_data": "   ", "iv": "AAAAAAAAAAAAAAAA"},
            {"encrypted_data": "ZW5jcnlwdGVk", "iv": "   "},
        ):
            with self.subTest(body=body):
                response = self._post(body)
                self.assertEqual(response.status_code, 400)
                self.assertFalse(response.json()["success"])
                self.assertEqual(response.json()["error"], ERROR_MISSING_REQUIRED)
        self.assertFalse(ServiceData.objects.filter(user=self.user).exists())

    def test_session_for_deleted_user_returns_404(self):
        """A session whose user was deleted mid-session gets a JSON 404."""
        self._authenticate()
        self.user.delete()
        response = self._post(
            {"encrypted_data": "ZW5jcnlwdGVk", "iv": "AAAAAAAAAAAAAAAA"}
        )
        self.assertEqual(response.status_code, 404)
        body = response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], ERROR_USER_NOT_FOUND)
        self.assertFalse(ServiceData.objects.exists())

    def test_invalid_iv_rejected(self):
        """A POST with a malformed Base64 IV is rejected."""
        self._authenticate()
        response = self._post({"encrypted_data": "ZW5jcnlwdGVk", "iv": "abc"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["error"], ERROR_INVALID_IV)
        self.assertNotIn("Base64", response.json()["error"])
        self.assertNotIn("padding", response.json()["error"].lower())

    def test_invalid_encrypted_data_rejected(self):
        """A POST with malformed ciphertext is rejected."""
        self._authenticate()
        response = self._post(
            {"encrypted_data": "not base64!!", "iv": "AAAAAAAAAAAAAAAA"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertFalse(ServiceData.objects.filter(user=self.user).exists())

    def test_wrong_iv_length_rejected(self):
        """A Base64 IV with the wrong decoded byte length is rejected."""
        self._authenticate()
        short_iv = base64.b64encode(b"\x00" * (GCM_IV_LENGTH_BYTES - 1)).decode("utf-8")
        response = self._post({"encrypted_data": "ZW5jcnlwdGVk", "iv": short_iv})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertFalse(ServiceData.objects.filter(user=self.user).exists())

    def test_invalid_json_rejected(self):
        """A POST with a malformed JSON body is rejected."""
        self._authenticate()
        response = self.client.post(
            self.url, data="{not json", content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["error"], ERROR_INVALID_JSON)

    def test_non_object_json_rejected(self):
        """A JSON value that is not an object is rejected before field access."""
        self._authenticate()
        response = self._post(["not", "an", "object"])
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["error"], ERROR_INVALID_JSON)
        self.assertFalse(ServiceData.objects.filter(user=self.user).exists())

    def test_non_string_payload_fields_rejected(self):
        """Vault ciphertext and IV fields must be strings."""
        self._authenticate()
        response = self._post({"encrypted_data": 123, "iv": "AAAAAAAAAAAAAAAA"})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])
        self.assertEqual(response.json()["error"], ERROR_INVALID_JSON)
        self.assertFalse(ServiceData.objects.filter(user=self.user).exists())

    def test_storage_errors_are_logged_without_raw_exception_details(self):
        """Unexpected storage failures return a generic error and sanitized logs."""
        self._authenticate()
        raw_detail = "SELECT encrypted_data FROM passwd_servicedata"
        with self.assertLogs("apps.passwd.views", level="ERROR") as logs:
            with patch(
                "apps.passwd.views.services.save_user_vault_data",
                side_effect=RuntimeError(raw_detail),
            ):
                response = self._post(
                    {"encrypted_data": "ZW5jcnlwdGVk", "iv": "AAAAAAAAAAAAAAAA"}
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], ERROR_UNEXPECTED)
        log_output = "\n".join(logs.output)
        self.assertIn("RuntimeError", log_output)
        self.assertNotIn(raw_detail, log_output)
        self.assertNotIn("Traceback", log_output)


class DataExportViewTests(TestCase):
    """Test cases for DataExportView (GDPR export)."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.url = reverse("passwd:export_data")
        self.user = create_user_with_password("TestPassword123!")

    def _authenticate(self):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = self.user.user_id
        session.save()

    def test_requires_authentication(self):
        """Unauthenticated requests are redirected to signin."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)

    def test_export_without_vault(self):
        """The export returns account data with a null vault when none exists."""
        self._authenticate()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("attachment", response["Content-Disposition"])

        payload = json.loads(response.content)
        self.assertEqual(payload["account"]["user_id"], self.user.user_id)
        self.assertIsNone(payload["vault"])

    def test_export_with_vault(self):
        """The export includes the encrypted vault blob when present."""
        ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        self._authenticate()
        response = self.client.get(self.url)

        payload = json.loads(response.content)
        self.assertIsNotNone(payload["vault"])
        self.assertEqual(payload["vault"]["encrypted_data"], "ZW5jcnlwdGVk")
        self.assertEqual(payload["vault"]["iv"], "AAAAAAAAAAAAAAAA")

    def test_session_for_deleted_user_redirects_to_signin(self):
        """A session whose user was deleted mid-session is flushed and redirected."""
        self._authenticate()
        self.user.delete()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_rate_limited_returns_403(self):
        """Requests past RATE_LIMIT_EXPORT in one window are blocked with 403."""
        self._authenticate()
        limit = int(RATE_LIMIT_EXPORT.split("/")[0])
        for _ in range(limit):
            self.client.get(self.url)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)
