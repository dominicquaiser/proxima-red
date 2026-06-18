"""Tests for the authentication views."""

import base64
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth.hashers import check_password
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from apps.auth.constants import (
    ERROR_ACCOUNT_DELETION_FAILED,
    ERROR_INVALID_USER_ID,
    ERROR_RATE_LIMITED,
    ERROR_UNEXPECTED,
    ERROR_USER_CREATION_FAILED,
)
from apps.auth.exceptions import UserCreationError
from apps.auth.models import User
from apps.auth.views import vault_url
from apps.auth.tests.factories import create_user_with_password
from apps.passwd.models import SharedPassword

AUTH_SECRET = base64.b64encode(b"a" * 32).decode()
NEW_AUTH_SECRET = base64.b64encode(b"b" * 32).decode()
WRONG_AUTH_SECRET = base64.b64encode(b"c" * 32).decode()
AUTH_SALT = base64.b64encode(b"d" * 32).decode()
VAULT_SALT = base64.b64encode(b"e" * 32).decode()
NEW_AUTH_SALT = base64.b64encode(b"f" * 32).decode()
NEW_VAULT_SALT = base64.b64encode(b"g" * 32).decode()


class SignupViewTests(TestCase):
    """Test cases for SignupView."""

    def setUp(self):
        """Set up test client."""
        cache.clear()  # reset per-IP rate-limit counters between tests
        self.client = Client()
        self.signup_url = reverse("auth:signup")

    def test_signup_get(self):
        """Test GET request to signup page."""
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "password")

    def test_signup_post_success(self):
        """Test successful user signup."""
        response = self.client.post(
            self.signup_url,
            {
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
            },
        )

        # Should redirect to signin
        self.assertEqual(response.status_code, 302)

        # User should be created
        self.assertEqual(User.objects.count(), 1)

    def test_signup_post_invalid(self):
        """Test signup with invalid data."""
        response = self.client.post(
            self.signup_url,
            {
                "auth_secret": "not-base64",
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
            },
        )

        # Should return to form with errors
        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.count(), 0)

    def test_signup_post_ajax_returns_user_id_and_salt(self):
        """An AJAX signup returns the new user_id and salt as JSON."""
        response = self.client.post(
            self.signup_url,
            {
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["success"])
        self.assertIn("user_id", body)
        self.assertIn("vault_salt", body)
        self.assertIn("auth_salt", body)
        self.assertEqual(User.objects.count(), 1)

    def _authenticate_session(self):
        session = self.client.session
        session["authenticated"] = True
        session.save()

    def test_signup_get_redirects_when_authenticated(self):
        """An already-authenticated session is sent to the vault instead."""
        self._authenticate_session()
        response = self.client.get(self.signup_url)
        self.assertRedirects(
            response, vault_url(), fetch_redirect_response=False
        )

    def test_signup_post_redirects_when_authenticated(self):
        """An authenticated POST is redirected without creating a user."""
        self._authenticate_session()
        response = self.client.post(
            self.signup_url,
            {
                "auth_secret": AUTH_SECRET,
                "auth_salt": AUTH_SALT,
                "vault_salt": VAULT_SALT,
            },
        )
        self.assertRedirects(
            response, vault_url(), fetch_redirect_response=False
        )
        self.assertEqual(User.objects.count(), 0)

    def test_signup_user_creation_error_returns_specific_message(self):
        """A UserCreationError maps to its own error message, not the generic one."""
        with self.assertLogs("apps.auth.views", level="ERROR"):
            with patch(
                "apps.auth.views.services.create_user_with_auth_secret",
                side_effect=UserCreationError("could not allocate user_id"),
            ):
                response = self.client.post(
                    self.signup_url,
                    {
                        "auth_secret": AUTH_SECRET,
                        "auth_salt": AUTH_SALT,
                        "vault_salt": VAULT_SALT,
                    },
                    HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], ERROR_USER_CREATION_FAILED)

    def test_signup_failure_non_ajax_flashes_error_and_renders_form(self):
        """A non-AJAX failure re-renders the signup form with a flashed error."""
        with self.assertLogs("apps.auth.views", level="ERROR"):
            with patch(
                "apps.auth.views.services.create_user_with_auth_secret",
                side_effect=RuntimeError("boom"),
            ):
                response = self.client.post(
                    self.signup_url,
                    {
                        "auth_secret": AUTH_SECRET,
                        "auth_salt": AUTH_SALT,
                        "vault_salt": VAULT_SALT,
                    },
                )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "auth/signup.html")
        flashed = [str(m) for m in response.context["messages"]]
        self.assertIn(ERROR_UNEXPECTED, flashed)

    def test_signup_storage_errors_are_logged_without_raw_exception_details(self):
        """Unexpected signup failures return a generic error and sanitized logs."""
        raw_detail = "duplicate key value violates unique constraint proxima_user"
        with self.assertLogs("apps.auth.views", level="ERROR") as logs:
            with patch(
                "apps.auth.views.services.create_user_with_auth_secret",
                side_effect=RuntimeError(raw_detail),
            ):
                response = self.client.post(
                    self.signup_url,
                    {
                        "auth_secret": AUTH_SECRET,
                        "auth_salt": AUTH_SALT,
                        "vault_salt": VAULT_SALT,
                    },
                    HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], ERROR_UNEXPECTED)
        log_output = "\n".join(logs.output)
        self.assertIn("RuntimeError", log_output)
        self.assertNotIn(raw_detail, log_output)
        self.assertNotIn("Traceback", log_output)


class SigninViewTests(TestCase):
    """Test cases for SigninView."""

    def setUp(self):
        """Set up test client and user."""
        cache.clear()  # reset per-IP rate-limit counters between tests
        self.client = Client()
        self.signin_url = reverse("auth:signin")
        self.salts_url = reverse("auth:salts")
        self.auth_secret = AUTH_SECRET
        self.user = create_user_with_password(self.auth_secret)

    def test_signin_get(self):
        """Test GET request to signin page."""
        response = self.client.get(self.signin_url)
        self.assertEqual(response.status_code, 200)

    def test_signin_post_success(self):
        """Test successful signin."""
        response = self.client.post(
            self.signin_url,
            {"user_id": self.user.user_id, "auth_secret": self.auth_secret},
        )

        # Should redirect to vault
        self.assertEqual(response.status_code, 302)

        # Session should be authenticated
        self.assertTrue(self.client.session.get("authenticated"))
        self.assertEqual(self.client.session.get("user_id"), self.user.user_id)

    def test_salts_post_ajax_returns_public_salts(self):
        """The public salt endpoint returns auth and vault salts for derivation."""
        response = self.client.post(
            self.salts_url,
            {"user_id": self.user.user_id},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["auth_salt"], self.user.auth_salt)
        self.assertEqual(body["vault_salt"], self.user.vault_salt)

    def test_signin_post_ajax_returns_salt_and_redirect(self):
        """An AJAX signin returns the salt and vault redirect URL as JSON."""
        response = self.client.post(
            self.signin_url,
            {"user_id": self.user.user_id, "auth_secret": self.auth_secret},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["success"])
        self.assertIn("vault_salt", body)
        self.assertIn("auth_salt", body)
        self.assertEqual(body["redirect_url"], vault_url())
        self.assertTrue(self.client.session.get("authenticated"))

    def test_signin_post_wrong_password(self):
        """Test signin with wrong password."""
        response = self.client.post(
            self.signin_url,
            {"user_id": self.user.user_id, "auth_secret": WRONG_AUTH_SECRET},
        )

        # Should return to form
        self.assertEqual(response.status_code, 200)

        # Session should not be authenticated
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_signin_get_redirects_when_authenticated(self):
        """An already-authenticated session is sent to the vault instead."""
        self.client.post(
            self.signin_url,
            {"user_id": self.user.user_id, "auth_secret": self.auth_secret},
        )
        response = self.client.get(self.signin_url)
        self.assertRedirects(
            response, vault_url(), fetch_redirect_response=False
        )

    def test_signin_post_redirects_when_authenticated(self):
        """An authenticated POST short-circuits to the vault redirect."""
        self.client.post(
            self.signin_url,
            {"user_id": self.user.user_id, "auth_secret": self.auth_secret},
        )
        response = self.client.post(
            self.signin_url,
            {"user_id": self.user.user_id, "auth_secret": WRONG_AUTH_SECRET},
        )
        self.assertRedirects(
            response, vault_url(), fetch_redirect_response=False
        )
        # The short-circuit must not have torn down the session.
        self.assertTrue(self.client.session.get("authenticated"))

    def test_signin_invalid_form_flushes_session(self):
        """A malformed signin attempt clears any existing session state."""
        session = self.client.session
        session["sentinel"] = "stale"
        session.save()

        response = self.client.post(self.signin_url, {"user_id": self.user.user_id})

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.client.session.get("sentinel"))
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_signin_authenticate_errors_are_logged_without_raw_details(self):
        """An authentication-service failure returns a generic sanitized error."""
        raw_detail = "connection to server at proxima_user failed"
        with self.assertLogs("apps.auth.views", level="ERROR") as logs:
            with patch(
                "apps.auth.views.services.authenticate_user",
                side_effect=RuntimeError(raw_detail),
            ):
                response = self.client.post(
                    self.signin_url,
                    {"user_id": self.user.user_id, "auth_secret": self.auth_secret},
                    HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], ERROR_UNEXPECTED)
        self.assertFalse(self.client.session.get("authenticated", False))
        log_output = "\n".join(logs.output)
        self.assertIn("RuntimeError", log_output)
        self.assertNotIn(raw_detail, log_output)

    def test_signin_session_creation_failure_returns_generic_error(self):
        """A session-creation failure after valid credentials returns a 500."""
        with self.assertLogs("apps.auth.views", level="ERROR"):
            with patch(
                "apps.auth.views.services.create_user_session",
                side_effect=RuntimeError("session backend down"),
            ):
                response = self.client.post(
                    self.signin_url,
                    {"user_id": self.user.user_id, "auth_secret": self.auth_secret},
                    HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], ERROR_UNEXPECTED)
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_signin_rate_limited_ajax_returns_429_json(self):
        """AJAX signin past the limit gets a 429 with the rate-limit message."""
        payload = {"user_id": self.user.user_id, "auth_secret": WRONG_AUTH_SECRET}

        # RATE_LIMIT_SIGNIN is 10/m; the 11th POST in the window is blocked.
        for _ in range(10):
            self.client.post(
                self.signin_url, payload, HTTP_X_REQUESTED_WITH="XMLHttpRequest"
            )

        response = self.client.post(
            self.signin_url, payload, HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )

        self.assertEqual(response.status_code, 429)
        body = response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], ERROR_RATE_LIMITED)


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "testserver"],
)
class PassSubdomainRedirectTests(TestCase):
    """The authenticated flow is pinned to the pass subdomain.

    The vault key lives in origin-scoped sessionStorage on PASS_SITE_URL, so auth
    pages reached on the main host must bounce to the pass host before the key is
    derived (otherwise the vault reports "Secure session expired").
    """

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = create_user_with_password(AUTH_SECRET)

    def _authenticate(self):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = self.user.user_id
        session.save()

    def test_signin_get_on_main_host_redirects_to_pass(self):
        """A signin GET on proxima.red is sent to the same path on pass."""
        response = self.client.get(reverse("auth:signin"), HTTP_HOST="proxima.red")
        self.assertRedirects(
            response,
            "https://pass.proxima.red/auth/signin/",
            fetch_redirect_response=False,
        )

    def test_signup_get_on_main_host_redirects_to_pass(self):
        """A signup GET on proxima.red is sent to the same path on pass."""
        response = self.client.get(reverse("auth:signup"), HTTP_HOST="proxima.red")
        self.assertRedirects(
            response,
            "https://pass.proxima.red/auth/signup/",
            fetch_redirect_response=False,
        )

    def test_account_get_on_main_host_redirects_to_pass(self):
        """An authenticated account GET on proxima.red is sent to pass."""
        self._authenticate()
        response = self.client.get(reverse("auth:account"), HTTP_HOST="proxima.red")
        self.assertRedirects(
            response,
            "https://pass.proxima.red/auth/account/",
            fetch_redirect_response=False,
        )

    def test_query_string_is_preserved_in_redirect(self):
        """The bounce keeps the original path and query intact."""
        response = self.client.get(
            reverse("auth:signin") + "?next=/vault/", HTTP_HOST="proxima.red"
        )
        self.assertRedirects(
            response,
            "https://pass.proxima.red/auth/signin/?next=/vault/",
            fetch_redirect_response=False,
        )

    def test_signin_get_on_pass_host_is_served_directly(self):
        """On the pass host the page renders without a redirect."""
        response = self.client.get(
            reverse("auth:signin"), HTTP_HOST="pass.proxima.red"
        )
        self.assertEqual(response.status_code, 200)

    @override_settings(
        SITE_URL="https://proxima.red", PASS_SITE_URL="https://proxima.red"
    )
    def test_single_domain_does_not_redirect(self):
        """When both sites share a host the mixin is a no-op."""
        response = self.client.get(reverse("auth:signin"), HTTP_HOST="proxima.red")
        self.assertEqual(response.status_code, 200)


class ReauthViewTests(TestCase):
    """The reauth endpoint backs the in-place unlock prompt."""

    def setUp(self):
        cache.clear()
        self.client = Client()
        self.reauth_url = reverse("auth:reauth")
        self.user = create_user_with_password(AUTH_SECRET)

    def _authenticate(self):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = self.user.user_id
        session.save()

    def test_requires_authentication(self):
        """An unauthenticated request is rejected with a JSON 401."""
        response = self.client.post(
            self.reauth_url,
            {"auth_secret": AUTH_SECRET},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["success"])

    def test_correct_secret_returns_salts(self):
        """The session user's correct secret returns the public salts."""
        self._authenticate()
        response = self.client.post(
            self.reauth_url,
            {"auth_secret": AUTH_SECRET},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["auth_salt"], self.user.auth_salt)
        self.assertEqual(body["vault_salt"], self.user.vault_salt)

    def test_wrong_secret_is_rejected(self):
        """A wrong secret returns a 401 and no salts (so no bad key is derived)."""
        self._authenticate()
        response = self.client.post(
            self.reauth_url,
            {"auth_secret": WRONG_AUTH_SECRET},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["success"])

    def test_missing_secret_is_rejected(self):
        """An empty payload is a 400, not a server error."""
        self._authenticate()
        response = self.client.post(
            self.reauth_url, {}, HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.json()["success"])

    def test_verifies_against_session_user_not_posted_id(self):
        """A posted user_id can't redirect the check to another account."""
        self._authenticate()
        other = create_user_with_password(NEW_AUTH_SECRET)
        # Correct secret for `other`, but the session belongs to self.user.
        response = self.client.post(
            self.reauth_url,
            {"auth_secret": NEW_AUTH_SECRET, "user_id": other.user_id},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(response.json()["success"])


class AuthSaltsViewTests(TestCase):
    """The public salts endpoint must not leak account existence."""

    def setUp(self):
        cache.clear()  # reset per-IP rate-limit counters between tests
        self.client = Client()
        self.salts_url = reverse("auth:salts")
        self.user = create_user_with_password(AUTH_SECRET)
        self.unknown_id = "00000001"
        # Guard the fixture: the decoy path keys on a genuinely absent id.
        self.assertFalse(User.objects.filter(user_id=self.unknown_id).exists())

    def _salts(self, user_id):
        response = self.client.post(
            self.salts_url,
            {"user_id": user_id},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_malformed_user_id_is_rejected(self):
        """Ids without the 8-digit shape get a 400, not decoy salts."""
        for bad_id in ("", "1234567", "123456789", "12ab5678"):
            with self.subTest(user_id=bad_id):
                response = self.client.post(
                    self.salts_url,
                    {"user_id": bad_id},
                    HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                )
                self.assertEqual(response.status_code, 400)
                body = response.json()
                self.assertFalse(body["success"])
                self.assertEqual(body["error"], ERROR_INVALID_USER_ID)

    def test_user_id_is_stripped_before_validation(self):
        """Surrounding whitespace doesn't fail an otherwise valid id."""
        response = self.client.post(
            self.salts_url,
            {"user_id": f"  {self.user.user_id}  "},
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["auth_salt"], self.user.auth_salt)

    def test_unknown_user_returns_stable_salts(self):
        """Repeated calls for a missing id return identical (decoy) salts."""
        first = self._salts(self.unknown_id)
        second = self._salts(self.unknown_id)
        self.assertEqual(first["auth_salt"], second["auth_salt"])
        self.assertEqual(first["vault_salt"], second["vault_salt"])

    def test_unknown_user_salts_have_real_salt_shape(self):
        """Decoy salts decode to the same byte length as real ones."""
        body = self._salts(self.unknown_id)
        self.assertEqual(len(base64.b64decode(body["auth_salt"])), 32)
        self.assertEqual(len(base64.b64decode(body["vault_salt"])), 32)

    def test_existence_is_not_observable_via_repetition(self):
        """A known and an unknown id both answer stably, so neither stands out."""
        known_first = self._salts(self.user.user_id)
        known_second = self._salts(self.user.user_id)
        unknown_first = self._salts(self.unknown_id)
        unknown_second = self._salts(self.unknown_id)

        self.assertEqual(known_first, known_second)
        self.assertEqual(unknown_first, unknown_second)
        # And a real account's salts are not the unknown id's decoys.
        self.assertNotEqual(known_first["auth_salt"], unknown_first["auth_salt"])


class SignoutViewTests(TestCase):
    """Test cases for SignoutView."""

    def setUp(self):
        """Set up test client and authenticated session."""
        cache.clear()  # reset per-IP rate-limit counters between tests
        self.client = Client()
        self.signout_url = reverse("auth:signout")
        self.auth_secret = AUTH_SECRET
        self.user = create_user_with_password(self.auth_secret)

        # Sign in
        self.client.post(
            reverse("auth:signin"),
            {"user_id": self.user.user_id, "auth_secret": self.auth_secret},
        )

    def test_signout_post(self):
        """Test signout via POST request."""
        # Verify session is authenticated
        self.assertTrue(self.client.session.get("authenticated"))

        response = self.client.post(self.signout_url)

        # Should redirect to signin
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)

        # Session should be cleared
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_signout_post_ajax(self):
        """AJAX signout returns a JSON success payload."""
        response = self.client.post(
            self.signout_url,
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_signout_get_not_allowed(self):
        """GET must not sign the user out (logout-CSRF protection)."""
        response = self.client.get(self.signout_url)

        self.assertEqual(response.status_code, 405)
        # Session is untouched
        self.assertTrue(self.client.session.get("authenticated"))


class _AuthenticatedViewTestCase(TestCase):
    """Base for tests that need an authenticated session."""

    def setUp(self):
        cache.clear()  # reset per-IP rate-limit counters between tests
        self.client = Client()
        self.auth_secret = AUTH_SECRET
        self.user = create_user_with_password(self.auth_secret)

    def _authenticate(self):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = self.user.user_id
        session.save()


class AccountViewTests(_AuthenticatedViewTestCase):
    """Test cases for AccountView."""

    def setUp(self):
        super().setUp()
        self.url = reverse("auth:account")

    def test_requires_authentication(self):
        """Unauthenticated requests are redirected to signin."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)

    def test_authenticated_renders_account(self):
        """An authenticated user sees the account page with their user object."""
        self._authenticate()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "auth/account.html")
        self.assertEqual(response.context["user_obj"], self.user)

    def test_missing_user_is_handled(self):
        """A session pointing at a deleted user is flushed and redirected."""
        self._authenticate()
        self.user.delete()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)
        self.assertFalse(self.client.session.get("authenticated", False))


class PasswordChangeViewTests(_AuthenticatedViewTestCase):
    """Test cases for PasswordChangeView."""

    def setUp(self):
        super().setUp()
        self.url = reverse("auth:change_password")
        self.new_auth_secret = NEW_AUTH_SECRET

    def _payload(self, current=None, new=None):
        return {
            "current_auth_secret": current or self.auth_secret,
            "new_auth_secret": new or self.new_auth_secret,
            "auth_salt": NEW_AUTH_SALT,
            "vault_salt": NEW_VAULT_SALT,
        }

    def test_requires_authentication(self):
        """Unauthenticated password changes are redirected to signin."""
        response = self.client.post(self.url, self._payload())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)

    def test_change_password_success(self):
        """A valid change rotates the hash and salt and keeps the session."""
        self._authenticate()
        old_salt = self.user.vault_salt

        response = self.client.post(self.url, self._payload())
        self.assertEqual(response.status_code, 302)

        self.user.refresh_from_db()
        self.assertTrue(check_password(self.new_auth_secret, self.user.password_hash))
        self.assertEqual(self.user.auth_salt, NEW_AUTH_SALT)
        self.assertNotEqual(old_salt, self.user.vault_salt)
        # Session is regenerated but remains authenticated.
        self.assertTrue(self.client.session.get("authenticated"))

    def test_change_password_ajax_returns_new_salt(self):
        """An AJAX change returns the rotated salt for client re-derivation."""
        self._authenticate()
        response = self.client.post(
            self.url, self._payload(), HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        self.assertIn("vault_salt", payload)
        self.assertIn("auth_salt", payload)

    def test_missing_user_is_handled(self):
        """A session pointing at a deleted user is flushed and redirected."""
        self._authenticate()
        self.user.delete()
        response = self.client.post(self.url, self._payload())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_change_password_wrong_current(self):
        """An incorrect current password is rejected and changes nothing."""
        self._authenticate()
        response = self.client.post(self.url, self._payload(current=WRONG_AUTH_SECRET))
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(check_password(self.auth_secret, self.user.password_hash))


class AccountDeletionViewTests(_AuthenticatedViewTestCase):
    """Test cases for AccountDeletionView."""

    def setUp(self):
        super().setUp()
        self.url = reverse("auth:delete_account")

    def test_requires_authentication(self):
        """Unauthenticated deletions are redirected to signin."""
        response = self.client.post(
            self.url, {"auth_secret": self.auth_secret, "confirmation_text": "DELETE"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)

    def test_delete_success(self):
        """A confirmed deletion removes the user and clears the session."""
        self._authenticate()
        response = self.client.post(
            self.url, {"auth_secret": self.auth_secret, "confirmation_text": "DELETE"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(User.objects.filter(pk=self.user.pk).exists())
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_delete_success_removes_owned_shares(self):
        """Account deletion removes shares created by that authenticated user."""
        owned_share = SharedPassword.objects.create(
            created_by=self.user,
            encrypted_data="Y2lwaGVy",
            iv="AAAAAAAAAAAAAAAA",
            expires_at=timezone.now() + timedelta(days=1),
        )
        anonymous_share = SharedPassword.objects.create(
            encrypted_data="YW5vbnltb3Vz",
            iv="AAAAAAAAAAAAAAAA",
            expires_at=timezone.now() + timedelta(days=1),
        )

        self._authenticate()
        response = self.client.post(
            self.url, {"auth_secret": self.auth_secret, "confirmation_text": "DELETE"}
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(SharedPassword.objects.filter(pk=owned_share.pk).exists())
        self.assertTrue(SharedPassword.objects.filter(pk=anonymous_share.pk).exists())

    def test_delete_wrong_password(self):
        """A wrong password leaves the account intact."""
        self._authenticate()
        response = self.client.post(
            self.url, {"auth_secret": WRONG_AUTH_SECRET, "confirmation_text": "DELETE"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def test_delete_wrong_confirmation(self):
        """A wrong confirmation phrase leaves the account intact."""
        self._authenticate()
        response = self.client.post(
            self.url, {"auth_secret": self.auth_secret, "confirmation_text": "nope"}
        )
        self.assertEqual(response.status_code, 400)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

    def test_missing_user_is_handled(self):
        """A session pointing at a deleted user is flushed and redirected."""
        self._authenticate()
        self.user.delete()
        response = self.client.post(
            self.url, {"auth_secret": self.auth_secret, "confirmation_text": "DELETE"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("auth:signin"), response.url)
        self.assertFalse(self.client.session.get("authenticated", False))

    def test_delete_failure_ajax_returns_500_with_sanitized_log(self):
        """A storage failure returns a generic 500 and keeps the session alive."""
        self._authenticate()
        raw_detail = "deadlock detected on relation proxima_user"
        with self.assertLogs("apps.auth.views", level="ERROR") as logs:
            with patch(
                "apps.auth.views.services.delete_user_account",
                side_effect=RuntimeError(raw_detail),
            ):
                response = self.client.post(
                    self.url,
                    {"auth_secret": self.auth_secret, "confirmation_text": "DELETE"},
                    HTTP_X_REQUESTED_WITH="XMLHttpRequest",
                )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["error"], ERROR_ACCOUNT_DELETION_FAILED)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())
        # A failed deletion must not sign the user out.
        self.assertTrue(self.client.session.get("authenticated"))
        log_output = "\n".join(logs.output)
        self.assertIn("RuntimeError", log_output)
        self.assertNotIn(raw_detail, log_output)

    def test_delete_failure_non_ajax_renders_account_with_error(self):
        """A non-AJAX storage failure re-renders the account page with a flash."""
        self._authenticate()
        with self.assertLogs("apps.auth.views", level="ERROR"):
            with patch(
                "apps.auth.views.services.delete_user_account",
                side_effect=RuntimeError("boom"),
            ):
                response = self.client.post(
                    self.url,
                    {"auth_secret": self.auth_secret, "confirmation_text": "DELETE"},
                )

        self.assertEqual(response.status_code, 500)
        self.assertTemplateUsed(response, "auth/account.html")
        flashed = [str(m) for m in response.context["messages"]]
        self.assertIn(ERROR_ACCOUNT_DELETION_FAILED, flashed)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())
