"""Exercise real HTTP authorization with a controlled clock; no expiry sleeps."""

import base64
import time
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.auth.tests.factories import create_user_with_password
from apps.auth.vault_sessions import identity

SECRET = base64.b64encode(b"a" * 32).decode()
NEW_SECRET = base64.b64encode(b"b" * 32).decode()


class VaultSessionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = create_user_with_password(SECRET)
        self.now = time.time()
        clock = patch("apps.auth.vault_sessions.time.time", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        self.signin(self.client)

    def signin(self, client):
        response = client.post(
            "/auth/signin/",
            {
                "user_id": self.user.user_id,
                "auth_secret": SECRET,
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200)

    def state(self, tool):
        response = self.client.get("/auth/vault-session/", {"tool": tool})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        return response.json()["state"]

    def reauth(self, tool, secret=SECRET):
        return self.client.post("/auth/reauth/", {"tool": tool, "auth_secret": secret})

    def test_password_expires_at_thirty_minutes_while_notes_remain_available(self):
        original = self.state("pass")["expires_at"]
        self.now += settings.PASSWORD_VAULT_TIMEOUT - 1
        self.assertEqual(self.client.get("/vault-data/").status_code, 200)
        self.assertEqual(self.state("pass")["expires_at"], original)
        self.now += 1
        self.assertEqual(self.client.get("/vault-data/").status_code, 423)
        self.assertEqual(self.client.get("/vault/index/").status_code, 200)

    def test_activity_renews_only_notes_and_reauth_renews_only_selected_tool(self):
        before = self.state("note")["expires_at"]
        self.now += 6 * 86400
        self.assertEqual(self.client.post("/auth/vault-session/").status_code, 200)
        renewed = self.state("note")["expires_at"]
        self.assertEqual(renewed, self.now + settings.NOTE_VAULT_IDLE_TIMEOUT)
        self.assertGreater(renewed, before)
        self.assertFalse(self.state("pass")["unlocked"])
        self.assertEqual(self.reauth("note").status_code, 200)
        self.assertFalse(self.state("pass")["unlocked"])
        self.now += 1
        self.assertEqual(self.reauth("pass").status_code, 200)
        self.assertEqual(self.state("note")["expires_at"], renewed)
        self.assertEqual(self.state("pass")["expires_at"], self.now + 1800)

    def test_note_reads_and_status_checks_do_not_renew_idle_window(self):
        expiry = self.state("note")["expires_at"]
        self.now += 86400
        self.assertEqual(self.client.get("/vault/index/").status_code, 200)
        self.assertEqual(self.client.get("/vault/notes/").status_code, 200)
        self.assertEqual(self.state("note")["expires_at"], expiry)

    def test_seven_day_boundary_cannot_be_revived_by_activity(self):
        self.now += settings.NOTE_VAULT_IDLE_TIMEOUT - 1
        self.assertTrue(self.state("note")["unlocked"])
        self.now += 1
        expired = self.client.session["vault_note_expires_at"]
        self.assertFalse(self.state("note")["unlocked"])
        self.assertEqual(self.client.get("/vault/index/").status_code, 423)
        self.assertEqual(self.client.post("/auth/vault-session/").status_code, 423)
        self.assertEqual(self.client.session["vault_note_expires_at"], expired)

    def test_legacy_session_requires_verification_before_either_vault(self):
        session = self.client.session
        for name in ("credential_version", "vault_pass_expires_at", "vault_note_expires_at"):
            session.pop(name)
        session.save()
        for tool in ("pass", "note"):
            self.assertFalse(self.state(tool)["unlocked"])
        self.assertEqual(self.client.get("/vault-data/").status_code, 423)
        self.assertEqual(self.reauth("pass").status_code, 200)
        self.assertTrue(self.state("pass")["unlocked"])
        self.assertFalse(self.state("note")["unlocked"])

    def test_all_password_endpoints_enforce_the_deadline(self):
        self.now += 1800
        for method, url in (
            ("get", "/vault-data/"),
            ("post", "/update-data/"),
            ("post", "/delete-share/"),
        ):
            with self.subTest(url=url):
                response = getattr(self.client, method)(url)
                self.assertEqual(response.status_code, 423)
                self.assertEqual(response.json()["code"], "vault_locked")

    def test_export_needs_both_grants_and_redirects_a_locked_navigation(self):
        self.assertEqual(self.client.get("/export-data/").status_code, 200)
        for expired_tool in ("pass", "note"):
            with self.subTest(expired=expired_tool):
                self.assertEqual(self.reauth("account").status_code, 200)
                session = self.client.session
                session[f"vault_{expired_tool}_expires_at"] = self.now
                session.save()
                response = self.client.get("/export-data/")
                self.assertEqual(response.status_code, 302)
                self.assertEqual(response.url, reverse("auth:account"))
        self.assertEqual(self.reauth("account").status_code, 200)
        self.assertEqual(self.client.get("/export-data/").status_code, 200)

    def test_vault_session_endpoint_is_rate_limited(self):
        for _ in range(120):
            self.client.get("/auth/vault-session/", {"tool": "pass"})
        response = self.client.get(
            "/auth/vault-session/", {"tool": "pass"}, HTTP_X_REQUESTED_WITH="XMLHttpRequest"
        )
        self.assertEqual(response.status_code, 429)

    @override_settings(ALLOWED_HOSTS=["testserver", "note.example", "pass.example"])
    def test_changing_hosts_cannot_bypass_a_tool_lock(self):
        self.now += 1800
        for host in ("testserver", "note.example", "pass.example"):
            self.assertEqual(self.client.get("/vault-data/", HTTP_HOST=host).status_code, 423)
            self.assertEqual(self.client.get("/vault/index/", HTTP_HOST=host).status_code, 200)

    def test_wrong_password_and_unknown_tool_do_not_extend_grants(self):
        before = dict(self.client.session)
        self.assertEqual(self.reauth("pass", NEW_SECRET).status_code, 401)
        self.assertEqual(self.reauth("arbitrary").status_code, 400)
        self.assertEqual(dict(self.client.session), before)

    def test_all_note_endpoints_enforce_the_idle_deadline(self):
        self.now += settings.NOTE_VAULT_IDLE_TIMEOUT
        note_id = "00000000-0000-0000-0000-000000000001"
        for method, url in (
            ("get", "/vault/index/"),
            ("post", "/vault/index/"),
            ("get", "/vault/notes/"),
            ("post", "/vault/notes/"),
            ("get", f"/vault/notes/{note_id}/"),
            ("post", f"/vault/notes/{note_id}/"),
            ("post", f"/vault/notes/{note_id}/delete/"),
            ("post", "/vault/notes/trash/"),
            ("post", "/vault/migrate/"),
        ):
            with self.subTest(method=method, url=url):
                response = getattr(self.client, method)(url)
                self.assertEqual(response.status_code, 423)
                self.assertEqual(response.json()["code"], "vault_locked")

    def test_account_change_guard_rejects_old_tab_writes_and_activity(self):
        for path in ("/auth/vault-session/", "/update-data/", "/vault/index/"):
            response = self.client.post(path, HTTP_X_VAULT_IDENTITY="another-account:key")
            self.assertEqual(response.status_code, 409)
            self.assertEqual(response.json()["code"], "vault_identity_changed")

    def test_logout_revokes_both_tools(self):
        self.client.post("/auth/signout/")
        for path in ("/vault-data/", "/vault/index/", "/auth/vault-session/"):
            self.assertEqual(self.client.get(path).status_code, 401)

    def test_password_change_rotates_cache_context_and_revokes_other_sessions(self):
        other = Client()
        self.signin(other)
        old_context = self.state("note")["cache_context"]
        old_identity = identity(self.user)
        response = self.client.post(
            "/auth/account/password/",
            {
                "current_auth_secret": SECRET,
                "new_auth_secret": NEW_SECRET,
                "auth_salt": base64.b64encode(b"c" * 32).decode(),
                "vault_salt": base64.b64encode(b"d" * 32).decode(),
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertNotEqual(self.state("note")["cache_context"], old_context)
        self.assertTrue(self.state("pass")["unlocked"])
        self.assertTrue(self.state("note")["unlocked"])
        self.assertEqual(other.get("/vault/index/").status_code, 401)
        self.assertEqual(
            self.client.post("/vault/index/", HTTP_X_VAULT_IDENTITY=old_identity).status_code, 409
        )

    def test_activity_requires_csrf_and_authenticated_session(self):
        client = Client(enforce_csrf_checks=True)
        client.cookies = self.client.cookies
        self.assertEqual(client.post("/auth/vault-session/").status_code, 403)
        self.assertEqual(Client().post("/auth/vault-session/").status_code, 401)
