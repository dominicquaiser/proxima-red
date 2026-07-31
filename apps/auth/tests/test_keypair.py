"""
Tests for the collaboration keypair storage and lookup (M4 named
collaborators): the ``UserKeyPair`` model, the create-once ``KeypairView``,
and the authenticated-only ``PubkeyLookupView``.
"""

import json

from django.core.cache import cache
from django.test import Client, TestCase
from django.urls import reverse

from apps.auth.models import UserKeyPair
from apps.auth.services import (
    create_user_keypair,
    get_public_key_for_user_id,
    get_user_keypair,
)

from .factories import (
    VALID_KEYPAIR_IV_B64,
    VALID_PRIVATE_KEY_BLOB_B64,
    VALID_PUBLIC_KEY_B64,
    create_user_with_password,
    make_keypair,
)

AJAX = {"HTTP_X_REQUESTED_WITH": "XMLHttpRequest"}


class KeypairTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client()
        self.user = create_user_with_password("correct horse battery staple")

    def _authenticate(self, user=None):
        session = self.client.session
        session["authenticated"] = True
        session["user_id"] = (user or self.user).user_id
        session.save()


class KeypairServiceTests(KeypairTestCase):
    def test_create_and_get_keypair(self):
        self.assertIsNone(get_user_keypair(self.user))
        keypair = create_user_keypair(
            self.user,
            public_key=VALID_PUBLIC_KEY_B64,
            encrypted_private_key=VALID_PRIVATE_KEY_BLOB_B64,
            private_key_iv=VALID_KEYPAIR_IV_B64,
        )
        self.assertEqual(get_user_keypair(self.user), keypair)

    def test_create_is_create_only(self):
        make_keypair(self.user)
        with self.assertRaises(Exception) as ctx:
            create_user_keypair(
                self.user,
                public_key=VALID_PUBLIC_KEY_B64,
                encrypted_private_key=VALID_PRIVATE_KEY_BLOB_B64,
                private_key_iv=VALID_KEYPAIR_IV_B64,
            )
        self.assertEqual(getattr(ctx.exception, "code", None), "keypair_exists")
        # Still exactly one row.
        self.assertEqual(UserKeyPair.objects.filter(user=self.user).count(), 1)

    def test_public_key_lookup_by_user_id(self):
        make_keypair(self.user)
        self.assertEqual(
            get_public_key_for_user_id(self.user.user_id), VALID_PUBLIC_KEY_B64
        )
        # No decoys: a missing keypair / user returns None, not a fake key.
        self.assertIsNone(get_public_key_for_user_id("00000000"))
        other = create_user_with_password("another secret")
        self.assertIsNone(get_public_key_for_user_id(other.user_id))

    def test_keypair_cascades_on_user_delete(self):
        make_keypair(self.user)
        self.user.delete()
        self.assertFalse(UserKeyPair.objects.exists())


class KeypairViewTests(KeypairTestCase):
    def test_get_requires_authentication(self):
        response = self.client.get(reverse("auth:keypair"), **AJAX)
        self.assertEqual(response.status_code, 401)

    def test_get_reports_absent_then_present(self):
        self._authenticate()
        response = self.client.get(reverse("auth:keypair"), **AJAX)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["success"])
        self.assertFalse(body["exists"])

        make_keypair(self.user)
        body = self.client.get(reverse("auth:keypair"), **AJAX).json()
        self.assertTrue(body["exists"])
        self.assertEqual(body["public_key"], VALID_PUBLIC_KEY_B64)
        self.assertEqual(body["encrypted_private_key"], VALID_PRIVATE_KEY_BLOB_B64)
        self.assertEqual(body["private_key_iv"], VALID_KEYPAIR_IV_B64)

    def test_post_creates_keypair(self):
        self._authenticate()
        response = self.client.post(
            reverse("auth:keypair"),
            {
                "public_key": VALID_PUBLIC_KEY_B64,
                "encrypted_private_key": VALID_PRIVATE_KEY_BLOB_B64,
                "private_key_iv": VALID_KEYPAIR_IV_B64,
            },
            **AJAX,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(UserKeyPair.objects.filter(user=self.user).exists())

    def test_post_conflicts_when_one_exists(self):
        make_keypair(self.user)
        self._authenticate()
        response = self.client.post(
            reverse("auth:keypair"),
            {
                "public_key": VALID_PUBLIC_KEY_B64,
                "encrypted_private_key": VALID_PRIVATE_KEY_BLOB_B64,
                "private_key_iv": VALID_KEYPAIR_IV_B64,
            },
            **AJAX,
        )
        self.assertEqual(response.status_code, 409)

    def test_post_rejects_wrong_public_key_length(self):
        self._authenticate()
        response = self.client.post(
            reverse("auth:keypair"),
            {
                "public_key": "c2hvcnQ=",  # not 91 bytes
                "encrypted_private_key": VALID_PRIVATE_KEY_BLOB_B64,
                "private_key_iv": VALID_KEYPAIR_IV_B64,
            },
            **AJAX,
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(UserKeyPair.objects.exists())


class PubkeyLookupViewTests(KeypairTestCase):
    def test_requires_authentication(self):
        make_keypair(self.user)
        response = self.client.post(
            reverse("auth:pubkey"), {"user_id": self.user.user_id}, **AJAX
        )
        self.assertEqual(response.status_code, 401)

    def test_returns_public_key_for_collaborator(self):
        target = create_user_with_password("target secret")
        make_keypair(target)
        self._authenticate()
        response = self.client.post(
            reverse("auth:pubkey"), {"user_id": target.user_id}, **AJAX
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["user_id"], target.user_id)
        self.assertEqual(body["public_key"], VALID_PUBLIC_KEY_B64)

    def test_404_for_missing_keypair_no_decoy(self):
        # A real account without a keypair, and a nonexistent id, both 404 —
        # never a decoy key (which would create an unopenable invite).
        no_keypair = create_user_with_password("no keypair")
        self._authenticate()
        for user_id in (no_keypair.user_id, "00000000"):
            response = self.client.post(
                reverse("auth:pubkey"), {"user_id": user_id}, **AJAX
            )
            self.assertEqual(response.status_code, 404)

    def test_rejects_malformed_user_id(self):
        self._authenticate()
        response = self.client.post(
            reverse("auth:pubkey"), {"user_id": "nope"}, **AJAX
        )
        self.assertEqual(response.status_code, 400)
