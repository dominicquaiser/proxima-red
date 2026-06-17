"""Tests for passwd service helpers."""

from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.passwd.models import SharedPassword
from apps.passwd.services import (
    delete_expired_shares,
    expired_shares,
    save_user_vault_data,
    serialize_service_data,
)


def make_share(**overrides):
    """Create a SharedPassword with sensible defaults for tests."""
    data = {
        "encrypted_data": "ZW5jcnlwdGVk",
        "iv": "AAAAAAAAAAAAAAAA",
        "expires_at": timezone.now() + timedelta(days=1),
    }
    data.update(overrides)
    return SharedPassword.objects.create(**data)


class ServiceDataSerializerTests(TestCase):
    """The vault blob has one canonical JSON shape."""

    def setUp(self):
        self.user = create_user_with_password("TestPassword123!")

    def test_serialize_service_data_for_client(self):
        service_data = save_user_vault_data(self.user, "ZW5jcnlwdGVk", b"\x00" * 12)

        self.assertEqual(
            serialize_service_data(service_data),
            {
                "encrypted_data": "ZW5jcnlwdGVk",
                "iv": "AAAAAAAAAAAAAAAA",
            },
        )

    def test_serialize_service_data_for_export(self):
        service_data = save_user_vault_data(self.user, "ZW5jcnlwdGVk", b"\x00" * 12)

        payload = serialize_service_data(service_data, include_updated_at=True)

        self.assertEqual(payload["encrypted_data"], "ZW5jcnlwdGVk")
        self.assertEqual(payload["iv"], "AAAAAAAAAAAAAAAA")
        self.assertEqual(payload["updated_at"], service_data.updated_at.isoformat())


class ExpiredShareCleanupTests(TestCase):
    """Expired shares can be pruned without exposing ciphertext."""

    def test_delete_expired_shares_removes_only_expired_rows(self):
        expired = make_share(expires_at=timezone.now() - timedelta(minutes=1))
        live = make_share(expires_at=timezone.now() + timedelta(minutes=1))

        deleted_count = delete_expired_shares()

        self.assertEqual(deleted_count, 1)
        self.assertFalse(SharedPassword.objects.filter(pk=expired.pk).exists())
        self.assertTrue(SharedPassword.objects.filter(pk=live.pk).exists())

    def test_delete_expired_shares_batched_removes_all(self):
        for _ in range(5):
            make_share(expires_at=timezone.now() - timedelta(minutes=1))
        live = make_share(expires_at=timezone.now() + timedelta(minutes=1))

        deleted_count = delete_expired_shares(batch_size=2)

        self.assertEqual(deleted_count, 5)
        self.assertEqual(list(SharedPassword.objects.all()), [live])

    def test_delete_expired_shares_returns_zero_when_nothing_expired(self):
        """The single-query path skips the DELETE when no rows are expired."""
        live = make_share(expires_at=timezone.now() + timedelta(minutes=1))

        self.assertEqual(delete_expired_shares(), 0)
        self.assertTrue(SharedPassword.objects.filter(pk=live.pk).exists())

    def test_expired_shares_queryset_selects_only_expired(self):
        expired = make_share(expires_at=timezone.now() - timedelta(minutes=1))
        make_share(expires_at=timezone.now() + timedelta(minutes=1))

        self.assertEqual(list(expired_shares()), [expired])
