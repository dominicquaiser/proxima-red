"""
Tests for the passwd app models.

Covers SharedPassword (anonymous shares) and ServiceData (per-user encrypted
vault), including defaults, string representations, expiry, and the
One-to-One/cascade relationship with the custom User model.
"""

from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.passwd.constants import GCM_IV_LENGTH_BYTES
from apps.passwd.models import ServiceData, SharedPassword


def make_share(**overrides):
    """Create a SharedPassword with sensible defaults for tests."""
    data = {
        "encrypted_data": "ZW5jcnlwdGVk",  # "encrypted" in base64
        "iv": "AAAAAAAAAAAAAAAA",
        "expires_at": timezone.now() + timedelta(days=1),
    }
    data.update(overrides)
    return SharedPassword.objects.create(**data)


class SharedPasswordModelTests(TestCase):
    """Test cases for the SharedPassword model."""

    def test_create_share_defaults(self):
        """A freshly created share has sane defaults."""
        share = make_share()

        self.assertIsNotNone(share.id)
        self.assertEqual(share.access_count, 0)
        self.assertEqual(share.encrypted_title, "")
        self.assertEqual(share.title_iv, "")
        self.assertIsNotNone(share.created_at)

    def test_str_untitled(self):
        """Shares without an encrypted title render as 'untitled'."""
        share = make_share()
        self.assertIn("untitled", str(share))

    def test_str_titled(self):
        """Shares with an encrypted title render as 'titled'."""
        share = make_share(encrypted_title="dGl0bGU=", title_iv="BBBBBBBBBBBBBBBB")
        self.assertIn("titled", str(share))
        self.assertNotIn("untitled", str(share))

    def test_repr_includes_id_and_expiry(self):
        """repr() references the share id prefix and both timestamps."""
        share = make_share()
        text = repr(share)
        self.assertIn(str(share.id)[:8], text)
        self.assertIn(share.created_at.isoformat(), text)
        self.assertIn(share.expires_at.isoformat(), text)

    def test_is_expired_false_for_future(self):
        """is_expired() is False while expires_at is in the future."""
        share = make_share(expires_at=timezone.now() + timedelta(hours=1))
        self.assertFalse(share.is_expired())

    def test_is_expired_true_for_past(self):
        """is_expired() is True once expires_at is in the past."""
        share = make_share(expires_at=timezone.now() - timedelta(hours=1))
        self.assertTrue(share.is_expired())

    def test_default_ordering_is_newest_first(self):
        """Shares are ordered by created_at descending."""
        first = make_share()
        second = make_share()

        shares = list(SharedPassword.objects.all())
        self.assertEqual(shares[0].id, second.id)
        self.assertEqual(shares[1].id, first.id)


class ServiceDataModelTests(TestCase):
    """Test cases for the ServiceData model."""

    def setUp(self):
        self.user = create_user_with_password("TestPassword123!")

    def test_create_service_data(self):
        """ServiceData stores an encrypted blob and a binary IV."""
        data = ServiceData.objects.create(
            user=self.user,
            encrypted_data="ZW5jcnlwdGVk",
            iv=b"\x00" * 12,
        )

        self.assertEqual(data.user, self.user)
        self.assertEqual(bytes(data.iv), b"\x00" * 12)
        self.assertIsNotNone(data.created_at)
        self.assertIsNotNone(data.updated_at)

    def test_iv_field_uses_aes_gcm_length(self):
        """The ServiceData IV field documents and validates the AES-GCM size."""
        field = ServiceData._meta.get_field("iv")
        self.assertEqual(field.max_length, GCM_IV_LENGTH_BYTES)

    def test_full_clean_rejects_wrong_iv_length(self):
        """Model validation rejects raw IVs that are not exactly 12 bytes."""
        data = ServiceData(
            user=self.user,
            encrypted_data="ZW5jcnlwdGVk",
            iv=b"\x00" * (GCM_IV_LENGTH_BYTES - 1),
        )
        with self.assertRaises(ValidationError):
            data.full_clean()

    def test_str_representation(self):
        """The string form references the owning user's id."""
        data = ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        self.assertEqual(str(data), f"Sharing data for User {self.user.user_id}")

    def test_repr_references_user_and_update_time(self):
        """repr() includes the owning user's id and the update timestamp."""
        data = ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        expected = (
            f"<ServiceData user_id={self.user.user_id} "
            f"updated={data.updated_at.isoformat()}>"
        )
        self.assertEqual(repr(data), expected)

    def test_one_to_one_with_user(self):
        """A user can have at most one ServiceData row."""
        ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        with self.assertRaises(Exception):
            ServiceData.objects.create(
                user=self.user, encrypted_data="b3RoZXI=", iv=b"\x01" * 12
            )

    def test_cascade_delete_with_user(self):
        """Deleting the user removes their ServiceData."""
        ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        self.assertEqual(ServiceData.objects.count(), 1)

        self.user.delete()
        self.assertEqual(ServiceData.objects.count(), 0)

    def test_related_name(self):
        """ServiceData is reachable from the user via service_data."""
        data = ServiceData.objects.create(
            user=self.user, encrypted_data="ZW5jcnlwdGVk", iv=b"\x00" * 12
        )
        self.assertEqual(self.user.service_data, data)
