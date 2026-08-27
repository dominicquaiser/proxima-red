"""Tests for passwd service helpers."""

import json
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.passwd.models import SharedPassword
from apps.passwd.services import (
    build_user_export,
    delete_expired_shares,
    delete_user_share,
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


class DeleteUserShareTests(TestCase):
    """Owners can revoke their own shares; everything else is a safe no-op."""

    def setUp(self):
        self.owner = create_user_with_password("TestPassword123!")
        self.other = create_user_with_password("TestPassword456!")

    def test_deletes_owner_share(self):
        share = make_share(created_by=self.owner)

        self.assertTrue(delete_user_share(self.owner, share.pk))
        self.assertFalse(SharedPassword.objects.filter(pk=share.pk).exists())

    def test_does_not_delete_another_users_share(self):
        share = make_share(created_by=self.other)

        self.assertFalse(delete_user_share(self.owner, share.pk))
        self.assertTrue(SharedPassword.objects.filter(pk=share.pk).exists())

    def test_unknown_share_id_is_noop(self):
        import uuid

        self.assertFalse(delete_user_share(self.owner, uuid.uuid4()))


class BuildUserExportTests(TestCase):
    """services.build_user_export: the account-wide GDPR export.

    The failure mode here is silence. These assert on the shape of
    the payload as much as on its contents.
    """

    def setUp(self):
        self.user = create_user_with_password("export secret")

    def test_export_has_a_section_for_every_kind_of_account_data(self):
        export = build_user_export(self.user)
        self.assertEqual(
            set(export),
            {
                "exported_at",
                "account",
                "vault",
                "shared_passwords",
                "note_vault",
                "shared_notes",
                "live_notes",
            },
        )

    def test_empty_account_exports_empty_sections_not_missing_ones(self):
        export = build_user_export(self.user)
        self.assertIsNone(export["vault"])
        self.assertEqual(export["shared_passwords"], [])
        self.assertEqual(export["shared_notes"], [])
        self.assertEqual(export["live_notes"], [])

    def test_password_shares_are_included_with_both_ciphertext_pairs(self):
        share = make_share(
            created_by=self.user,
            encrypted_title="dGl0bGU=",
            title_iv="BBBBBBBBBBBBBBBB",
        )
        export = build_user_export(self.user)

        self.assertEqual(len(export["shared_passwords"]), 1)
        row = export["shared_passwords"][0]
        self.assertEqual(row["id"], str(share.id))
        self.assertEqual(row["encrypted_data"], share.encrypted_data)
        self.assertEqual(row["iv"], share.iv)
        self.assertEqual(row["encrypted_title"], "dGl0bGU=")
        self.assertEqual(row["title_iv"], "BBBBBBBBBBBBBBBB")

    def test_anonymous_rows_belong_to_nobody_and_are_not_exported(self):
        """No created_by means nothing links the row to this account."""
        make_share()  # anonymous
        export = build_user_export(self.user)
        self.assertEqual(export["shared_passwords"], [])

    def test_another_users_rows_are_not_exported(self):
        other = create_user_with_password("other secret")
        make_share(created_by=other)
        export = build_user_export(self.user)
        self.assertEqual(export["shared_passwords"], [])

    def test_export_is_json_serializable(self):
        """It is served as a file download, so a stray UUID or datetime fails hard."""
        make_share(created_by=self.user)
        json.dumps(build_user_export(self.user))
