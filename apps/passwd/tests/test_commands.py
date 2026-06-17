"""
Tests for the passwd app management commands.

Covers delete_share (single-share takedown removal) and delete_expired (the
scheduled cleanup of shares past their expiry).
"""

import uuid
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from apps.passwd.models import SharedPassword


def make_share(**overrides):
    """Create a SharedPassword with sensible defaults for tests."""
    data = {
        "encrypted_data": "ZW5jcnlwdGVk",  # "encrypted" in base64
        "iv": "AAAAAAAAAAAAAAAA",
        "expires_at": timezone.now() + timedelta(days=1),
    }
    data.update(overrides)
    return SharedPassword.objects.create(**data)


class DeleteShareCommandTests(TestCase):
    """Test cases for the delete_share management command."""

    def test_deletes_the_named_share(self):
        """The share with the given UUID is removed."""
        share = make_share()

        call_command("delete_share", str(share.id), stdout=StringIO())

        self.assertFalse(SharedPassword.objects.filter(id=share.id).exists())

    def test_deletes_only_the_named_share(self):
        """Other shares are left untouched."""
        target = make_share()
        bystander = make_share()

        call_command("delete_share", str(target.id), stdout=StringIO())

        self.assertFalse(SharedPassword.objects.filter(id=target.id).exists())
        self.assertTrue(SharedPassword.objects.filter(id=bystander.id).exists())

    def test_dry_run_does_not_delete(self):
        """--dry-run reports the share but leaves it in place."""
        share = make_share()
        out = StringIO()

        call_command("delete_share", str(share.id), "--dry-run", stdout=out)

        self.assertTrue(SharedPassword.objects.filter(id=share.id).exists())
        self.assertIn("DRY RUN", out.getvalue())

    def test_invalid_uuid_raises(self):
        """A malformed identifier raises a clear CommandError."""
        with self.assertRaises(CommandError):
            call_command("delete_share", "not-a-uuid", stdout=StringIO())

    def test_missing_share_raises(self):
        """A well-formed but unknown UUID raises CommandError."""
        with self.assertRaises(CommandError):
            call_command("delete_share", str(uuid.uuid4()), stdout=StringIO())

    def test_output_never_includes_encrypted_data(self):
        """The command must not echo encrypted contents."""
        secret = "U0VDUkVUX0NJUEhFUlRFWFQ="  # distinctive base64 blob
        share = make_share(encrypted_data=secret, encrypted_title=secret)
        out = StringIO()

        call_command("delete_share", str(share.id), stdout=out)

        self.assertNotIn(secret, out.getvalue())

    def test_verbosity_zero_deletes_silently(self):
        """With --verbosity 0 the share is deleted without any output."""
        share = make_share()
        out = StringIO()

        call_command("delete_share", str(share.id), verbosity=0, stdout=out)

        self.assertFalse(SharedPassword.objects.filter(id=share.id).exists())
        self.assertEqual(out.getvalue(), "")

    def test_dry_run_verbosity_zero_is_silent(self):
        """A --dry-run at --verbosity 0 neither deletes nor prints."""
        share = make_share()
        out = StringIO()

        call_command(
            "delete_share", str(share.id), "--dry-run", verbosity=0, stdout=out
        )

        self.assertTrue(SharedPassword.objects.filter(id=share.id).exists())
        self.assertEqual(out.getvalue(), "")

    def test_deletion_error_is_wrapped_as_command_error(self):
        """A database failure during deletion surfaces as a CommandError."""
        share = make_share()

        with patch.object(
            SharedPassword, "delete", side_effect=RuntimeError("db down")
        ):
            with self.assertRaisesMessage(CommandError, "Error during deletion"):
                call_command("delete_share", str(share.id), stdout=StringIO())

        self.assertTrue(SharedPassword.objects.filter(id=share.id).exists())


class DeleteExpiredCommandTests(TestCase):
    """Test cases for the delete_expired management command."""

    def test_deletes_expired_shares_only(self):
        """Shares past their expiry are removed; live shares are kept."""
        expired = make_share(expires_at=timezone.now() - timedelta(hours=1))
        live = make_share(expires_at=timezone.now() + timedelta(days=1))

        call_command("delete_expired", stdout=StringIO())

        self.assertFalse(SharedPassword.objects.filter(id=expired.id).exists())
        self.assertTrue(SharedPassword.objects.filter(id=live.id).exists())

    def test_dry_run_keeps_shares(self):
        """--dry-run reports the count but deletes nothing."""
        expired = make_share(expires_at=timezone.now() - timedelta(hours=1))
        out = StringIO()

        call_command("delete_expired", "--dry-run", stdout=out)

        self.assertTrue(SharedPassword.objects.filter(id=expired.id).exists())
        self.assertIn("DRY RUN", out.getvalue())

    def test_reports_when_nothing_to_delete(self):
        """With no expired shares the command reports a clean run."""
        make_share(expires_at=timezone.now() + timedelta(days=1))
        out = StringIO()

        call_command("delete_expired", stdout=out)

        self.assertIn("No expired passwords", out.getvalue())
        self.assertEqual(SharedPassword.objects.count(), 1)

    def test_statistics_flag_outputs_stats(self):
        """--statistics prints the statistics block for expired shares."""
        make_share(expires_at=timezone.now() - timedelta(days=40))
        out = StringIO()

        call_command("delete_expired", "--statistics", stdout=out)

        output = out.getvalue()
        self.assertIn("Statistics", output)
        self.assertIn("Expired > 30 days ago", output)

    def test_batch_deletion_removes_all(self):
        """All expired shares are removed even when batched in small chunks."""
        for _ in range(3):
            make_share(expires_at=timezone.now() - timedelta(hours=1))

        call_command("delete_expired", batch_size=1, stdout=StringIO())

        self.assertEqual(SharedPassword.objects.count(), 0)

    def test_verbosity_zero_deletes_silently(self):
        """With --verbosity 0 expired shares are deleted without any output."""
        make_share(expires_at=timezone.now() - timedelta(hours=1))
        out = StringIO()

        call_command("delete_expired", verbosity=0, stdout=out)

        self.assertEqual(SharedPassword.objects.count(), 0)
        self.assertEqual(out.getvalue(), "")

    def test_noop_verbosity_zero_is_silent(self):
        """A clean run at --verbosity 0 prints nothing."""
        out = StringIO()

        call_command("delete_expired", verbosity=0, stdout=out)

        self.assertEqual(out.getvalue(), "")

    def test_verbose_dry_run_shows_samples_without_encrypted_data(self):
        """--dry-run -v2 lists sample records, capped at 10, without ciphertext.

        Titled and untitled shares get their placeholder labels; the encrypted
        title and data themselves must never be echoed.
        """
        secret = "U0VDUkVUX0NJUEhFUlRFWFQ="  # distinctive base64 blob
        for _ in range(6):
            make_share(
                expires_at=timezone.now() - timedelta(hours=1),
                encrypted_data=secret,
            )
        for _ in range(6):
            make_share(
                expires_at=timezone.now() - timedelta(hours=1),
                encrypted_data=secret,
                encrypted_title=secret,
                title_iv="BBBBBBBBBBBBBBBB",
            )
        out = StringIO()

        call_command("delete_expired", "--dry-run", verbosity=2, stdout=out)

        output = out.getvalue()
        self.assertIn("Sample Records", output)
        # 6 of each kind means the first 10 contain at least one of both labels.
        self.assertIn("(encrypted title)", output)
        self.assertIn("(No title)", output)
        self.assertIn("... and 2 more", output)
        self.assertNotIn(secret, output)
        # Dry run: everything is still there.
        self.assertEqual(SharedPassword.objects.count(), 12)

    def test_verbose_dry_run_with_few_records_omits_more_line(self):
        """With 10 or fewer records the sample list has no '... and N more' tail."""
        make_share(expires_at=timezone.now() - timedelta(hours=1))
        out = StringIO()

        call_command("delete_expired", "--dry-run", verbosity=2, stdout=out)

        output = out.getvalue()
        self.assertIn("Sample Records", output)
        self.assertNotIn("more", output)

    def test_dry_run_default_verbosity_omits_samples(self):
        """--dry-run without -v2 reports the count but no sample listing."""
        make_share(expires_at=timezone.now() - timedelta(hours=1))
        out = StringIO()

        call_command("delete_expired", "--dry-run", stdout=out)

        self.assertNotIn("Sample Records", out.getvalue())

    def test_deletion_error_is_wrapped_as_command_error(self):
        """A service failure during deletion surfaces as a CommandError."""
        make_share(expires_at=timezone.now() - timedelta(hours=1))

        with patch(
            "apps.passwd.management.commands.delete_expired.services.delete_expired_shares",
            side_effect=RuntimeError("db down"),
        ):
            with self.assertRaisesMessage(CommandError, "Error during deletion"):
                call_command("delete_expired", stdout=StringIO())

        self.assertEqual(SharedPassword.objects.count(), 1)
