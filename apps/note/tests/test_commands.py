"""Tests for the delete_expired_notes management command."""

from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from apps.note.models import LiveNote, LiveNoteUpdate, SharedNote

from .factories import make_live_note, make_live_update, make_note, make_plain_note


def run_command(*args, **kwargs):
    """Run delete_expired_notes and return its stdout."""
    out = StringIO()
    call_command("delete_expired_notes", *args, stdout=out, **kwargs)
    return out.getvalue()


class DeleteExpiredNotesCommandTests(TestCase):
    """Command behavior: delete, dry-run, batching, output hygiene."""

    def setUp(self):
        self.expired = make_note(expires_at=timezone.now() - timedelta(minutes=1))
        self.active = make_note(expires_at=timezone.now() + timedelta(days=1))

    def test_deletes_only_expired_notes(self):
        output = run_command()

        self.assertFalse(SharedNote.objects.filter(pk=self.expired.pk).exists())
        self.assertTrue(SharedNote.objects.filter(pk=self.active.pk).exists())
        self.assertIn("Successfully deleted 1 expired note(s).", output)

    def test_dry_run_deletes_nothing(self):
        output = run_command("--dry-run")

        self.assertTrue(SharedNote.objects.filter(pk=self.expired.pk).exists())
        self.assertIn("DRY RUN", output)

    def test_batch_size_deletes_all(self):
        for _ in range(4):
            make_note(expires_at=timezone.now() - timedelta(minutes=1))

        run_command("--batch-size", "2")

        self.assertEqual(
            SharedNote.objects.filter(pk=self.active.pk).count(),
            SharedNote.objects.count(),
        )

    def test_noop_when_nothing_expired(self):
        self.expired.delete()
        output = run_command()
        self.assertIn("No expired notes to delete.", output)

    def test_verbosity_zero_is_silent(self):
        output = run_command(verbosity=0)
        self.assertEqual(output, "")

    def test_output_never_includes_note_content(self):
        """Dry-run samples print metadata only, never the body."""
        secret = "MARKER-super-secret-body"
        make_plain_note(
            content=secret, expires_at=timezone.now() - timedelta(minutes=1)
        )

        output = run_command("--dry-run", verbosity=2)

        self.assertNotIn(secret, output)
        self.assertIn("plain-text", output)


class DeleteExpiredLiveNotesCommandTests(TestCase):
    """The live-note sweep: same command, second pass."""

    def setUp(self):
        self.expired = make_live_note(expires_at=timezone.now() - timedelta(minutes=1))
        self.active = make_live_note(expires_at=timezone.now() + timedelta(days=1))

    def test_deletes_only_expired_live_notes_with_their_updates(self):
        make_live_update(self.expired)
        make_live_update(self.expired)
        kept = make_live_update(self.active)

        output = run_command()

        self.assertFalse(LiveNote.objects.filter(pk=self.expired.pk).exists())
        self.assertTrue(LiveNote.objects.filter(pk=self.active.pk).exists())
        self.assertEqual(
            list(LiveNoteUpdate.objects.values_list("pk", flat=True)), [kept.pk]
        )
        self.assertIn("Successfully deleted 1 expired live note(s).", output)

    def test_both_sweeps_report_independently(self):
        make_note(expires_at=timezone.now() - timedelta(minutes=1))

        output = run_command()

        self.assertIn("Successfully deleted 1 expired note(s).", output)
        self.assertIn("Successfully deleted 1 expired live note(s).", output)

    def test_dry_run_previews_live_notes_without_deleting(self):
        make_live_update(self.expired)

        output = run_command("--dry-run", verbosity=2)

        self.assertTrue(LiveNote.objects.filter(pk=self.expired.pk).exists())
        self.assertIn("DRY RUN: Would delete 1 expired live note(s).", output)
        self.assertIn("| live |", output)
        self.assertNotIn(self.expired.snapshot, output)

    def test_noop_message_when_no_live_notes_expired(self):
        self.expired.delete()
        output = run_command()
        self.assertIn("No expired live notes to delete.", output)
