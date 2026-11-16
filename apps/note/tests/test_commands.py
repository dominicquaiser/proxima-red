"""
Tests for the note app's management commands.

Covers delete_expired_notes (the scheduled sweeps) and delete_note (single-note
takedown removal).
"""

import uuid
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase
from django.utils import timezone

from apps.auth.tests.factories import create_user_with_password
from apps.note.constants import VAULT_TRASH_RETENTION_DAYS
from apps.note.models import LiveNote, LiveNoteUpdate, SharedNote, VaultNote

from .factories import (
    make_live_note,
    make_live_update,
    make_note,
    make_plain_note,
    make_vault_note,
)


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


class DeleteTrashedVaultNotesCommandTests(TestCase):
    """The vault-note sweep: same command, third pass.

    Vault notes have no expiry of their own; only the client-set ``trashed_at``
    flag plus the retention window makes one eligible.
    """

    def setUp(self):
        self.user = create_user_with_password("correct horse battery staple")
        self.window = timedelta(days=VAULT_TRASH_RETENTION_DAYS)
        self.due = make_vault_note(
            self.user, trashed_at=timezone.now() - self.window - timedelta(minutes=1)
        )
        self.recent = make_vault_note(self.user, trashed_at=timezone.now())
        self.active = make_vault_note(self.user)

    def test_deletes_only_notes_past_the_retention_window(self):
        output = run_command()

        self.assertFalse(VaultNote.objects.filter(pk=self.due.pk).exists())
        self.assertTrue(VaultNote.objects.filter(pk=self.recent.pk).exists())
        self.assertTrue(VaultNote.objects.filter(pk=self.active.pk).exists())
        self.assertIn("Successfully deleted 1 expired trashed vault note(s).", output)

    def test_dry_run_previews_without_deleting(self):
        output = run_command("--dry-run", verbosity=2)

        self.assertTrue(VaultNote.objects.filter(pk=self.due.pk).exists())
        self.assertIn("DRY RUN: Would delete 1 expired trashed vault note(s).", output)
        self.assertIn("| vault |", output)
        self.assertNotIn(self.due.content, output)

    def test_noop_message_when_nothing_is_due(self):
        self.due.delete()
        output = run_command()
        self.assertIn("No expired trashed vault notes to delete.", output)


def run_delete_note(*args, **kwargs):
    """Run delete_note and return its stdout."""
    out = StringIO()
    call_command("delete_note", *args, stdout=out, **kwargs)
    return out.getvalue()


class DeleteNoteCommandTests(TestCase):
    """delete_note: takedown removal of one shared or live note by its UUID."""

    def test_deletes_a_plain_text_shared_note(self):
        note = make_plain_note()

        output = run_delete_note(str(note.pk))

        self.assertFalse(SharedNote.objects.filter(pk=note.pk).exists())
        self.assertIn(f"Successfully deleted plain-text shared note {note.pk}.", output)

    def test_deletes_an_encrypted_shared_note(self):
        note = make_note()

        output = run_delete_note(str(note.pk))

        self.assertFalse(SharedNote.objects.filter(pk=note.pk).exists())
        self.assertIn(f"Successfully deleted encrypted shared note {note.pk}.", output)

    def test_deletes_a_live_note_with_its_updates(self):
        note = make_live_note()
        make_live_update(note)
        kept = make_live_update(make_live_note())

        output = run_delete_note(str(note.pk))

        self.assertFalse(LiveNote.objects.filter(pk=note.pk).exists())
        self.assertEqual(
            list(LiveNoteUpdate.objects.values_list("pk", flat=True)), [kept.pk]
        )
        self.assertIn(f"Successfully deleted live note {note.pk}.", output)

    def test_deletes_only_the_named_note(self):
        target = make_plain_note()
        other_note = make_plain_note()
        other_live = make_live_note()

        run_delete_note(str(target.pk))

        self.assertTrue(SharedNote.objects.filter(pk=other_note.pk).exists())
        self.assertTrue(LiveNote.objects.filter(pk=other_live.pk).exists())

    def test_dry_run_does_not_delete(self):
        note = make_plain_note()

        output = run_delete_note(str(note.pk), "--dry-run")

        self.assertTrue(SharedNote.objects.filter(pk=note.pk).exists())
        self.assertIn(f"DRY RUN: Would delete plain-text shared note {note.pk}.", output)

    def test_invalid_uuid_raises(self):
        with self.assertRaisesMessage(CommandError, "not a valid note UUID"):
            run_delete_note("not-a-uuid")

    def test_unknown_uuid_raises(self):
        with self.assertRaisesMessage(CommandError, "No shared note or live note found"):
            run_delete_note(str(uuid.uuid4()))

    def test_vault_notes_are_never_matched(self):
        """Vault notes have no public link, so no takedown id can reach one."""
        vault_note = make_vault_note(create_user_with_password("correct horse battery staple"))

        with self.assertRaises(CommandError):
            run_delete_note(str(vault_note.pk))

        self.assertTrue(VaultNote.objects.filter(pk=vault_note.pk).exists())

    def test_output_never_includes_note_content(self):
        """Metadata only: neither a plain-text body nor ciphertext is printed."""
        body = "MARKER-reported-plain-text-body"
        plain = make_plain_note(content=body)
        live = make_live_note()

        output = run_delete_note(str(plain.pk), "--dry-run")
        output += run_delete_note(str(live.pk), "--dry-run")

        self.assertNotIn(body, output)
        self.assertNotIn(live.snapshot, output)
        self.assertIn(f"Plain-text shared note {plain.pk} | created", output)
        self.assertIn(f"Live note {live.pk} | created", output)

    def test_verbosity_zero_deletes_silently(self):
        note = make_plain_note()

        output = run_delete_note(str(note.pk), verbosity=0)

        self.assertFalse(SharedNote.objects.filter(pk=note.pk).exists())
        self.assertEqual(output, "")

    def test_dry_run_verbosity_zero_is_silent(self):
        note = make_live_note()

        output = run_delete_note(str(note.pk), "--dry-run", verbosity=0)

        self.assertTrue(LiveNote.objects.filter(pk=note.pk).exists())
        self.assertEqual(output, "")

    def test_deletion_error_is_wrapped_as_command_error(self):
        note = make_plain_note()

        with patch.object(SharedNote, "delete", side_effect=RuntimeError("db down")):
            with self.assertRaisesMessage(CommandError, "Error during deletion"):
                run_delete_note(str(note.pk))

        self.assertTrue(SharedNote.objects.filter(pk=note.pk).exists())
