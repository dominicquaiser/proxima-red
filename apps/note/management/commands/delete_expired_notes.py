"""
Django management command to delete expired shared notes and live notes.

This command can be run manually or scheduled via cron to automatically clean
up expired notes from the database. It is a lean mirror of the passwd tool's
``delete_expired`` (each tool owns its cleanup, so the apps stay independent).
It sweeps static shared notes, live notes (editable share links; their update
logs cascade with them), and vault notes that have sat in the user's Trash past
the retention window. Active vault notes have no expiry and never match: only
the client-set ``trashed_at`` flag makes a vault note eligible.

Usage:
    python manage.py delete_expired_notes
    python manage.py delete_expired_notes --dry-run
    python manage.py delete_expired_notes --verbosity 2
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.note import services


class Command(BaseCommand):
    """Delete expired shared notes and live notes.

    The command supports dry-run previews, configurable delete batches, and
    verbosity-controlled output.

    Attributes:
        help (str): Summary displayed by Django's command-line help.
    """

    help = (
        "Deletes shared notes and live notes that have passed their " "expiration date."
    )

    def add_arguments(self, parser):
        """Register note-cleanup command-line options.

        Args:
            parser (argparse.ArgumentParser): Django command argument parser.

        Returns:
            None: The parser is modified in place.
        """
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be deleted without actually deleting",
        )

        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of records to delete in each batch (default: 1000)",
        )

    def handle(self, *args, **options):
        """Execute the expired-note cleanup, one sweep per note kind.

        Args:
            *args (Any): Positional command arguments supplied by Django.
            **options (Any): Parsed command options, including ``dry_run``,
                ``batch_size``, and ``verbosity``.

        Returns:
            None: The command reports its result through Django's output
                streams.

        Raises:
            CommandError: If deleting expired records fails.
        """
        now = timezone.now()

        self._run_sweep(
            label="note",
            queryset=services.expired_notes(now=now),
            delete=lambda batch_size: services.delete_expired_notes(
                now=now, batch_size=batch_size
            ),
            sample_line=self._shared_note_sample,
            options=options,
        )
        self._run_sweep(
            label="live note",
            queryset=services.expired_live_notes(now=now),
            delete=lambda batch_size: services.delete_expired_live_notes(
                now=now, batch_size=batch_size
            ),
            sample_line=self._live_note_sample,
            options=options,
        )
        self._run_sweep(
            label="trashed vault note",
            queryset=services.expired_trashed_vault_notes(now=now),
            delete=lambda batch_size: services.delete_expired_trashed_vault_notes(
                now=now, batch_size=batch_size
            ),
            sample_line=self._vault_note_sample,
            options=options,
        )

    def _run_sweep(self, *, label, queryset, delete, sample_line, options):
        """Count, preview, and (unless dry-running) delete one note kind.

        Args:
            label (str): Human-readable singular kind name for the messages.
            queryset (QuerySet): The kind's expired rows.
            delete (callable): One-argument callable running the batched
                deletion for the shared cutoff and returning the count.
            sample_line (callable): Formats one row for the dry-run preview.
            options (dict): Parsed command options.

        Returns:
            None: Output is written to the command's standard output stream.

        Raises:
            CommandError: If the service cannot delete the records.
        """
        verbosity = options["verbosity"]
        total_count = queryset.count()

        self._show_summary(label, total_count, options["dry_run"], verbosity)

        if total_count == 0:
            if verbosity >= 1:
                self.stdout.write(self.style.SUCCESS(f"No expired {label}s to delete."))
            return

        if options["dry_run"]:
            if verbosity >= 2:
                self._show_samples(queryset, sample_line)
            return

        try:
            deleted_count = delete(options["batch_size"])
        except Exception as e:
            raise CommandError(f"Error during deletion: {e}")

        if verbosity >= 1:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully deleted {deleted_count} expired {label}(s)."
                )
            )

    def _show_summary(self, label, total_count, dry_run, verbosity):
        """Print the initial cleanup summary when output is enabled.

        Args:
            label (str): Human-readable singular kind name.
            total_count (int): Number of expired rows.
            dry_run (bool): Whether the command is running without deletion.
            verbosity (int): Django command verbosity level.

        Returns:
            None: Output is written to the command's standard output stream.
        """
        if verbosity < 1:
            return
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"DRY RUN: Would delete {total_count} expired {label}(s)."
                )
            )
            return
        self.stdout.write(f"Found {total_count} expired {label}(s) to delete.")

    def _show_samples(self, queryset, sample_line):
        """Display sample records that would be deleted.

        Only non-sensitive metadata is printed: the body is (or may be)
        encrypted, and even plain-text bodies are user content that has no
        place in logs.

        At most 10 rows are shown so verbose dry runs remain readable.

        Args:
            queryset (QuerySet): Expired rows to preview.
            sample_line (callable): Formats one row into a log-safe line.

        Returns:
            None: Sample metadata is written to the command's standard output
                stream.
        """
        self.stdout.write(self.style.WARNING("\n--- Sample Records (first 10) ---"))

        for row in queryset[:10]:
            self.stdout.write(sample_line(row))

        if queryset.count() > 10:
            self.stdout.write(f"  ... and {queryset.count() - 10} more")

        self.stdout.write(self.style.WARNING("--- End Sample Records ---\n"))

    @staticmethod
    def _shared_note_sample(note):
        """Format one expired shared note as a non-sensitive preview line."""
        mode = "encrypted" if note.is_encrypted else "plain-text"
        return (
            f"  - {str(note.id)[:8]}... | {mode} | "
            f"Expired: {note.expires_at.isoformat()} | "
            f"Accesses: {note.access_count}"
        )

    @staticmethod
    def _live_note_sample(note):
        """Format one expired live note as a non-sensitive preview line."""
        return (
            f"  - {str(note.id)[:8]}... | live | "
            f"Expired: {note.expires_at.isoformat()} | "
            f"Pending updates: {note.updates.count()} | "
            f"Accesses: {note.access_count}"
        )

    @staticmethod
    def _vault_note_sample(note):
        """Format one expired trashed vault note as a preview line.

        Vault notes have no name and no access counter, and their body is
        ciphertext, so the size is the only other non-sensitive detail worth
        printing.
        """
        return (
            f"  - {str(note.id)[:8]}... | vault | "
            f"Trashed: {note.trashed_at.isoformat()} | "
            f"Size: {len(note.content)}"
        )
