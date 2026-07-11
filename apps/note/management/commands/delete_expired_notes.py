"""
Django management command to delete expired shared notes.

This command can be run manually or scheduled via cron to automatically clean
up expired notes from the database. It is a lean mirror of the passwd tool's
``delete_expired`` (each tool owns its cleanup, so the apps stay independent).

Usage:
    python manage.py delete_expired_notes
    python manage.py delete_expired_notes --dry-run
    python manage.py delete_expired_notes --verbosity 2
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.note import services


class Command(BaseCommand):
    """Delete expired shared notes.

    The command supports dry-run previews, configurable delete batches, and
    verbosity-controlled output.

    Attributes:
        help (str): Summary displayed by Django's command-line help.
    """

    help = "Deletes shared notes that have passed their expiration date."

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
        """Execute the expired-note cleanup.

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
        expired = services.expired_notes(now=now)
        total_count = expired.count()

        self._show_summary(total_count, options["dry_run"], options["verbosity"])

        if total_count == 0:
            if options["verbosity"] >= 1:
                self.stdout.write(self.style.SUCCESS("No expired notes to delete."))
            return

        if options["dry_run"]:
            if options["verbosity"] >= 2:
                self._show_samples(expired)
            return

        self._delete_expired(now, options["batch_size"], options["verbosity"])

    def _show_summary(self, total_count, dry_run, verbosity):
        """Print the initial cleanup summary when output is enabled.

        Args:
            total_count (int): Number of expired notes.
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
                    f"DRY RUN: Would delete {total_count} expired note(s)."
                )
            )
            return
        self.stdout.write(f"Found {total_count} expired note(s) to delete.")

    def _delete_expired(self, now, batch_size, verbosity):
        """Delete expired records and print the final summary.

        Args:
            now (datetime.datetime): Expiry cutoff shared with the initial
                count query.
            batch_size (int): Maximum records deleted per batch.
            verbosity (int): Django command verbosity level.

        Returns:
            None: Records are deleted and output is written to the command's
                standard output stream.

        Raises:
            CommandError: If the service cannot delete the records.
        """
        try:
            deleted_count = services.delete_expired_notes(
                now=now, batch_size=batch_size
            )
        except Exception as e:
            raise CommandError(f"Error during deletion: {e}")

        if verbosity >= 1:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully deleted {deleted_count} expired note(s)."
                )
            )

    def _show_samples(self, queryset):
        """Display sample records that would be deleted.

        Only non-sensitive metadata is printed: the body may be encrypted, and
        even plain-text bodies are user content that has no place in logs.

        At most 10 rows are shown so verbose dry runs remain readable.

        Args:
            queryset (QuerySet[SharedNote]): Expired notes to preview.

        Returns:
            None: Sample metadata is written to the command's standard output
                stream.
        """
        self.stdout.write(self.style.WARNING("\n--- Sample Records (first 10) ---"))

        for note in queryset[:10]:
            mode = "encrypted" if note.is_encrypted else "plain-text"
            self.stdout.write(
                f"  - {str(note.id)[:8]}... | {mode} | "
                f"Expired: {note.expires_at.isoformat()} | "
                f"Accesses: {note.access_count}"
            )

        if queryset.count() > 10:
            self.stdout.write(f"  ... and {queryset.count() - 10} more")

        self.stdout.write(self.style.WARNING("--- End Sample Records ---\n"))
