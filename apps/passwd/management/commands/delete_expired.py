"""
Django management command to delete expired shared passwords.

This command can be run manually or scheduled via cron/celery to
automatically clean up expired password shares from the database.

Usage:
    python manage.py delete_expired
    python manage.py delete_expired --dry-run
    python manage.py delete_expired --verbosity 2
    python manage.py delete_expired --statistics
"""

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Avg
from django.utils import timezone

from apps.passwd import services


class Command(BaseCommand):
    """
    Management command to delete expired shared passwords.

    This command finds all SharedPassword objects where 'expires_at' is in
    the past and deletes them. Supports dry-run mode for testing and
    verbose output for monitoring.
    """

    help = "Deletes shared passwords that have passed their expiration date."

    def add_arguments(self, parser):
        """
        Add command-line arguments.

        Args:
            parser: ArgumentParser instance
        """
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be deleted without actually deleting",
        )

        parser.add_argument(
            "--statistics",
            action="store_true",
            help="Show detailed statistics about expired shares",
        )

        parser.add_argument(
            "--batch-size",
            type=int,
            default=1000,
            help="Number of records to delete in each batch (default: 1000)",
        )

    def handle(self, *args, **options):
        """
        Execute the command logic.

        Args:
            *args: Positional arguments
            **options: Command options from add_arguments

        Returns:
            None

        Raises:
            CommandError: If an error occurs during execution
        """
        now = timezone.now()
        expired_passwords = services.expired_shares(now=now)
        total_count = expired_passwords.count()

        self._show_summary(total_count, options["dry_run"], options["verbosity"])

        if options["statistics"] and total_count > 0:
            self._show_statistics(expired_passwords, now, options["verbosity"])

        if total_count == 0:
            self._show_noop(options["verbosity"])
            return

        if options["dry_run"]:
            self._show_dry_run_samples(expired_passwords, options["verbosity"])
            return

        self._delete_expired(now, options["batch_size"], options["verbosity"])

    def _show_summary(self, total_count, dry_run, verbosity):
        """Print the initial deletion summary when command output is enabled."""
        if verbosity < 1:
            return
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"DRY RUN: Would delete {total_count} expired password(s)."
                )
            )
            return
        self.stdout.write(f"Found {total_count} expired password(s) to delete.")

    def _show_noop(self, verbosity):
        """Print the no-op message when no expired records exist."""
        if verbosity >= 1:
            self.stdout.write(self.style.SUCCESS("No expired passwords to delete."))

    def _show_dry_run_samples(self, expired_passwords, verbosity):
        """Print sample records in verbose dry-run mode."""
        if verbosity >= 2:
            self._show_samples(expired_passwords)

    def _delete_expired(self, now, batch_size, verbosity):
        """Delete expired records via the service and print the final summary."""
        try:
            deleted_count = services.delete_expired_shares(
                now=now, batch_size=batch_size
            )
        except Exception as e:
            raise CommandError(f"Error during deletion: {e}")

        if verbosity >= 1:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully deleted {deleted_count} expired password(s)."
                )
            )

    def _show_statistics(self, queryset, now, verbosity):
        """
        Display detailed statistics about expired shares.

        Args:
            queryset: QuerySet of expired shares
            now: Current timestamp
            verbosity: Verbosity level for output
        """
        self.stdout.write(self.style.WARNING("\n--- Statistics ---"))

        # Age distribution
        very_old = queryset.filter(expires_at__lt=now - timedelta(days=30)).count()
        old = queryset.filter(
            expires_at__gte=now - timedelta(days=30),
            expires_at__lt=now - timedelta(days=7),
        ).count()
        recent = queryset.filter(expires_at__gte=now - timedelta(days=7)).count()

        self.stdout.write(f"Expired > 30 days ago: {very_old}")
        self.stdout.write(f"Expired 7-30 days ago: {old}")
        self.stdout.write(f"Expired < 7 days ago: {recent}")

        # Access statistics
        never_accessed = queryset.filter(access_count=0).count()
        self.stdout.write(f"Never accessed: {never_accessed}")

        # Average access count
        avg_access = queryset.aggregate(Avg("access_count"))["access_count__avg"] or 0
        self.stdout.write(f"Average access count: {avg_access:.2f}")

        self.stdout.write(self.style.WARNING("--- End Statistics ---\n"))

    def _show_samples(self, queryset):
        """
        Display sample records that would be deleted.

        Args:
            queryset: QuerySet of records to delete
        """
        self.stdout.write(self.style.WARNING("\n--- Sample Records (first 10) ---"))

        for share in queryset[:10]:
            # The title is encrypted client-side and cannot be shown here.
            title = "(encrypted title)" if share.encrypted_title else "(No title)"
            self.stdout.write(
                f"  - {str(share.id)[:8]}... | {title} | "
                f"Expired: {share.expires_at.isoformat()} | "
                f"Accesses: {share.access_count}"
            )

        if queryset.count() > 10:
            self.stdout.write(f"  ... and {queryset.count() - 10} more")

        self.stdout.write(self.style.WARNING("--- End Sample Records ---\n"))
