"""
Django management command to delete a single shared password by its ID.

Intended for handling takedown / removal requests: a report references a
share by its public URL (``/<uuid>/#key``), and the UUID before the ``#`` is
this share's primary key. The key after ``#`` never reaches the server and is
not needed to delete. The secret itself is encrypted client-side and cannot be
inspected here, so removal acts on the supplied identifier, not its contents.

Usage:
    python manage.py delete_share <uuid>
    python manage.py delete_share <uuid> --dry-run
    python manage.py delete_share <uuid> --verbosity 2
"""

import uuid

from django.core.management.base import BaseCommand, CommandError

from apps.passwd.models import SharedPassword


class Command(BaseCommand):
    """
    Management command to delete one SharedPassword by its UUID.

    Validates the identifier, reports the share's non-sensitive metadata
    (never the encrypted contents), and deletes it. Supports dry-run mode.
    """

    help = "Deletes a single shared password by its UUID (for takedown requests)."

    def add_arguments(self, parser):
        """
        Add command-line arguments.

        Args:
            parser: ArgumentParser instance
        """
        parser.add_argument(
            "share_id",
            help="UUID of the share to delete (the part before '#' in the URL)",
        )

        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview what would be deleted without actually deleting",
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
            CommandError: If the identifier is invalid or no share is found
        """
        dry_run = options["dry_run"]
        verbosity = options["verbosity"]

        share_uuid = self._parse_share_uuid(options["share_id"])
        share = self._get_share(share_uuid)

        self._show_share_summary(share, verbosity)

        if dry_run:
            self._show_dry_run(share, verbosity)
            return

        self._delete_share(share)

        if verbosity >= 1:
            self.stdout.write(
                self.style.SUCCESS(f"Successfully deleted share {share_uuid}.")
            )

    def _parse_share_uuid(self, raw_id):
        """Parse the CLI share id into a UUID or raise CommandError."""
        try:
            return uuid.UUID(str(raw_id))
        except (ValueError, AttributeError, TypeError):
            raise CommandError(f"'{raw_id}' is not a valid share UUID.")

    def _get_share(self, share_uuid):
        """Return the share for ``share_uuid`` or raise CommandError."""
        try:
            return SharedPassword.objects.get(id=share_uuid)
        except SharedPassword.DoesNotExist:
            raise CommandError(f"No share found with ID {share_uuid}.")

    def _show_share_summary(self, share, verbosity):
        """Print non-sensitive share metadata."""
        if verbosity < 1:
            return

        title = "(encrypted title)" if share.encrypted_title else "(no title)"
        self.stdout.write(
            f"Share {share.id} | {title} | "
            f"created {share.created_at.isoformat()} | "
            f"expires {share.expires_at.isoformat()} | "
            f"accesses {share.access_count}"
        )

    def _show_dry_run(self, share, verbosity):
        """Print the dry-run deletion message."""
        if verbosity >= 1:
            self.stdout.write(
                self.style.WARNING(f"DRY RUN: Would delete share {share.id}.")
            )

    def _delete_share(self, share):
        """Delete the share, wrapping database errors as CommandError."""
        try:
            share.delete()
        except Exception as e:
            raise CommandError(f"Error during deletion: {e}")
