"""
Django management command to delete a single shared note or live note by its ID.

The note tool's counterpart to ``delete_share``, intended for handling
takedown / removal requests. A report references a note by its public URL:
``/<uuid>/`` for a shared note (followed by ``#key`` when it is encrypted) or
``/live/<uuid>/#key`` for an editable live note. That UUID is the note's
primary key; the key after ``#`` never reaches the server and is not needed to
delete.

Unlike a password share, a plain-text shared note is readable by the server,
which makes notes the likelier subject of a takedown request. Encrypted notes
and live notes can only be read through the reported link. Either way, removal
acts on the supplied identifier, and the command never prints note contents.
Deleting a live note also deletes its pending update rows; anyone still
editing it gets the same "not found" as for an expired note.

Usage:
    python manage.py delete_note <uuid>
    python manage.py delete_note <uuid> --dry-run
    python manage.py delete_note <uuid> --verbosity 2
"""

import uuid

from django.core.management.base import BaseCommand, CommandError

from apps.note.models import LiveNote, SharedNote


class Command(BaseCommand):
    """
    Management command to delete one SharedNote or LiveNote by its UUID.

    Validates the identifier, reports the note's non-sensitive metadata (never
    its contents), and deletes it. Supports dry-run mode.
    """

    help = "Deletes a single shared note or live note by its UUID (for takedown requests)."

    def add_arguments(self, parser):
        """
        Add command-line arguments.

        Args:
            parser: ArgumentParser instance
        """
        parser.add_argument(
            "note_id",
            help=(
                "UUID of the note to delete: the path segment before any '#' "
                "in its link (after /live/ for a live note)"
            ),
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
            CommandError: If the identifier is invalid or no note is found
        """
        dry_run = options["dry_run"]
        verbosity = options["verbosity"]

        note_uuid = self._parse_note_uuid(options["note_id"])
        note = self._get_note(note_uuid)
        kind = self._describe_kind(note)

        self._show_note_summary(note, kind, verbosity)

        if dry_run:
            if verbosity >= 1:
                self.stdout.write(
                    self.style.WARNING(f"DRY RUN: Would delete {kind} {note.id}.")
                )
            return

        self._delete_note(note)

        if verbosity >= 1:
            self.stdout.write(
                self.style.SUCCESS(f"Successfully deleted {kind} {note_uuid}.")
            )

    def _parse_note_uuid(self, raw_id):
        """Parse the CLI note id into a UUID or raise CommandError."""
        try:
            return uuid.UUID(str(raw_id))
        except (ValueError, AttributeError, TypeError):
            raise CommandError(f"'{raw_id}' is not a valid note UUID.")

    def _get_note(self, note_uuid):
        """Return the shared or live note for ``note_uuid`` or raise CommandError."""
        for model in (SharedNote, LiveNote):
            note = model.objects.filter(id=note_uuid).first()
            if note is not None:
                return note
        raise CommandError(f"No shared note or live note found with ID {note_uuid}.")

    def _describe_kind(self, note):
        """Name the kind of note for output, e.g. 'plain-text shared note'."""
        if isinstance(note, LiveNote):
            return "live note"
        return "encrypted shared note" if note.is_encrypted else "plain-text shared note"

    def _show_note_summary(self, note, kind, verbosity):
        """Print non-sensitive note metadata."""
        if verbosity < 1:
            return

        self.stdout.write(
            f"{kind.capitalize()} {note.id} | "
            f"created {note.created_at.isoformat()} | "
            f"expires {note.expires_at.isoformat()} | "
            f"accesses {note.access_count}"
        )

    def _delete_note(self, note):
        """Delete the note, wrapping database errors as CommandError."""
        try:
            note.delete()
        except Exception as e:
            raise CommandError(f"Error during deletion: {e}")
