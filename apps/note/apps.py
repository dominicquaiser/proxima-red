"""Django application configuration for the note sharing app."""

from django.apps import AppConfig


class NoteConfig(AppConfig):
    """Configure the note app for Django's application registry.

    Attributes:
        default_auto_field (str): Default model primary-key field class.
        name (str): Dotted Python path to the application.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.note"
