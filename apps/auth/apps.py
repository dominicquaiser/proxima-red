"""App configuration for the custom authentication app."""

from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.auth"
    label = "proxima_auth"  # Avoid conflict with Django's built-in 'auth' app
    verbose_name = "Authentication"
