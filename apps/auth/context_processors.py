"""
Template context processor exposing the session-authenticated user.

This project authenticates via a custom session flag (see ``apps.auth``), not
Django's ``request.user``, so Django's ``auth`` context processor is
intentionally *not* enabled (its ``{{ user }}`` would always be
``AnonymousUser`` here, a silent footgun). Templates should use
``{{ current_user }}`` instead, which resolves to the real ``User`` for an
authenticated session or ``None`` otherwise.
"""

from django.http import HttpRequest
from django.utils.functional import SimpleLazyObject

from .services import get_user_by_id
from .utils import get_authenticated_user_id


def current_user(request: HttpRequest) -> dict:
    """
    Expose the session's ``User`` (or ``None``) to every template.

    The lookup is wrapped in ``SimpleLazyObject`` so the database is only hit
    when a template actually references ``current_user`` — mirroring Django's
    own ``auth`` context processor.
    """

    def resolve():
        user_id = get_authenticated_user_id(request)
        return get_user_by_id(user_id) if user_id else None

    return {"current_user": SimpleLazyObject(resolve)}
