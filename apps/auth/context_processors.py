"""
Template context processors for the session user and the host's vault tool.

This project authenticates via a custom session flag (see ``apps.auth``), not
Django's ``request.user``, so Django's ``auth`` context processor is
intentionally *not* enabled (its ``{{ user }}`` would always be
``AnonymousUser`` here, a silent footgun). Templates should use
``{{ current_user }}`` instead, which resolves to the real ``User`` for an
authenticated session or ``None`` otherwise.
"""

from django.core.exceptions import DisallowedHost
from django.http import HttpRequest
from django.utils.functional import SimpleLazyObject

from apps.core.hosts import is_main_site, is_note_site

from .constants import DEFAULT_VAULT_TOOL, VAULT_TOOL_NOTE
from .services import get_user_by_id
from .utils import get_authenticated_user_id


def current_user(request: HttpRequest) -> dict:
    """
    Expose the session's ``User`` (or ``None``) to every template.

    The lookup is wrapped in ``SimpleLazyObject`` so the database is only hit
    when a template actually references ``current_user`` - mirroring Django's
    own ``auth`` context processor.
    """

    def resolve():
        user_id = get_authenticated_user_id(request)
        return get_user_by_id(user_id) if user_id else None

    return {"current_user": SimpleLazyObject(resolve)}


def host_tool(request: HttpRequest) -> dict:
    """
    Expose the vault tool of the host serving the page as ``{{ host_tool }}``.

    Auth lives on the main site, so the shared header's Sign In / Sign Up
    links must say which vault the flow should land on: ``note`` on the note
    host and on the main site (which has no vault of its own), the default
    everywhere else. The auth pages pass their own vetted ``tool``, which the
    header prefers.

    ``get_host()`` raises ``DisallowedHost`` for a junk ``Host`` header, and
    the error page rendered for that request uses the same header, so it falls
    back to the default instead of turning a clean 400 into a 500.
    """
    try:
        leads_to_notes = is_note_site(request) or is_main_site(request)
    except DisallowedHost:
        leads_to_notes = False
    return {"host_tool": VAULT_TOOL_NOTE if leads_to_notes else DEFAULT_VAULT_TOOL}
