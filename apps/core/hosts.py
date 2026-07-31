"""
Host classification for the multi-site dispatch.

One Django instance serves three hosts (``SITE_URL``, ``PASS_SITE_URL``,
``NOTE_SITE_URL``); these helpers say which one a request arrived on. They
live in a leaf module (like ``apps.core.http``) so tool apps can host-gate
their own views — e.g. the note tool's live page — without importing
``apps.core.views``, whose dispatchers import tool views in return.
"""

from urllib.parse import urlparse

from django.conf import settings
from django.http import HttpRequest


def is_pass_subdomain(request: HttpRequest) -> bool:
    """Return True when the request arrives on the pass.proxima.red subdomain."""
    host = request.get_host().split(":")[0]
    return host == (urlparse(settings.PASS_SITE_URL).hostname or "")


def is_note_site(request: HttpRequest) -> bool:
    """Return True when the request arrives on the note.proxima.red subdomain.

    The pass subdomain wins ties: in environments where all site URLs share a
    host (local dev without env vars, the test suite), requests keep resolving
    to the passwd tool exactly as they did before the note tool existed.
    """
    host = request.get_host().split(":")[0]
    note_host = urlparse(settings.NOTE_SITE_URL).hostname or ""
    return host == note_host and not is_pass_subdomain(request)


def is_main_site(request: HttpRequest) -> bool:
    """Return True when the request arrives on the main proxima.red host.

    Excludes the pass subdomain so that, in environments where both sites share
    a host (local dev, the test suite), the request resolves to the share form
    rather than the landing page.
    """
    host = request.get_host().split(":")[0]
    main_host = urlparse(settings.SITE_URL).hostname or ""
    return host == main_host and not is_pass_subdomain(request)
