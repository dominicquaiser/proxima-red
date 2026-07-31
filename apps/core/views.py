"""
Views for the core app: static informational pages and the project's custom
error handlers (wired up as ``handler400``/``403``/``404``/``500`` in
``config/urls.py``).
"""

from datetime import date

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

# Host classification lives in apps.core.hosts (a leaf module) so tool apps
# can host-gate their own views without importing this dispatcher module.
from .hosts import is_main_site, is_note_site, is_pass_subdomain


def pgp_key(request: HttpRequest) -> HttpResponse:
    key = (settings.BASE_DIR / "static" / "pgp-key.asc").read_text()
    return HttpResponse(key, content_type="application/pgp-keys")


def index(request: HttpRequest) -> HttpResponse:
    """Root URL: the landing page on the main proxima.red host, the note editor
    on the note subdomain, the share form on the pass subdomain (and any other
    host).

    All sites are served from one Django instance over ``/``; this dispatches
    by host the same way ``robots.txt``/``sitemap.xml`` do.

    The landing page is read-only, so only safe-method requests are claimed for
    it. A note-host request (any method) goes to the note tool; everything else
    falls through to the share view - notably the vault's create-share POST,
    which reverses to ``passwd:create`` (``/``) and must reach the JSON
    endpoint regardless of which host the vault was opened on.
    """
    if request.method in ("GET", "HEAD") and is_main_site(request):
        return render(request, "core/index.html")
    if is_note_site(request):
        # Imported here to avoid a core -> note import at module load.
        from apps.note.views import CreateNoteView

        return CreateNoteView.as_view()(request)
    # Imported here to avoid a core -> passwd import at module load.
    from apps.passwd.views import CreateShareView

    return CreateShareView.as_view()(request)


def retrieve_dispatch(request: HttpRequest, pk) -> HttpResponse:
    """``/<uuid>/``: a note on the note subdomain, a password share elsewhere.

    Same host-dispatch arrangement as ``index``: core claims the path first
    (see config/urls.py) while both tools keep their own ``<uuid:pk>/`` route
    reversible. A UUID opened on the wrong host 404s in the dispatched view,
    which is correct - the two tools' share spaces are separate.
    """
    if is_note_site(request):
        # Imported here to avoid a core -> note import at module load.
        from apps.note.views import RetrieveNoteView

        return RetrieveNoteView.as_view()(request, pk=pk)
    # Imported here to avoid a core -> passwd import at module load.
    from apps.passwd.views import RetrieveShareView

    return RetrieveShareView.as_view()(request, pk=pk)


def vault_dispatch(request: HttpRequest) -> HttpResponse:
    """``/vault/``: the note vault on the note subdomain, the passwd vault
    elsewhere.

    Same host-dispatch arrangement as ``index``/``retrieve_dispatch``: core
    claims the path first (see config/urls.py) while both tools keep their own
    ``vault/`` route reversible. The vaults' JSON APIs need no dispatch — their
    literal paths (``/vault-data/`` vs ``/vault/index/`` etc.) don't collide.
    """
    if is_note_site(request):
        # Imported here to avoid a core -> note import at module load.
        from apps.note.views import NoteVaultView

        return NoteVaultView.as_view()(request)
    # Imported here to avoid a core -> passwd import at module load.
    from apps.passwd.views import VaultView

    return VaultView.as_view()(request)


def robots_txt(request: HttpRequest) -> HttpResponse:
    if is_pass_subdomain(request):
        lines = [
            "User-agent: *",
            "Disallow: /vault/",
            "Disallow: /vault-data/",
            "Disallow: /update-data/",
            "Disallow: /export-data/",
            "",
            f"Sitemap: {settings.PASS_SITE_URL}/sitemap.xml",
        ]
    elif is_note_site(request):
        # Retrieve pages need no Disallow: they are unguessable UUIDs and
        # carry a noindex meta tag themselves. /vault/ covers the vault page
        # and every vault JSON API beneath it.
        lines = [
            "User-agent: *",
            "Disallow: /vault/",
            "",
            f"Sitemap: {settings.NOTE_SITE_URL}/sitemap.xml",
        ]
    else:
        lines = [
            "User-agent: *",
            "Disallow: /auth/account/",
            "Disallow: /auth/salts/",
            "Disallow: /auth/signout/",
            "",
            f"Sitemap: {settings.SITE_URL}/sitemap.xml",
        ]
    return HttpResponse("\n".join(lines), content_type="text/plain; charset=utf-8")


def sitemap(request: HttpRequest) -> HttpResponse:
    lastmod = date.today().isoformat()
    if is_pass_subdomain(request):
        return render(
            request,
            "core/sitemap_pass.xml",
            {"site_url": settings.PASS_SITE_URL, "lastmod": lastmod},
            content_type="application/xml",
        )
    if is_note_site(request):
        return render(
            request,
            "core/sitemap_note.xml",
            {"site_url": settings.NOTE_SITE_URL, "lastmod": lastmod},
            content_type="application/xml",
        )
    return render(
        request,
        "core/sitemap_proxima.xml",
        {"site_url": settings.SITE_URL, "lastmod": lastmod},
        content_type="application/xml",
    )


def imprint(request: HttpRequest) -> HttpResponse:
    """Render the imprint / legal-notice page."""
    return render(request, "core/imprint.html")


def privacy(request: HttpRequest) -> HttpResponse:
    """Render the privacy-policy page."""
    return render(request, "core/privacy.html")


def about(request: HttpRequest) -> HttpResponse:
    """Render the about page."""
    return render(request, "core/about.html")


def _render_error(
    request: HttpRequest, template_name: str, status: int
) -> HttpResponse:
    """Render one of the styled error pages."""
    return render(request, template_name, status=status)


def error_400(request: HttpRequest, exception: Exception) -> HttpResponse:
    """Render the styled 400 (Bad Request) page."""
    return _render_error(request, "core/400.html", 400)


def error_403(request: HttpRequest, exception: Exception) -> HttpResponse:
    """Render the styled 403 (Forbidden) page."""
    return _render_error(request, "core/403.html", 403)


def error_404(request: HttpRequest, exception: Exception) -> HttpResponse:
    """Render the styled 404 (Not Found) page."""
    return _render_error(request, "core/404.html", 404)


def error_500(request: HttpRequest) -> HttpResponse:
    """Render the styled 500 (Server Error) page.

    Unlike the 400/403/404 handlers, Django invokes ``handler500`` with only the
    request and no ``exception`` argument, so this signature omits it on purpose.
    """
    return _render_error(request, "core/500.html", 500)
