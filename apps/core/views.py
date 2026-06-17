"""
Views for the core app: static informational pages and the project's custom
error handlers (wired up as ``handler400``/``403``/``404``/``500`` in
``config/urls.py``).
"""

from urllib.parse import urlparse

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


def pgp_key(request: HttpRequest) -> HttpResponse:
    key = (settings.BASE_DIR / "static" / "pgp-key.asc").read_text()
    return HttpResponse(key, content_type="application/pgp-keys")


def _is_pass_subdomain(request: HttpRequest) -> bool:
    """Return True when the request arrives on the pass.proxima.red subdomain."""
    host = request.get_host().split(":")[0]
    return host == (urlparse(settings.PASS_SITE_URL).hostname or "")


def _is_main_site(request: HttpRequest) -> bool:
    """Return True when the request arrives on the main proxima.red host.

    Excludes the pass subdomain so that, in environments where both sites share
    a host (local dev, the test suite), the request resolves to the share form
    rather than the landing page.
    """
    host = request.get_host().split(":")[0]
    main_host = urlparse(settings.SITE_URL).hostname or ""
    return host == main_host and not _is_pass_subdomain(request)


def index(request: HttpRequest) -> HttpResponse:
    """Root URL: the landing page on the main proxima.red host, the share form
    on the pass subdomain (and any other host).

    Both sites are served from one Django instance over ``/``; this dispatches
    by host the same way ``robots.txt``/``sitemap.xml`` do.
    """
    if _is_main_site(request):
        return render(request, "core/index.html")
    # Imported here to avoid a core -> passwd import at module load.
    from apps.passwd.views import CreateShareView

    return CreateShareView.as_view()(request)


def robots_txt(request: HttpRequest) -> HttpResponse:
    if _is_pass_subdomain(request):
        lines = [
            "User-agent: *",
            "Disallow: /vault/",
            "Disallow: /vault-data/",
            "Disallow: /update-data/",
            "Disallow: /export-data/",
            "",
            f"Sitemap: {settings.PASS_SITE_URL}/sitemap.xml",
        ]
    else:
        lines = [
            "User-agent: *",
            "Disallow: /auth/account/",
            "",
            f"Sitemap: {settings.SITE_URL}/sitemap.xml",
        ]
    return HttpResponse("\n".join(lines), content_type="text/plain; charset=utf-8")


def sitemap(request: HttpRequest) -> HttpResponse:
    if _is_pass_subdomain(request):
        return render(
            request,
            "core/sitemap_pass.xml",
            {"site_url": settings.PASS_SITE_URL},
            content_type="application/xml",
        )
    return render(
        request,
        "core/sitemap_proxima.xml",
        {"site_url": settings.SITE_URL},
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
