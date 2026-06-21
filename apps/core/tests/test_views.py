"""
Tests for the core app views.

Covers the static informational pages (about/imprint/privacy), the
host-dependent robots.txt/sitemap.xml views, and the custom error handlers
wired up as ``handler400``/``403``/``404``/``500`` in ``config/urls.py``. The
error handlers are invoked directly via RequestFactory so the assertions don't
depend on ``DEBUG`` or on triggering real failures.
"""

from django.http import HttpResponse
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.core import views
from apps.core.middleware import SecurityHeadersMiddleware


class StaticPageTests(TestCase):
    """The informational pages render with their templates."""

    def setUp(self):
        self.client = Client()

    def test_about_page(self):
        """GET about/ renders the about page."""
        response = self.client.get(reverse("core:about"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/about.html")

    def test_imprint_page(self):
        """GET imprint/ renders the imprint page."""
        response = self.client.get(reverse("core:imprint"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/imprint.html")

    def test_privacy_page(self):
        """GET privacy/ renders the privacy page."""
        response = self.client.get(reverse("core:privacy"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/privacy.html")


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "testserver"],
)
class IndexViewTests(TestCase):
    """The root URL dispatches by host: landing page vs. share form."""

    def setUp(self):
        self.client = Client()

    def test_main_site_renders_landing(self):
        """GET / on the main host renders the landing page."""
        response = self.client.get("/", HTTP_HOST="proxima.red")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/index.html")

    def test_pass_subdomain_renders_share_form(self):
        """GET / on the pass subdomain renders the create-share form."""
        response = self.client.get("/", HTTP_HOST="pass.proxima.red")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/create.html")

    def test_unrelated_host_renders_share_form(self):
        """Any other host (e.g. local dev sharing one host) falls back to create."""
        response = self.client.get("/", HTTP_HOST="testserver")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passwd/create.html")

    def test_main_site_post_falls_through_to_create(self):
        """POST / on the main host reaches the share-create view, not the landing
        page (the vault's create modal posts to passwd:create, i.e. "/")."""
        response = self.client.post(
            "/",
            {"encrypted_data": "", "iv": ""},
            HTTP_HOST="proxima.red",
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertFalse(response.json()["success"])


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "testserver"],
)
class RobotsTxtTests(TestCase):
    """robots.txt serves a host-specific policy for the two sites."""

    def setUp(self):
        self.client = Client()

    def test_main_site_disallows_account_page(self):
        """The main site's robots.txt hides the account page and links its sitemap."""
        response = self.client.get(reverse("core:robots_txt"), HTTP_HOST="proxima.red")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/plain; charset=utf-8")
        body = response.content.decode()
        self.assertIn("Disallow: /auth/account/", body)
        self.assertIn("Sitemap: https://proxima.red/sitemap.xml", body)
        self.assertNotIn("/vault/", body)

    def test_pass_subdomain_disallows_vault_endpoints(self):
        """The pass subdomain's robots.txt hides all vault endpoints."""
        response = self.client.get(
            reverse("core:robots_txt"), HTTP_HOST="pass.proxima.red"
        )
        self.assertEqual(response.status_code, 200)
        body = response.content.decode()
        for path in ("/vault/", "/vault-data/", "/update-data/", "/export-data/"):
            self.assertIn(f"Disallow: {path}", body)
        self.assertIn("Sitemap: https://pass.proxima.red/sitemap.xml", body)
        self.assertNotIn("/auth/account/", body)

    def test_pass_subdomain_matches_with_explicit_port(self):
        """Host matching strips the port before comparing hostnames."""
        response = self.client.get(
            reverse("core:robots_txt"), HTTP_HOST="pass.proxima.red:8443"
        )
        self.assertIn("Disallow: /vault/", response.content.decode())

    def test_unrelated_host_gets_main_site_policy(self):
        """Any host other than the pass subdomain falls back to the main policy."""
        response = self.client.get(reverse("core:robots_txt"), HTTP_HOST="testserver")
        self.assertIn("Disallow: /auth/account/", response.content.decode())


@override_settings(
    SITE_URL="https://proxima.red",
    PASS_SITE_URL="https://pass.proxima.red",
    ALLOWED_HOSTS=["proxima.red", "pass.proxima.red", "testserver"],
)
class SitemapTests(TestCase):
    """sitemap.xml renders the host-specific sitemap template."""

    def setUp(self):
        self.client = Client()

    def test_main_site_renders_proxima_sitemap(self):
        """The main site serves sitemap_proxima.xml with SITE_URL locations."""
        response = self.client.get(reverse("core:sitemap"), HTTP_HOST="proxima.red")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/xml")
        self.assertTemplateUsed(response, "core/sitemap_proxima.xml")
        body = response.content.decode()
        self.assertIn("https://proxima.red/about/", body)
        # Auth is canonical on the main site, so it advertises the auth pages.
        self.assertIn("https://proxima.red/auth/signin/", body)
        self.assertIn("https://proxima.red/auth/signup/", body)

    def test_pass_subdomain_renders_pass_sitemap(self):
        """The pass subdomain serves sitemap_pass.xml with PASS_SITE_URL locations."""
        response = self.client.get(
            reverse("core:sitemap"), HTTP_HOST="pass.proxima.red"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/xml")
        self.assertTemplateUsed(response, "core/sitemap_pass.xml")
        body = response.content.decode()
        self.assertIn("https://pass.proxima.red/", body)
        # Auth moved to the main site; the pass sitemap must not list it.
        self.assertNotIn("/auth/", body)


class SecurityHeadersTests(TestCase):
    """SecurityHeadersMiddleware attaches CSP and Permissions-Policy responses."""

    def setUp(self):
        self.client = Client()

    def test_csp_header_present_and_locks_scripts(self):
        """Responses carry a CSP that confines scripts to same-origin."""
        response = self.client.get(reverse("core:about"))
        csp = response.headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'self'", csp)
        self.assertIn("script-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        # script-src must not allow inline/eval, or the protection is moot.
        self.assertNotIn("'unsafe-inline'", csp.split("script-src")[1].split(";")[0])

    def test_permissions_policy_header_present(self):
        """Responses carry a Permissions-Policy disabling unused features."""
        response = self.client.get(reverse("core:about"))
        self.assertIn("camera=()", response.headers.get("Permissions-Policy", ""))

    def test_view_set_headers_are_not_clobbered(self):
        """Headers a view set deliberately win over the configured defaults."""

        def get_response(request):
            response = HttpResponse()
            response["Content-Security-Policy"] = "default-src 'none'"
            response["Permissions-Policy"] = "camera=(self)"
            return response

        middleware = SecurityHeadersMiddleware(get_response)
        response = middleware(RequestFactory().get("/"))

        self.assertEqual(response["Content-Security-Policy"], "default-src 'none'")
        self.assertEqual(response["Permissions-Policy"], "camera=(self)")


class ErrorHandlerTests(TestCase):
    """Each custom handler renders its template with the matching status code."""

    def setUp(self):
        self.factory = RequestFactory()

    def test_error_400(self):
        """error_400 renders 400.html with a 400 status."""
        request = self.factory.get("/")
        with self.assertTemplateUsed("core/400.html"):
            response = views.error_400(request, exception=None)
        self.assertEqual(response.status_code, 400)

    def test_error_403(self):
        """error_403 renders 403.html with a 403 status."""
        request = self.factory.get("/")
        with self.assertTemplateUsed("core/403.html"):
            response = views.error_403(request, exception=None)
        self.assertEqual(response.status_code, 403)

    def test_error_404(self):
        """error_404 renders 404.html with a 404 status."""
        request = self.factory.get("/")
        with self.assertTemplateUsed("core/404.html"):
            response = views.error_404(request, exception=None)
        self.assertEqual(response.status_code, 404)

    def test_error_500(self):
        """error_500 renders 500.html with a 500 status (request-only signature)."""
        request = self.factory.get("/")
        with self.assertTemplateUsed("core/500.html"):
            response = views.error_500(request)
        self.assertEqual(response.status_code, 500)

    @override_settings(
        ALLOWED_HOSTS=["proxima.red"], SITE_URL="https://proxima.red"
    )
    def test_error_page_renders_with_disallowed_host(self):
        """A bad Host header still renders a clean 400 instead of cascading to 500.

        The error templates extend base.html, which builds the canonical/OG URLs.
        If that touched ``request.get_host()`` it would re-raise ``DisallowedHost``
        mid-render and escalate the 400 into a 500 (the production cascade these
        handlers must survive). The canonical base must fall back to ``SITE_URL``
        rather than echo the spoofed host.
        """
        request = self.factory.get("/", HTTP_HOST="www.junk-domain.example")
        with self.assertTemplateUsed("core/400.html"):
            response = views.error_400(request, exception=None)
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(b"junk-domain", response.content)
