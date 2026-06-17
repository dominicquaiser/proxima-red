"""
Project security-header middleware.

Adds a Content-Security-Policy (and a Permissions-Policy) to every response.
Django ships neither out of the box, but for a browser-delivered end-to-end
encrypted app a strict CSP is the primary defence against an injected or
third-party script exfiltrating the URL-fragment share key or the sessionStorage
vault key. The header values live in settings (``CONTENT_SECURITY_POLICY``,
``PERMISSIONS_POLICY``) so they can be tuned per environment without code
changes; an empty/unset value disables that particular header.
"""

from django.conf import settings


class SecurityHeadersMiddleware:
    """Attach the configured CSP and Permissions-Policy headers to each response."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.csp = getattr(settings, "CONTENT_SECURITY_POLICY", "") or ""
        self.permissions_policy = getattr(settings, "PERMISSIONS_POLICY", "") or ""

    def __call__(self, request):
        response = self.get_response(request)
        # Don't clobber a header a view set deliberately (e.g. a stricter CSP).
        if self.csp and "Content-Security-Policy" not in response:
            response["Content-Security-Policy"] = self.csp
        if self.permissions_policy and "Permissions-Policy" not in response:
            response["Permissions-Policy"] = self.permissions_policy
        return response
