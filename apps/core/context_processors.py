from django.conf import settings
from django.core.exceptions import DisallowedHost


def site_urls(request):
    """Expose SITE_URL/PASS_SITE_URL and a host-poisoning-safe canonical base.

    ``canonical_base`` is the ``scheme://host`` prefix used for canonical and
    Open Graph URLs in the base template. It is computed here, rather than via
    ``{{ request.get_host }}`` in the template, so that requests with an invalid
    ``Host`` header (raw-IP probes, junk domains pointed at our IP) can still
    render the styled error pages. Calling ``get_host()`` during template render
    would re-raise ``DisallowedHost`` mid-response and escalate a clean 400 into
    a cascading 500. Falling back to ``SITE_URL`` also makes the canonical tag
    immune to Host-header injection.
    """
    try:
        canonical_base = f"{request.scheme}://{request.get_host()}"
    except DisallowedHost:
        canonical_base = settings.SITE_URL
    return {
        "site_url": settings.SITE_URL,
        "pass_site_url": settings.PASS_SITE_URL,
        "canonical_base": canonical_base,
    }
