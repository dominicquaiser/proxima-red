from django.conf import settings


def site_urls(request):
    """Expose SITE_URL and PASS_SITE_URL to every template."""
    return {
        "site_url": settings.SITE_URL,
        "pass_site_url": settings.PASS_SITE_URL,
    }
