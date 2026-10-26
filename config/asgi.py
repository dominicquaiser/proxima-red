"""
ASGI config for config project: the single production entrypoint serving both
protocols. HTTP requests take the same Django stack as config.wsgi; WebSocket
connections (the live-note sync hot path, /ws/...) go to apps.note.routing.

Notes on the websocket stack:
- AllowedHostsOriginValidator rejects cross-site socket opens (browsers always
  send Origin on WebSocket handshakes), keyed off ALLOWED_HOSTS.
- The live-note socket is anonymous (holding the link is the capability), so
  the stack carries no session or auth middleware. Channels' AuthMiddlewareStack
  would be unusable here regardless: django.contrib.auth is intentionally not
  installed (see config/settings/base.py).
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.production")

# Initialise Django before importing anything that touches the app registry
# (channels routing, apps.note.routing).
django_asgi_app = get_asgi_application()

from django.conf import settings  # noqa: E402

from channels.routing import ProtocolTypeRouter, URLRouter  # noqa: E402
from channels.security.websocket import AllowedHostsOriginValidator  # noqa: E402

from apps.note.routing import websocket_urlpatterns  # noqa: E402

http_app = django_asgi_app
if settings.DEBUG:
    # The uvicorn dev server serves this module directly (no runserver, which
    # is what normally injects static file handling in development).
    from django.contrib.staticfiles.handlers import ASGIStaticFilesHandler

    http_app = ASGIStaticFilesHandler(django_asgi_app)

application = ProtocolTypeRouter(
    {
        "http": http_app,
        "websocket": AllowedHostsOriginValidator(URLRouter(websocket_urlpatterns)),
    }
)
