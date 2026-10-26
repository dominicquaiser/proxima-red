"""WebSocket URL patterns for the note app, mounted by config/asgi.py.

Like the /live/... HTTP endpoints, the socket paths are collision-free
literals that answer on every host; holding the link (and its fragment key)
is the capability, so there is no host gate here.
"""

from django.urls import path

from . import consumers

websocket_urlpatterns = [
    path("ws/live/<uuid:pk>/", consumers.LiveNoteConsumer.as_asgi(), name="live_ws"),
]
