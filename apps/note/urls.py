"""URL routes for creating and retrieving shared notes."""

from django.urls import path

from . import views

app_name = "note"

# ``apps.core`` is mounted first and dispatches these shared paths by host.
# Keeping the routes here makes ``note:create`` and ``note:retrieve`` reversible.
urlpatterns = [
    path("", views.CreateNoteView.as_view(), name="create"),
    path("<uuid:pk>/", views.RetrieveNoteView.as_view(), name="retrieve"),
]
