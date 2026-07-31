"""URL routes for creating and retrieving shared notes, and the note vault."""

from django.urls import path

from . import views

app_name = "note"

# ``apps.core`` is mounted first and dispatches these shared paths by host.
# Keeping the routes here makes ``note:create`` and ``note:retrieve`` reversible.
# ``vault/`` is likewise host-dispatched by core (note host -> note vault,
# otherwise the passwd vault) and shadow-registered here so ``note:vault``
# stays reversible. The vault JSON APIs below have collision-free literal
# paths, so they match on every host, which the password-change migration on
# the main site relies on. The ``live/`` paths (editable share links) are
# collision-free literals too; only the HTML page host-gates, in the view
# itself (``LiveNotePageView``), keeping live links note-host-only like
# ``/<uuid>/`` retrieves.
urlpatterns = [
    path("", views.CreateNoteView.as_view(), name="create"),
    path("vault/", views.NoteVaultView.as_view(), name="vault"),
    path("vault/index/", views.VaultIndexView.as_view(), name="vault_index"),
    path("vault/notes/", views.VaultNoteCollectionView.as_view(), name="vault_notes"),
    path(
        "vault/notes/<uuid:pk>/",
        views.VaultNoteDetailView.as_view(),
        name="vault_note",
    ),
    path(
        "vault/notes/<uuid:pk>/delete/",
        views.VaultNoteDeleteView.as_view(),
        name="vault_note_delete",
    ),
    path("vault/migrate/", views.VaultMigrateView.as_view(), name="vault_migrate"),
    path("live/", views.CreateLiveNoteView.as_view(), name="live_create"),
    path("live/<uuid:pk>/", views.LiveNotePageView.as_view(), name="live"),
    path(
        "live/<uuid:pk>/state/",
        views.LiveNoteStateView.as_view(),
        name="live_state",
    ),
    path(
        "live/<uuid:pk>/updates/",
        views.LiveNoteUpdatesView.as_view(),
        name="live_updates",
    ),
    path(
        "live/<uuid:pk>/snapshot/",
        views.LiveNoteSnapshotView.as_view(),
        name="live_snapshot",
    ),
    path(
        "live/<uuid:pk>/key/",
        views.LiveNoteKeyView.as_view(),
        name="live_key",
    ),
    path(
        "live/<uuid:pk>/access/",
        views.LiveNoteAccessView.as_view(),
        name="live_access",
    ),
    path(
        "live/<uuid:pk>/collaborators/",
        views.LiveNoteCollaboratorsView.as_view(),
        name="live_collaborators",
    ),
    path(
        "live/<uuid:pk>/rekey/",
        views.LiveNoteRekeyView.as_view(),
        name="live_rekey",
    ),
    path("<uuid:pk>/", views.RetrieveNoteView.as_view(), name="retrieve"),
]
