"""
URL configuration for config project.

It mounts app URL confs and registers error handlers.
"""

from django.urls import path, include

handler400 = "apps.core.views.error_400"
handler403 = "apps.core.views.error_403"
handler404 = "apps.core.views.error_404"
handler500 = "apps.core.views.error_500"

urlpatterns = [
    # core comes first so its root (the landing page / host-aware dispatcher)
    # and its "<uuid:pk>/" retrieve dispatcher claim those paths ahead of the
    # tools' own identical patterns; passwd and note keep them reversible as
    # ``passwd:create``/``passwd:retrieve`` and ``note:create``/``note:retrieve``
    # and own all their other routes.
    path("", include("apps.core.urls")),
    path("", include("apps.passwd.urls")),
    path("", include("apps.note.urls")),
    path("auth/", include("apps.auth.urls")),
]
