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
    path("", include("apps.passwd.urls")),
    path("", include("apps.core.urls")),
    path("auth/", include("apps.auth.urls")),
]
