from django.urls import path
from . import views


app_name = "core"

urlpatterns = [
    path("", views.index, name="index"),
    path("pgp-key", views.pgp_key, name="pgp_key"),
    path("robots.txt", views.robots_txt, name="robots_txt"),
    path("sitemap.xml", views.sitemap, name="sitemap"),
    path("about/", views.about, name="about"),
    path("imprint/", views.imprint, name="imprint"),
    path("privacy/", views.privacy, name="privacy"),
]
