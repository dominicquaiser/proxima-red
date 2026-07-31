from django.urls import path

from . import views

app_name = "auth"

urlpatterns = [
    path("salts/", views.AuthSaltsView.as_view(), name="salts"),
    path("reauth/", views.ReauthView.as_view(), name="reauth"),
    path("keypair/", views.KeypairView.as_view(), name="keypair"),
    path("pubkey/", views.PubkeyLookupView.as_view(), name="pubkey"),
    path("signup/", views.SignupView.as_view(), name="signup"),
    path("signin/", views.SigninView.as_view(), name="signin"),
    path("signout/", views.SignoutView.as_view(), name="signout"),
    path("account/", views.AccountView.as_view(), name="account"),
    path(
        "account/password/",
        views.PasswordChangeView.as_view(),
        name="change_password",
    ),
    path(
        "account/delete/",
        views.AccountDeletionView.as_view(),
        name="delete_account",
    ),
]
