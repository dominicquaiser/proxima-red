from django.urls import path
from . import views

app_name = "passwd"

urlpatterns = [
    path("", views.CreateShareView.as_view(), name="create"),
    path("<uuid:pk>/", views.RetrieveShareView.as_view(), name="retrieve"),
    path("vault/", views.VaultView.as_view(), name="vault"),
    path("vault-data/", views.VaultDataView.as_view(), name="vault_data"),
    path("update-data/", views.UpdateEncryptedDataView.as_view(), name="update_data"),
    path("delete-share/", views.DeleteShareView.as_view(), name="delete_share"),
    path("export-data/", views.DataExportView.as_view(), name="export_data"),
]
