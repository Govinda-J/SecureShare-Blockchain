from django.urls import path, include
from mp import views

urlpatterns = [
    path("", views.home, name="home"),
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout_view, name="logout"),

    path("dashboard/", views.dashboard, name="dashboard"),
    path("profile/", views.profile_view, name="profile"),
    path("activities/", views.activities_view, name="activities"),
    path("files/", views.files_view, name="files"),
    path("attributes/", views.request_attributes, name="request_attributes"),

    path("upload/", views.uploader, name="upload"),
    path("grant/", views.granter, name="grant"),
    path("revoke/", views.revoker, name="revoke"),

    path("request/", views.requester, name="request"),
    path("download/", views.downloader, name="download"),

    path("delete-file/", views.delete_file, name="delete_file"),
    path("access-request/<int:req_id>/dismiss/", views.dismiss_access_request, name="dismiss_access_request"),
    path("owner-download/", views.owner_downloader, name="owner_download"),

    # Staff-only — no wallet/private-key required, gated by Django's is_staff
    path("staff/", views.admin_home, name="admin_home"),
    path("staff/user/<int:profile_id>/attributes/", views.manage_attributes, name="manage_attributes"),
    path("staff/attribute-request/<int:req_id>/resolve/", views.resolve_attribute_request, name="resolve_attribute_request"),
]