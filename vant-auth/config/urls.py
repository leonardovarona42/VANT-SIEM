from django.urls import include, path

urlpatterns = [
    path("auth/", include("auth_app.urls")),
]
