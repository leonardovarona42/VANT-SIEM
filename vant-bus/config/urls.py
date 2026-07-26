from django.urls import include, path

urlpatterns = [
    path("api/", include("bus_app.urls")),
]
