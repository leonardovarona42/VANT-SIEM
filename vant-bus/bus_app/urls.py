from django.urls import path

from bus_app import views

urlpatterns = [
    path("alerts/send/", views.send_alert, name="send_alert"),
    path("alerts/history/", views.alert_history, name="alert_history"),
    path("alerts/config/", views.alert_config, name="alert_config"),
    path("events/recent/", views.recent_events, name="recent_events"),
    path("events/<str:stream>/", views.stream_events, name="stream_events"),
    path("stats/", views.stats, name="stats"),
    path("health/", views.health, name="health"),
]
