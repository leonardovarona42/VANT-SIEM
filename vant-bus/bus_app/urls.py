from django.urls import path

from bus_app import views

urlpatterns = [
    # Events
    path("events/", views.event_list, name="event_list"),
    path("events/receive/", views.event_receive, name="event_receive"),
    path("events/<int:event_id>/", views.event_detail, name="event_detail"),

    # Groups
    path("groups/", views.group_list_create, name="group_list_create"),
    path("groups/<int:group_id>/", views.group_detail, name="group_detail"),
    path("groups/<int:group_id>/members/", views.group_members, name="group_members"),

    # Subscriptions
    path("subscriptions/", views.subscription_list_create, name="subscription_list_create"),
    path("subscriptions/<int:sub_id>/", views.subscription_delete, name="subscription_delete"),

    # Notifications
    path("notifications/", views.notification_list, name="notification_list"),
    path("notifications/<int:notif_id>/read/", views.notification_mark_read, name="notification_mark_read"),
    path("notifications/read-all/", views.notification_mark_all_read, name="notification_mark_all_read"),

    # Email Config
    path("email-config/", views.email_config, name="email_config"),
    path("email-config/test/", views.email_config_test, name="email_config_test"),

    # Orchestration
    path("services/", views.service_list_create, name="service_list_create"),
    path("services/<int:svc_id>/", views.service_detail, name="service_detail"),
    path("services/<int:svc_id>/health/", views.service_health_history, name="service_health_history"),
    path("services/<int:svc_id>/<str:action>/", views.service_action, name="service_action"),

    # Dashboard
    path("dashboard/", views.dashboard_summary, name="dashboard_summary"),
    path("stats/", views.bus_stats, name="bus_stats"),

    # Legacy alerts (backward compat)
    path("alerts/send/", views.send_alert, name="send_alert"),
    path("alerts/history/", views.alert_history, name="alert_history"),
    path("alerts/config/", views.alert_config, name="alert_config"),

    # Streams
    path("events/recent/", views.recent_events, name="recent_events"),
    path("events/<str:stream>/stream/", views.stream_events, name="stream_events"),

    # Health
    path("health/", views.health, name="health"),
]
