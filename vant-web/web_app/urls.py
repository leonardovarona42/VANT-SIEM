from django.urls import path
from . import views

app_name = "web"

urlpatterns = [
    # Auth
    path("", views.dashboard_view, name="dashboard"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),

    # Dashboard API
    path("api/metrics/", views.dashboard_metrics, name="dashboard-metrics"),
    path("api/notifications/", views.notifications_api, name="get-notifications"),
    path("api/health/", views.service_health_api, name="service-health"),

    # Logs
    path("logs/", views.events_list, name="events-list"),
    path("logs/discovery/", views.logs_discovery, name="logs-discovery"),
    path("logs/suricata/", views.suricata_dashboard, name="suricata-dashboard"),
    path("logs/<str:event_id>/", views.event_detail, name="event-detail"),

    # SOC / DLP / Bitacora
    path("soc/", views.incidents_list, name="incidents-list"),
    path("soc/dlp/", views.incidents_list, name="dlp-incidents-list"),
    path("soc/policies/", views.policies_list, name="policies-list"),
    path("soc/policies/create/", views.policy_create, name="policy-create"),
    path("soc/policies/<str:code>/edit/", views.policy_edit, name="policy-edit"),
    path("soc/policies/<str:code>/delete/", views.policy_delete, name="policy-delete"),
    path("soc/incidents/<str:incident_id>/", views.incident_detail, name="incident-detail"),
    path("soc/incidents/<str:incident_id>/acknowledge/", views.incident_acknowledge, name="incident-acknowledge"),
    path("soc/incidents/<str:incident_id>/resolve/", views.incident_resolve, name="incident-resolve"),

    # Inventory
    path("inventory/", views.inventory_dashboard, name="inventory-dashboard"),
    path("inventory/agents/", views.agents_list, name="agents-list"),
    path("inventory/agents/<str:agent_id>/", views.agent_detail, name="agent-detail"),
    path("inventory/agents/<str:agent_id>/config/", views.agent_config_view, name="agent-config"),
    path("inventory/software/", views.software_list, name="software-list"),
]
