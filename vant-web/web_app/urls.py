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

    # SOC: Bitacora de Incidentes
    path("soc/incidentes/", views.soc_incidents_list, name="soc-incidents-list"),
    path("soc/incidentes/<str:incident_id>/", views.soc_incident_detail, name="soc-incident-detail"),
    path("soc/incidentes/<str:incident_id>/<str:action>/", views.soc_incident_transition, name="soc-incident-transition"),

    # SOC: Reportes
    path("soc/reportes/", views.reportes_list, name="soc-reportes-list"),

    # SOC: Categorias / Subcategorias
    path("soc/categorias/", views.categorias_list, name="soc-categorias-list"),
    path("soc/categorias/create/", views.soc_categoria_create, name="soc-categoria-create"),
    path("soc/categorias/<int:pk>/edit/", views.soc_categoria_edit, name="soc-categoria-edit"),
    path("soc/categorias/<int:pk>/delete/", views.soc_categoria_delete, name="soc-categoria-delete"),
    path("soc/subcategorias/", views.subcategorias_list, name="soc-subcategorias-list"),
    path("soc/subcategorias/create/", views.soc_subcategoria_create, name="soc-subcategoria-create"),
    path("soc/subcategorias/<int:pk>/edit/", views.soc_subcategoria_edit, name="soc-subcategoria-edit"),
    path("soc/subcategorias/<int:pk>/delete/", views.soc_subcategoria_delete, name="soc-subcategoria-delete"),

    # SOC: Responsables / Areas
    path("soc/responsables/", views.responsables_list, name="soc-responsables-list"),
    path("soc/responsables/create/", views.soc_responsable_create, name="soc-responsable-create"),
    path("soc/responsables/<int:pk>/edit/", views.soc_responsable_edit, name="soc-responsable-edit"),
    path("soc/responsables/<int:pk>/delete/", views.soc_responsable_delete, name="soc-responsable-delete"),
    path("soc/areas/", views.areas_list, name="soc-areas-list"),
    path("soc/areas/create/", views.soc_area_create, name="soc-area-create"),
    path("soc/areas/<int:pk>/edit/", views.soc_area_edit, name="soc-area-edit"),
    path("soc/areas/<int:pk>/delete/", views.soc_area_delete, name="soc-area-delete"),

    # SOC: Medidas
    path("soc/medidas/", views.medidas_list, name="soc-medidas-list"),
    path("soc/medidas/create/", views.soc_medida_create, name="soc-medida-create"),
    path("soc/medidas/<int:pk>/edit/", views.soc_medida_edit, name="soc-medida-edit"),
    path("soc/medidas/<int:pk>/delete/", views.soc_medida_delete, name="soc-medida-delete"),

    # SOC: Involucrados
    path("soc/involucrados/", views.involucrados_list, name="soc-involucrados-list"),
    path("soc/involucrados/create/", views.soc_involucrado_create, name="soc-involucrado-create"),
    path("soc/involucrados/<int:pk>/", views.involucrado_detail, name="soc-involucrado-detail"),
    path("soc/involucrados/<int:pk>/edit/", views.soc_involucrado_edit, name="soc-involucrado-edit"),
    path("soc/involucrados/<int:pk>/delete/", views.soc_involucrado_delete, name="soc-involucrado-delete"),

    # SOC: Infraestructura / CMDB
    path("soc/servicios/", views.servicios_list, name="soc-servicios-list"),
    path("soc/servicios/<str:servicio_id>/", views.servicio_detail, name="soc-servicio-detail"),

    # Inventory
    path("inventory/", views.inventory_dashboard, name="inventory-dashboard"),
    path("inventory/agents/", views.agents_list, name="agents-list"),
    path("inventory/agents/<str:agent_id>/", views.agent_detail, name="agent-detail"),
    path("inventory/agents/<str:agent_id>/config/", views.agent_config_view, name="agent-config"),
    path("inventory/software/", views.software_list, name="software-list"),
]
