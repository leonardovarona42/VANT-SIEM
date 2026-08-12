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
    path("logs/almacenamiento/", views.logs_storage_dashboard, name="logs-storage-dashboard"),
    path("logs/discovery/", views.logs_discovery, name="logs-discovery"),
    path("logs/", views.logs_discovery, name="logs-discovery-root"),
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
    path("soc/incidentes/create/", views.incidente_create_page, name="soc-incidentes-create"),
    path("soc/incidentes/create/submit/", views.incidente_create, name="soc-incidentes-create-submit"),
    path("soc/incidentes/<str:incident_id>/", views.soc_incident_detail, name="soc-incident-detail"),
    path("soc/incidentes/<str:incident_id>/edit/", views.incidente_edit_page, name="soc-incidente-edit"),
    path("soc/incidentes/<str:incident_id>/edit/submit/", views.incidente_edit_submit, name="soc-incidente-edit-submit"),
    path("soc/incidentes/<str:incident_id>/delete/", views.incidente_delete, name="soc-incidente-delete"),
    path("soc/incidentes/<str:incident_id>/<str:action>/", views.soc_incident_transition, name="soc-incident-transition"),

    # SOC: Reportes
    path("soc/reportes/", views.reportes_list, name="soc-reportes-list"),
    path("soc/reportes/create/", views.reporte_create_page, name="soc-reportes-create"),
    path("soc/reportes/create/submit/", views.reporte_create, name="soc-reportes-create-submit"),
    path("soc/reportes/<int:pk>/", views.reporte_detail, name="soc-reporte-detail"),
    path("soc/reportes/<int:pk>/edit/", views.reporte_edit_page, name="soc-reporte-edit"),
    path("soc/reportes/<int:pk>/edit/submit/", views.reporte_edit, name="soc-reporte-edit-submit"),
    path("soc/reportes/<int:pk>/delete/", views.reporte_delete, name="soc-reporte-delete"),

    # SOC: Categorias / Subcategorias
    path("soc/categorias/", views.categorias_list, name="soc-categorias-list"),
    path("soc/categorias/create/", views.categoria_create_page, name="soc-categoria-create"),
    path("soc/categorias/create/submit/", views.soc_categoria_create, name="soc-categoria-create-submit"),
    path("soc/categorias/<int:pk>/edit/", views.soc_categoria_edit, name="soc-categoria-edit"),
    path("soc/categorias/<int:pk>/delete/", views.soc_categoria_delete, name="soc-categoria-delete"),
    path("soc/subcategorias/", views.subcategorias_list, name="soc-subcategorias-list"),
    path("soc/subcategorias/create/", views.subcategoria_create_page, name="soc-subcategoria-create"),
    path("soc/subcategorias/create/submit/", views.soc_subcategoria_create, name="soc-subcategoria-create-submit"),
    path("soc/subcategorias/<int:pk>/edit/", views.soc_subcategoria_edit, name="soc-subcategoria-edit"),
    path("soc/subcategorias/<int:pk>/delete/", views.soc_subcategoria_delete, name="soc-subcategoria-delete"),

    # SOC: Responsables / Areas
    path("soc/responsables/", views.responsables_list, name="soc-responsables-list"),
    path("soc/responsables/create/", views.responsable_create_page, name="soc-responsable-create"),
    path("soc/responsables/create/submit/", views.soc_responsable_create, name="soc-responsable-create-submit"),
    path("soc/responsables/<int:pk>/edit/", views.soc_responsable_edit, name="soc-responsable-edit"),
    path("soc/responsables/<int:pk>/delete/", views.soc_responsable_delete, name="soc-responsable-delete"),
    path("soc/areas/", views.areas_list, name="soc-areas-list"),
    path("soc/areas/create/", views.area_create_page, name="soc-area-create"),
    path("soc/areas/create/submit/", views.soc_area_create, name="soc-area-create-submit"),
    path("soc/areas/<int:pk>/edit/", views.soc_area_edit, name="soc-area-edit"),
    path("soc/areas/<int:pk>/delete/", views.soc_area_delete, name="soc-area-delete"),

    # SOC: Medidas
    path("soc/medidas/", views.medidas_list, name="soc-medidas-list"),
    path("soc/medidas/create/", views.medida_create_page, name="soc-medida-create"),
    path("soc/medidas/create/submit/", views.soc_medida_create, name="soc-medida-create-submit"),
    path("soc/medidas/<int:pk>/edit/", views.soc_medida_edit, name="soc-medida-edit"),
    path("soc/medidas/<int:pk>/delete/", views.soc_medida_delete, name="soc-medida-delete"),

    # SOC: Involucrados
    path("soc/involucrados/", views.involucrados_list, name="soc-involucrados-list"),
    path("soc/involucrados/create/", views.involucrado_create_page, name="soc-involucrado-create"),
    path("soc/involucrados/create/submit/", views.soc_involucrado_create, name="soc-involucrado-create-submit"),
    path("soc/involucrados/<int:pk>/", views.involucrado_detail, name="soc-involucrado-detail"),
    path("soc/involucrados/<int:pk>/edit/", views.soc_involucrado_edit, name="soc-involucrado-edit"),
    path("soc/involucrados/<int:pk>/delete/", views.soc_involucrado_delete, name="soc-involucrado-delete"),

    # SOC: Infraestructura / CMDB
    path("soc/servicios/metrics/ajax/", views.servicios_metrics_ajax, name="soc-servicios-metrics-ajax"),
    path("soc/servicios/", views.servicios_list, name="soc-servicios-list"),
    path("soc/servicios/create/", views.servicio_create_page, name="soc-servicios-create"),
    path("soc/servicios/create/submit/", views.servicio_create, name="soc-servicios-create-submit"),
    path("soc/servicios/<str:servicio_id>/", views.servicio_detail, name="soc-servicio-detail"),
    path("soc/servicios/<str:servicio_id>/edit/", views.servicio_edit, name="soc-servicio-edit"),
    path("soc/servicios/<str:servicio_id>/delete/", views.servicio_delete, name="soc-servicio-delete"),

    # SOC: Topologia
    path("soc/esquema/fisico/", views.esquema_fisico, name="soc-esquema-fisico"),
    path("soc/esquema/logico/", views.esquema_logico, name="soc-esquema-logico"),
    path("soc/redes/", views.redes_list, name="soc-redes-list"),

    # AJAX API for inline creation
    path("api/involucrados/create/", views.api_involucrado_create, name="api-involucrado-create"),
    path("api/medidas/create/", views.api_medida_create, name="api-medida-create"),

    # Inventory
    path("inventory/", views.inventory_dashboard, name="inventory-dashboard"),
    path("inventory/agents/", views.agents_list, name="agents-list"),
    path("inventory/agents/<str:agent_id>/", views.agent_detail, name="agent-detail"),
    path("inventory/agents/<str:agent_id>/config/", views.agent_config_view, name="agent-config"),
    path("inventory/agents/<str:agent_id>/restart/", views.agent_restart, name="agent-restart"),
    path("inventory/agents/<str:agent_id>/delete/", views.agent_delete, name="agent-delete"),
    path("inventory/agents/<str:agent_id>/procesos/", views.agent_processes, name="agent-processes"),
    path("inventory/agents/<str:agent_id>/procesos/collect/", views.agent_collect_processes, name="agent-collect-processes"),
    path("inventory/agents/<str:agent_id>/servicios/", views.agent_services, name="agent-services"),
    path("inventory/software/", views.software_list, name="software-list"),

    # Bus: Eventos en Tiempo Real
    path("bus/eventos/", views.bus_eventos, name="bus-eventos"),
    path("api/bus/eventos/", views.bus_eventos_ajax, name="bus-eventos-ajax"),
    path("api/bus/eventos/<int:event_id>/", views.bus_evento_detalle_ajax, name="bus-evento-detalle-ajax"),

    # Configuracion: Users
    path("configuracion/usuarios/", views.configuracion_usuarios, name="configuracion-usuarios"),
    path("configuracion/usuarios/crear/", views.configuracion_usuario_create, name="configuracion-usuario-create"),
    path("configuracion/usuarios/crear/submit/", views.configuracion_usuario_create_submit, name="configuracion-usuario-create-submit"),
    path("configuracion/usuarios/<int:pk>/editar/", views.configuracion_usuario_edit, name="configuracion-usuario-edit"),
    path("configuracion/usuarios/<int:pk>/editar/submit/", views.configuracion_usuario_edit_submit, name="configuracion-usuario-edit-submit"),
    path("configuracion/usuarios/<int:pk>/eliminar/", views.configuracion_usuario_delete_submit, name="configuracion-usuario-delete"),
    path("configuracion/usuarios/<int:pk>/reset-password/", views.configuracion_usuario_reset_password, name="configuracion-usuario-reset-password"),

    # Configuracion: Notification Groups
    path("configuracion/grupos/", views.configuracion_grupos, name="configuracion-grupos"),
    path("configuracion/grupos/crear/", views.configuracion_grupo_create, name="configuracion-grupo-create"),
    path("configuracion/grupos/<int:pk>/editar/", views.configuracion_grupo_edit, name="configuracion-grupo-edit"),
    path("configuracion/grupos/<int:pk>/eliminar/", views.configuracion_grupo_delete_submit, name="configuracion-grupo-delete"),
    path("configuracion/grupos/<int:pk>/", views.configuracion_grupo_detail, name="configuracion-grupo-detail"),

    # Configuracion: Email Config
    path("configuracion/correo/", views.configuracion_correo, name="configuracion-correo"),
    path("configuracion/correo/crear/", views.configuracion_correo_create, name="configuracion-correo-create"),
    path("configuracion/correo/<int:pk>/editar/", views.configuracion_correo_edit, name="configuracion-correo-edit"),
    path("configuracion/correo/<int:pk>/eliminar/", views.configuracion_correo_delete_submit, name="configuracion-correo-delete"),
    path("configuracion/correo/<int:pk>/test/", views.configuracion_correo_test_submit, name="configuracion-correo-test"),

    # Configuracion: Ecosystem Status
    path("configuracion/ecosistema/", views.configuracion_ecosistema, name="configuracion-ecosistema"),
    path("configuracion/ecosistema/<int:pk>/<str:action>/", views.configuracion_ecosistema_action, name="configuracion-ecosistema-action"),

    # Configuracion: Gestion de Base de Datos
    path("configuracion/db/", views.db_dashboard, name="configuracion-db-dashboard"),
    path("configuracion/db/optimize/", views.db_optimize_action, name="configuracion-db-optimize"),
    path("configuracion/db/retention/", views.db_retention_list, name="configuracion-db-retention"),
    path("configuracion/db/retention/create/", views.db_retention_create, name="configuracion-db-retention-create"),
    path("configuracion/db/retention/<int:pk>/edit/", views.db_retention_edit, name="configuracion-db-retention-edit"),
    path("configuracion/db/retention/<int:pk>/delete/", views.db_retention_delete, name="configuracion-db-retention-delete"),
    path("configuracion/db/backups/", views.db_backups_list, name="configuracion-db-backups"),
    path("configuracion/db/backups/create/", views.db_backup_create, name="configuracion-db-backup-create"),
    path("configuracion/db/backups/<int:pk>/restore/", views.db_backup_restore, name="configuracion-db-backup-restore"),

    # Estado de Recoleccion
    path("estado-recoleccion/", views.intelligence_dashboard, name="estado-recoleccion"),

    # Intelligence Analytics Dashboard
    path("inteligencia/", views.intelligence_analytics, name="inteligencia"),
    path("inteligencia/geo/", views.intelligence_geo, name="inteligencia-geo"),
    path("inteligencia/geo/live/", views.intelligence_geo_live, name="inteligencia-geo-live"),
    path("inteligencia/geo/report/", views.intelligence_geo_report, name="inteligencia-geo-report"),
    path("inteligencia/geo/report/api/", views.intelligence_geo_report_api, name="inteligencia-geo-report-api"),

    # SOAR (mismo dropdown de Inteligencia)
    path("inteligencia/soar/", views.intelligence_soar, name="inteligencia-soar"),
    path("inteligencia/soar/api/<path:path>", views.intelligence_soar_api, name="inteligencia-soar-api"),

    # Configuracion: Intelligence API Keys
    path("configuracion/api-keys/", views.configuracion_api_keys, name="configuracion-api-keys"),
    path("configuracion/api-keys/save/", views.configuracion_api_key_save, name="configuracion-api-key-save"),
    path("configuracion/api-keys/<str:provider>/delete/", views.configuracion_api_key_delete, name="configuracion-api-key-delete"),
    path("configuracion/api-keys/<str:provider>/test/", views.configuracion_api_key_test, name="configuracion-api-key-test"),
]
