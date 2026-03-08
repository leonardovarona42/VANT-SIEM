
from django.urls import path
from . import views

urlpatterns = [
    # Dashboards principales
    path('visual/', views.opensearch_visual_dashboard, name='opensearch-visual-dashboard'),
    path('discover/', views.opensearch_discovery, name='opensearch-discovery'),
    path('visualizations/create/', views.opensearch_create_visualizations, name='opensearch-create-visualizations'),
    path('visualizations/preview/', views.opensearch_visualizations_preview, name='opensearch-visualizations-preview'),
    path('visualizations/save/', views.opensearch_visualizations_save, name='opensearch-visualizations-save'),
    path('visualizations/list/', views.opensearch_visualizations_list, name='opensearch-visualizations-list'),
    path('visualizations/delete/', views.opensearch_visualizations_delete, name='opensearch-visualizations-delete'),
    path('dashboards/save/', views.opensearch_dashboards_save, name='opensearch-dashboards-save'),
    path('dashboards/list/', views.opensearch_dashboards_list, name='opensearch-dashboards-list'),
    path('intelligence/', views.intelligence_dashboard, name='intelligence-dashboard'),
    path('snort/', views.snort_dashboard, name='snort-dashboard'),
    path('snort/v2/', views.snort_dashboard_v2, name='snort-dashboard-v2'),
    path('snort/api/', views.snort_dashboard_api, name='snort-dashboard-api'),
    path('snort/details/<int:log_id>/', views.snort_log_details, name='snort-log-details'),
    path('suricata/', views.suricata_dashboard, name='suricata-dashboard'),
    path('suricata/api/', views.suricata_dashboard_api, name='suricata-dashboard-api'),
    # Configuración
    path('config/', views.ids_config, name='ids-config'),
    path('config/test/<int:config_id>/', views.test_config, name='test-config'),
    path('config/toggle/<int:config_id>/', views.toggle_ingest, name='toggle-ingest'),
    # Alertas
    path('alerts/', views.alerts_dashboard, name='alerts-dashboard'),
    path('alerts/acknowledge/<int:alert_id>/', views.acknowledge_alert, name='acknowledge-alert'),
    # Estadísticas
    path('statistics/', views.statistics_dashboard, name='statistics-dashboard'),
    # Gestión de servicios
    path('service/', views.service_management, name='service-management'),
    path('service/start/', views.start_service, name='start-service'),
    path('service/start-daemon/', views.start_daemon_service, name='start-daemon-service'),
    path('service/status/', views.get_service_status, name='get-service-status'),
    path('service/stop/', views.stop_service, name='stop-service'),
    path('service/rotate-logs/', views.run_log_rotation, name='run-log-rotation'),

    # Nuevas rutas de rotación avanzada
    path('service/rotate-database/', views.rotate_database, name='rotate-database'),
    path('service/preview-db-rotation/', views.preview_db_rotation, name='preview-db-rotation'),
    path('service/rotate-files/', views.rotate_files, name='rotate-files'),
    path('service/scan-files/', views.scan_files, name='scan-files'),
    path('service/preview-file-rotation/', views.preview_file_rotation, name='preview-file-rotation'),
    path('service/optimize-db/', views.optimize_database, name='optimize-database'),
    path('service/rebuild-indexes/', views.rebuild_indexes, name='rebuild-indexes'),
    path('service/cleanup-temp/', views.cleanup_temp_files, name='cleanup-temp'),
    path('service/generate-report/', views.generate_report, name='generate-report'),
    path('service/rotation-history/', views.rotation_history, name='rotation-history'),
]
