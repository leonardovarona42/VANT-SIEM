from django.contrib.auth import views as auth_views
from django.urls import path
from . import views

urlpatterns = [
    # Dashboard y autenticación
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('devices/management/', views.devices_management, name='devices-management'),
    path('devices/inventory/', views.inventory_service_dashboard, name='inventory-service-dashboard'),
    path('devices/assets/', views.inventory_assets_dashboard, name='inventory-assets-dashboard'),
    path('devices/dlp/', views.dlp_service_dashboard, name='dlp-service-dashboard'),
    path('devices/dlp/policies/', views.dlp_policy_list, name='dlp-policy-list'),
    path('devices/dlp/policies/create/', views.dlp_policy_create, name='dlp-policy-create'),
    path('devices/dlp/policies/<int:policy_id>/edit/', views.dlp_policy_edit, name='dlp-policy-edit'),
    path('devices/dlp/policies/<int:policy_id>/rules/', views.dlp_rule_save, name='dlp-rule-save'),
    path('devices/dlp/policies/<int:policy_id>/rules/<int:rule_id>/edit/', views.dlp_rule_save, name='dlp-rule-edit'),
    path('devices/dlp/policies/<int:policy_id>/rules/<int:rule_id>/delete/', views.dlp_rule_delete, name='dlp-rule-delete'),
    path('devices/dlp/incidents/', views.dlp_incident_list, name='dlp-incident-list'),
    path('devices/dlp/incidents/<int:incident_id>/update/', views.dlp_incident_update, name='dlp-incident-update'),
    path('api/devices/inventory/dashboard/', views.inventory_dashboard_api, name='inventory-dashboard-api'),
    path('api/devices/dlp/dashboard/', views.dlp_dashboard_api, name='dlp-dashboard-api'),
    path('api/agent/enroll/', views.agent_enroll, name='agent-enroll'),
    path('api/agent/bootstrap-secret/', views.agent_bootstrap_secret, name='agent-bootstrap-secret'),
    path('api/agent/heartbeat/', views.agent_heartbeat, name='agent-heartbeat'),
    path('api/agent/inventory/', views.agent_inventory, name='agent-inventory'),
    path('api/agent/dlp/incidents/', views.agent_dlp_incidents, name='agent-dlp-incidents'),
    path('api/agent/dlp/config/', views.agent_dlp_config, name='agent-dlp-config'),
    path('api/agent/commands/pull/', views.agent_commands_pull, name='agent-commands-pull'),
    path('api/agent/commands/ack/', views.agent_commands_ack, name='agent-commands-ack'),
    path('api/agent/list/', views.agent_list, name='agent-list'),
    path('api/agent/detail/<str:agent_id>/', views.agent_detail, name='agent-detail'),
    path('api/agent/command/issue/', views.agent_command_issue, name='agent-command-issue'),
    path('devices/management/<str:agent_id>/', views.agent_detail_page, name='agent-detail-page'),
    # Agent APIs moved to VANT_SIEM/agent_urls.py
    path('password-change/', views.password_change_view, name='password-change'),
    
    # Gestión de usuarios
    path('users/', views.user_management, name='user-management'),
    path('users/create-request/', views.create_user_request, name='create-user-request'),
    path('users/approve/<int:request_id>/', views.approve_user_request, name='approve-user-request'),
    path('users/reject/<int:request_id>/', views.reject_user_request, name='reject-user-request'),
    path('users/<int:user_id>/permissions/', views.user_permissions, name='user-permissions'),
    path('users/<int:user_id>/permissions/<int:permission_id>/update/', views.update_user_permission, name='update-user-permission'),
    
    # Sistema de notificaciones
    path('notifications/', views.notifications, name='notifications'),
    path('api/notifications/', views.get_notifications, name='get-notifications'),
    path('notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark-notification-read'),
    path('notifications/mark-all-read/', views.mark_all_notifications_read, name='mark-all-notifications-read'),
    
    # Sistema de logs
    path('logs/', views.system_logs, name='system-logs'),
    
    # Control del sistema de logging
    path('logging-control/', views.logging_control, name='logging-control'),
    path('api/logging/start/', views.start_logging_system, name='start-logging-system'),
    path('api/logging/stop/', views.stop_logging_system, name='stop-logging-system'),
    path('api/logging/status/', views.get_logging_status_api, name='get-logging-status'),
    
    # Configuración de correo
    path('email-configuration/', views.email_configuration, name='email-configuration'),
    path('email-configuration/create/', views.create_email_config, name='create-email-config'),
    path('email-configuration/edit/<int:config_id>/', views.edit_email_config, name='edit-email-config'),
    path('api/email-config/<int:config_id>/activate/', views.activate_email_config, name='activate-email-config'),
    path('api/email-config/<int:config_id>/test/', views.test_email_config, name='test-email-config'),
    
    # Gestión de alertas por correo
    path('email-alerts/', views.email_alerts_management, name='email-alerts-management'),
    path('api/email-alert/update/', views.update_email_alert, name='update-email-alert'),
    path('api/email-alert/user/', views.get_user_email_alerts, name='get-user-email-alerts'),
    
    # Logs de correos
    path('email-logs/', views.email_logs, name='email-logs'),

    # Análisis (páginas)
    path('analysis/ip/', views.analysis_ip_view, name='analysis-ip'),
    path('analysis/indicator/', views.analysis_indicator_view, name='analysis-indicator'),
    path('analysis/mac/', views.analysis_mac_view, name='analysis-mac'),

    # Análisis (APIs)
    path('api/analysis/ip/', views.analyze_ip, name='analyze-ip'),
    path('api/analysis/indicator/', views.analyze_indicator, name='analyze-indicator'),
    path('api/analysis/mac/', views.analyze_mac, name='analyze-mac'),
    path('analysis/config/', views.analysis_config, name='analysis-config'),
    path('api/analysis/config/save/', views.analysis_config_save, name='analysis-config-save'),

    # Settings -> Servicios internos de análisis
    path('settings/analysis-services/', views.analysis_services_hub, name='analysis-services-hub'),
    path('settings/analysis-services/virustotal/', views.virustotal_config, name='virustotal-config'),
    path('api/settings/analysis-services/virustotal/save/', views.virustotal_config_save, name='virustotal-config-save'),
    path('api/settings/analysis-services/virustotal/test/', views.virustotal_test, name='virustotal-test'),

    path('settings/analysis-services/abuseipdb/', views.abuseipdb_config, name='abuseipdb-config'),
    path('api/settings/analysis-services/abuseipdb/save/', views.abuseipdb_config_save, name='abuseipdb-config-save'),
    path('api/settings/analysis-services/abuseipdb/test/', views.abuseipdb_test, name='abuseipdb-test'),

    path('settings/analysis-services/macvendors/', views.macvendors_config, name='macvendors-config'),
    path('api/settings/analysis-services/macvendors/save/', views.macvendors_config_save, name='macvendors-config-save'),
    path('api/settings/analysis-services/macvendors/test/', views.macvendors_test, name='macvendors-test'),

    # Análisis Interno (histórico)
    path('analysis/internal/virustotal/', views.analysis_internal_vt, name='analysis-internal-vt'),
    path('analysis/internal/abuseipdb/', views.analysis_internal_abuseipdb, name='analysis-internal-abuseipdb'),
    path('analysis/internal/macvendors/', views.analysis_internal_macvendors, name='analysis-internal-macvendors'),
    path('analysis/internal/virustotal/<int:pk>/', views.analysis_internal_vt_detail, name='analysis-internal-vt-detail'),
    path('analysis/internal/abuseipdb/<int:pk>/', views.analysis_internal_abuseipdb_detail, name='analysis-internal-abuseipdb-detail'),
    path('analysis/internal/macvendors/<int:pk>/', views.analysis_internal_macvendors_detail, name='analysis-internal-macvendors-detail'),

    # Guardar resultados en registros locales
    path('api/analysis/save/vt/', views.save_vt_record, name='save-vt-record'),
    path('api/analysis/save/abuseipdb/', views.save_abuseipdb_record, name='save-abuseipdb-record'),
    path('api/analysis/save/macvendors/', views.save_macvendors_record, name='save-macvendors-record'),

    # Búsquedas locales (offline)
    path('analysis/local/ip/', views.local_search_ip, name='local-search-ip'),
    path('analysis/local/mac/', views.local_search_mac, name='local-search-mac'),
    path('analysis/local/indicator/', views.local_search_indicator, name='local-search-indicator'),

    # Reportes de históricos
    path('analysis/reports/virustotal/', views.report_vt, name='report-vt'),
    path('analysis/reports/abuseipdb/', views.report_abuseipdb, name='report-abuseipdb'),
    path('analysis/reports/macvendors/', views.report_macvendors, name='report-macvendors'),

    # Herramientas de red
    path('tools/ping/', views.tools_ping_view, name='tools-ping'),
    path('api/tools/ping/', views.api_tools_ping, name='api-tools-ping'),

    path('tools/dns/', views.tools_dns_view, name='tools-dns'),
    path('api/tools/dns/', views.api_tools_dns, name='api-tools-dns'),

    path('tools/scan/', views.tools_scan_view, name='tools-scan'),
    path('api/tools/scan/', views.api_tools_scan, name='api-tools-scan'),

    path('tools/bruteforce/', views.tools_bruteforce_view, name='tools-bruteforce'),
    path('api/tools/bruteforce/', views.api_tools_bruteforce, name='api-tools-bruteforce'),

    path('tools/traceroute/', views.tools_traceroute_view, name='tools-traceroute'),
    path('api/tools/traceroute/', views.api_tools_traceroute, name='api-tools-traceroute'),

    path('tools/service-scan/', views.tools_service_scan_view, name='tools-service-scan'),
    path('api/tools/service-scan/', views.api_tools_service_scan, name='api-tools-service-scan'),

    path('tools/discovery/', views.tools_discovery_view, name='tools-discovery'),
    path('api/tools/discovery/', views.api_tools_discovery, name='api-tools-discovery'),

    path('tools/ipcalc/', views.tools_ipcalc_view, name='tools-ipcalc'),
    path('api/tools/ipcalc/', views.api_tools_ipcalc, name='api-tools-ipcalc'),

    # Monitoreo de servicios
    path('tools/monitoring/', views.monitoring_services, name='monitoring-services'),
    path('api/monitoring/check/', views.monitoring_check_api, name='monitoring-check-api'),
    path('api/monitoring/history/<int:servicio_id>/', views.monitoring_history_api, name='monitoring-history-api'),
    
    # Configuración de monitoreo (Settings)
    path('settings/monitoring/', views.monitoring_config, name='monitoring-config'),

    # Amenazas IDS-IPS (deshabilitadas temporalmente)
    path('threats/', views.threats_dashboard, name='threats-dashboard'),
    # Configuración de notificaciones mejoradas
    path('settings/notifications/', views.notification_settings, name='notification-settings'),
    path('api/notifications/settings/save/', views.save_notification_settings, name='save-notification-settings'),
    path('api/notifications/channel/add/', views.add_notification_channel, name='add-notification-channel'),
    path('api/notifications/template/add/', views.add_notification_template, name='add-notification-template'),
    path('api/notifications/channel/<int:channel_id>/delete/', views.delete_notification_channel, name='delete-notification-channel'),
    path('api/notifications/template/<int:template_id>/delete/', views.delete_notification_template, name='delete-notification-template'),
    path('api/notifications/stats/', views.get_notification_stats, name='get-notification-stats'),
    path('api/notifications/channel/<int:channel_id>/test/', views.test_notification_channel, name='test-notification-channel'),
    path('api/notifications/channel/<int:channel_id>/toggle/', views.toggle_notification_channel, name='toggle-notification-channel'),
    path('api/notifications/cleanup/', views.cleanup_notifications, name='cleanup-notifications'),
    path('api/notifications/queue/status/', views.notification_queue_status, name='notification-queue-status'),

    # Análisis Inteligente con IA (Ollama)
    path('analysis/ollama/', views.analysis_ollama, name='analysis-ollama'),
    path('api/analysis/ollama/test/', views.ollama_test_connection, name='ollama-test-connection'),
    path('api/analysis/ollama/trends/', views.ollama_analyze_trends, name='ollama-analyze-trends'),
    path('api/analysis/ollama/ip/', views.ollama_analyze_ip, name='ollama-analyze-ip'),
    path('api/analysis/ollama/correlate/', views.ollama_correlate_events, name='ollama-correlate-events'),
    path('api/analysis/ollama/report/', views.ollama_generate_report, name='ollama-generate-report'),
    path('api/analysis/ollama/report/email/', views.ollama_send_report_email, name='ollama-send-report-email'),
    path('api/analysis/ollama/cross-reference/', views.ollama_cross_reference, name='ollama-cross-reference'),
    path('api/analysis/ollama/chat/', views.ollama_chat, name='ollama-chat'),

    # Configuración de Ollama
    path('settings/ollama/', views.ollama_config, name='ollama-config'),
    path('api/settings/ollama/save/', views.ollama_config_save, name='ollama-config-save'),

    # Configuracion LDAP
    path('settings/ldap/', views.ldap_config_list, name='ldap-config-list'),
    path('settings/ldap/create/', views.ldap_config_create, name='ldap-config-create'),
    path('settings/ldap/edit/<int:config_id>/', views.ldap_config_edit, name='ldap-config-edit'),
    path('settings/ldap/delete/<int:config_id>/', views.ldap_config_delete, name='ldap-config-delete'),
]
