from django.contrib.auth import views as auth_views
from django.urls import path
from . import views

urlpatterns = [
    # Auth
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('password-change/', views.password_change_view, name='password-change'),

    # Usuarios
    path('users/', views.user_management, name='user-management'),
    path('users/create-request/', views.create_user_request, name='create-user-request'),
    path('users/approve/<int:request_id>/', views.approve_user_request, name='approve-user-request'),
    path('users/reject/<int:request_id>/', views.reject_user_request, name='reject-user-request'),
    path('users/<int:user_id>/permissions/', views.user_permissions, name='user-permissions'),
    path('users/<int:user_id>/permissions/<int:permission_id>/update/', views.update_user_permission, name='update-user-permission'),

    # Notificaciones
    path('notifications/', views.notifications, name='notifications'),
    path('api/notifications/', views.get_notifications, name='get-notifications'),
    path('notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark-notification-read'),
    path('notifications/mark-all-read/', views.mark_all_notifications_read, name='mark-all-notifications-read'),

    # Logs del sistema
    path('system/logs/', views.system_logs, name='system-logs'),
    path('logging-control/', views.logging_control, name='logging-control'),
    path('api/logging/start/', views.start_logging_system, name='start-logging-system'),
    path('api/logging/stop/', views.stop_logging_system, name='stop-logging-system'),
    path('api/logging/status/', views.get_logging_status_api, name='get-logging-status'),

    # Configuracion de correo
    path('email-configuration/', views.email_configuration, name='email-configuration'),
    path('email-configuration/create/', views.create_email_config, name='create-email-config'),
    path('email-configuration/edit/<int:config_id>/', views.edit_email_config, name='edit-email-config'),
    path('api/email-config/<int:config_id>/activate/', views.activate_email_config, name='activate-email-config'),
    path('api/email-config/<int:config_id>/test/', views.test_email_config, name='test-email-config'),

    # Notificaciones - settings
    path('settings/notifications/', views.save_notification_settings, name='notification-settings'),
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

    # LDAP
    path('settings/ldap/', views.ldap_config_list, name='ldap-config-list'),
    path('settings/ldap/create/', views.ldap_config_create, name='ldap-config-create'),
    path('settings/ldap/edit/<int:config_id>/', views.ldap_config_edit, name='ldap-config-edit'),
    path('settings/ldap/delete/<int:config_id>/', views.ldap_config_delete, name='ldap-config-delete'),
]
