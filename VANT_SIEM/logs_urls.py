from django.urls import path
from . import logs_views as views

urlpatterns = [
    # Dashboards principales
    path('', views.log_dashboard, name='log-dashboard'),
    path('list/', views.log_list, name='log-list'),
    path('detail/<int:event_id>/', views.log_detail, name='log-detail'),
    path('sources/', views.log_sources_view, name='log-sources'),
    path('statistics/', views.log_statistics, name='log-statistics'),

    # Saved visualizations / dashboards
    path('saved/', views.saved_visualizations_list, name='saved-visualizations'),
    path('saved/create/', views.saved_visualization_create, name='saved-visualizations-create'),
    path('saved/<str:vis_id>/update/', views.saved_visualization_update, name='saved-visualizations-update'),
    path('saved/<str:vis_id>/delete/', views.saved_visualization_delete, name='saved-visualizations-delete'),

    # APIs
    path('api/events/', views.api_log_events, name='api-log-events'),
    path('api/ingest/', views.api_ingest_log, name='api-ingest-log'),
    path('api/sources/', views.api_log_sources, name='api-log-sources'),
    path('api/saved/', views.saved_visualizations_list, name='api-saved-visualizations'),

    # Legacy redirects
    path('snort/', views.legacy_snort_redirect, name='snort-log-list'),
    path('suricata/', views.legacy_suricata_redirect, name='suricata-dashboard'),
]
