from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    health_check, LogSourceViewSet, LogEventListView, LogEventDetailView,
    ingest_log, ingest_bulk, ingest_syslog, log_statistics, log_histogram,
    LogRetentionPolicyViewSet,
)
from .ui_views import (
    logs_discovery, logs_list, log_detail, logs_sources, logs_retention,
    log_source_create, log_source_edit, log_source_delete,
    run_cleanup_now, delete_logs_by_filter, suricata_dashboard,
)

router = DefaultRouter()
router.register(r'api/sources', LogSourceViewSet, basename='log-source')
router.register(r'api/retention', LogRetentionPolicyViewSet, basename='log-retention')

urlpatterns = [
    # UI - Discovery
    path('', logs_discovery, name='logs-dashboard'),
    path('list/', logs_list, name='logs-list'),
    path('event/<int:pk>/', log_detail, name='log-detail'),
    path('sources/', logs_sources, name='logs-sources'),
    path('sources/new/', log_source_create, name='logs-source-create'),
    path('sources/<str:source_id>/edit/', log_source_edit, name='logs-source-edit'),
    path('sources/<str:source_id>/delete/', log_source_delete, name='logs-source-delete'),
    path('suricata/', suricata_dashboard, name='logs-suricata'),
    path('retention/', logs_retention, name='logs-retention'),
    path('actions/cleanup/', run_cleanup_now, name='logs-cleanup'),
    path('actions/delete-filter/', delete_logs_by_filter, name='logs-delete-filter'),

    # API
    path('api/health/', health_check, name='logs-api-health'),
    path('api/events/', LogEventListView.as_view(), name='log-api-events-list'),
    path('api/events/<int:pk>/', LogEventDetailView.as_view(), name='log-api-events-detail'),
    path('api/ingest/', ingest_log, name='log-api-ingest'),
    path('api/ingest/bulk/', ingest_bulk, name='log-api-ingest-bulk'),
    path('api/syslog/', ingest_syslog, name='log-api-syslog'),
    path('api/statistics/', log_statistics, name='log-api-statistics'),
    path('api/events/histogram/', log_histogram, name='log-api-histogram'),
    path('api/', include(router.urls)),
]
