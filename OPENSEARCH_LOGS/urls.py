from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    health_check, LogSourceViewSet, LogEventListView, LogEventDetailView,
    ingest_log, ingest_bulk, ingest_syslog, log_statistics,
    LogRetentionPolicyViewSet,
)

router = DefaultRouter()
router.register(r'sources', LogSourceViewSet, basename='log-source')
router.register(r'retention', LogRetentionPolicyViewSet, basename='log-retention')

urlpatterns = [
    path('health/', health_check, name='logs-health'),
    path('api/events/', LogEventListView.as_view(), name='log-events-list'),
    path('api/events/<int:pk>/', LogEventDetailView.as_view(), name='log-events-detail'),
    path('api/ingest/', ingest_log, name='log-ingest'),
    path('api/ingest/bulk/', ingest_bulk, name='log-ingest-bulk'),
    path('api/syslog/', ingest_syslog, name='log-syslog'),
    path('api/statistics/', log_statistics, name='log-statistics'),
    path('', include(router.urls)),
]
