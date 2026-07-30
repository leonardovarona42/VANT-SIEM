from django.urls import path, include
from logs_app import views

urlpatterns = [
    path('api/health/', views.health_check, name='health_check'),
    path('api/ingest/bulk/', views.ingest_bulk, name='ingest_bulk'),
    path('api/sources/', views.upsert_source, name='upsert_source'),
    path('api/sources/list/', views.source_list, name='source_list'),
    path('api/sources/host-ips/', views.source_host_ips, name='source_host_ips'),
    path('api/sources/source-types/', views.source_type_list, name='source_type_list'),
    path('api/events/', views.event_list, name='event_list'),
    path('api/events/field-values/', views.field_values, name='event_field_values'),
    path('api/events/histogram/', views.event_histogram, name='event_histogram'),
    path('api/events/<int:pk>/', views.event_detail, name='event_detail'),
    path('api/statistics/', views.log_statistics, name='log_statistics'),
    path('api/statistics/suricata/', views.suricata_stats, name='suricata_stats'),
    path('api/retention/',              views.retention_list,  name='retention_list'),
    path('api/retention/cleanup/',      views.retention_cleanup, name='retention_cleanup'),
    path('api/storage/dashboard/',      views.storage_dashboard, name='storage_dashboard'),
]
