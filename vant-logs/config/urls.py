from django.urls import path, include
from logs_app import views

urlpatterns = [
    path('api/health/', views.health_check, name='health_check'),
    path('api/ingest/bulk/', views.ingest_bulk, name='ingest_bulk'),
    path('api/sources/', views.upsert_source, name='upsert_source'),
    path('api/events/', views.event_list, name='event_list'),
    path('api/events/histogram/', views.event_histogram, name='event_histogram'),
    path('api/events/<int:pk>/', views.event_detail, name='event_detail'),
    path('api/statistics/', views.log_statistics, name='log_statistics'),
    path('api/retention/', views.retention_list, name='retention_list'),
    path('api/retention/cleanup/', views.retention_cleanup, name='retention_cleanup'),
]
