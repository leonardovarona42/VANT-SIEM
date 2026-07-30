from django.urls import path
from . import views

urlpatterns = [
    # AbuseIPDB
    path('ip/lookup/', views.ip_lookup, name='ip_lookup'),
    path('ip/reports/', views.ip_report_list, name='ip_report_list'),
    path('ip/reports/<int:pk>/', views.ip_report_detail, name='ip_report_detail'),

    # MAC Vendors
    path('mac/lookup/', views.mac_lookup, name='mac_lookup'),

    # VirusTotal
    path('vt/lookup/', views.vt_lookup, name='vt_lookup'),

    # API Key Management
    path('keys/', views.api_key_list, name='api_key_list'),
    path('keys/<str:provider>/', views.api_key_detail, name='api_key_detail'),
    path('keys/<str:provider>/test/', views.api_key_test, name='api_key_test'),

    # Scan Jobs (SOAR later)
    path('jobs/', views.scan_job_list, name='scan_job_list'),
    path('jobs/<int:pk>/', views.scan_job_detail, name='scan_job_detail'),
    path('jobs/create/', views.scan_job_create, name='scan_job_create'),

    # Dashboard stats
    path('stats/', views.intelligence_stats, name='intelligence_stats'),

    # Cross-reference analytics
    path('analytics/dashboard/', views.analytics_dashboard, name='analytics_dashboard'),
    path('analytics/geo/', views.analytics_geo, name='analytics_geo'),

    # Web views (rendered by vant-web, but API for data)
    path('dashboard/', views.intelligence_dashboard, name='intelligence_dashboard'),
]
