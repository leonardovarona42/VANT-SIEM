from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views
from . import ui_views

router = DefaultRouter()
router.register(r'api/policies', views.DlpPolicyViewSet, basename='dlp-policy')
router.register(r'api/rules', views.DlpRuleViewSet, basename='dlp-rule')
router.register(r'api/incidents', views.DlpIncidentViewSet, basename='dlp-incident')
router.register(r'api/scans', views.DlpScanSummaryViewSet, basename='dlp-scan')

urlpatterns = [
    path('', include(router.urls)),

    path('api/agent/dlp/config/', views.dlp_agent_config, name='dlp-agent-config'),
    path('api/agent/dlp/threats/', views.ingest_dlp_threats, name='dlp-ingest-threats'),
    path('api/statistics/', views.dlp_statistics, name='dlp-statistics'),

    path('dashboard/', ui_views.dlp_dashboard, name='dlp-dashboard'),
    path('incidents/', ui_views.incidents_list, name='dlp-incidents'),
    path('incidents/<int:pk>/', ui_views.incident_detail, name='dlp-incident-detail'),
    path('incidents/<int:pk>/ack/', ui_views.incident_acknowledge, name='dlp-incident-ack'),
    path('incidents/<int:pk>/resolve/', ui_views.incident_resolve, name='dlp-incident-resolve'),
    path('policies/', ui_views.policies_list, name='dlp-policies'),
    path('policies/create/', ui_views.policy_create, name='dlp-policy-create'),
    path('policies/<str:code>/edit/', ui_views.policy_edit, name='dlp-policy-edit'),
    path('policies/<str:code>/delete/', ui_views.policy_delete, name='dlp-policy-delete'),
    path('policies/<str:code>/rules/', ui_views.policy_rules, name='dlp-policy-rules'),
    path('rules/<int:rule_id>/delete/', ui_views.rule_delete, name='dlp-rule-delete'),
    path('scans/', ui_views.scan_summaries, name='dlp-scans'),
]
