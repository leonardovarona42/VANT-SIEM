from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"api/policies", views.DlpPolicyViewSet, basename="aegis-policy")
router.register(r"api/rules", views.DlpRuleViewSet, basename="aegis-rule")
router.register(r"api/incidents", views.DlpThreatViewSet, basename="aegis-incident")
router.register(r"api/scans", views.DlpScanSummaryViewSet, basename="aegis-scan")

urlpatterns = [
    # REST API
    path("", include(router.urls)),
    path("api/health/", views.health_check, name="aegis-api-health"),
    path("api/stats/", views.dlp_statistics, name="aegis-api-stats"),
    # Agent-facing endpoints
    path("api/agent/dlp/config/", views.agent_dlp_config, name="aegis-agent-config"),
    path("api/agent/dlp/threats/", views.ingest_dlp_threats, name="aegis-ingest-threats"),
    path("api/agent/dlp/threats/upload/", views.ingest_dlp_threats_multipart, name="aegis-ingest-threats-upload"),
    # UI dashboard
    path("dashboard/", views.dlp_dashboard, name="aegis-dashboard"),
    path("incidents/", views.incidents_list, name="aegis-incidents"),
    path("incidents/<int:pk>/", views.incident_detail, name="aegis-incident-detail"),
    path("incidents/<int:pk>/ack/", views.incident_acknowledge, name="aegis-incident-ack"),
    path("incidents/<int:pk>/resolve/", views.incident_resolve, name="aegis-incident-resolve"),
    path("policies/", views.policies_list, name="aegis-policies"),
    path("policies/create/", views.policy_create, name="aegis-policy-create"),
    path("policies/<str:code>/edit/", views.policy_edit, name="aegis-policy-edit"),
    path("policies/<str:code>/delete/", views.policy_delete, name="aegis-policy-delete"),
    path("policies/<str:code>/rules/", views.policy_rules, name="aegis-policy-rules"),
    path("rules/<int:rule_id>/delete/", views.rule_delete, name="aegis-rule-delete"),
    path("scans/", views.scan_summaries, name="aegis-scans"),
    path("evidence/<int:pk>/download/", views.evidence_download, name="aegis-evidence-download"),
]
