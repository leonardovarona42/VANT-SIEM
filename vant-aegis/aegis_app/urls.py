from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"policies", views.DlpPolicyViewSet, basename="dlp-policy")
router.register(r"incidents", views.DlpThreatViewSet, basename="dlp-incident")
router.register(r"scans", views.DlpScanSummaryViewSet, basename="dlp-scan")

urlpatterns = [
    path("api/health/", views.health_check, name="aegis-health"),
    path("api/stats/", views.dlp_statistics, name="aegis-stats"),

    path("api/agent/dlp/config/", views.agent_dlp_config, name="aegis-agent-config"),
    path("api/agent/dlp/threats/", views.ingest_dlp_threats, name="aegis-agent-ingest"),
    path("api/agent/dlp/threats/upload/", views.ingest_dlp_threats_multipart, name="aegis-agent-ingest-upload"),

    path("api/evidence/<int:pk>/download/", views.evidence_download, name="aegis-evidence-download"),

    path("", include(router.urls)),
]
