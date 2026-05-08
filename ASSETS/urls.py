from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    health_check,
    agent_dlp_config,
    agent_submit_threats,
    threat_stats,
    DlpThreatViewSet,
)

router = DefaultRouter()
router.register(r"api/threats", DlpThreatViewSet, basename="dlp-threat")

urlpatterns = [
    # Health
    path("api/health/", health_check, name="assets-api-health"),
    path("api/stats/", threat_stats, name="assets-api-stats"),

    # Agent-facing DLP endpoints
    path("api/agent/dlp/config/", agent_dlp_config, name="assets-agent-dlp-config"),
    path("api/agent/dlp/threats/", agent_submit_threats, name="assets-agent-dlp-threats"),

    # REST framework viewsets (read-only threat list)
    path("api/", include(router.urls)),
]
