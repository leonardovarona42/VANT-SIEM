import json
import logging

from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import DlpPolicy, DlpRule, DlpThreat
from .serializers import (
    DlpPolicySerializer,
    DlpThreatSerializer,
    DlpThreatSubmitSerializer,
)

logger = logging.getLogger(__name__)


# =========================================================================
#  Health
# =========================================================================

@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    try:
        from django.db import connection
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False

    threat_count = DlpThreat.objects.count()
    policy_count = DlpPolicy.objects.filter(is_active=True).count()

    return Response({
        "status": "healthy" if db_ok else "degraded",
        "service": "assets-dlp",
        "database": "connected" if db_ok else "disconnected",
        "total_threats": threat_count,
        "active_policies": policy_count,
        "timestamp": timezone.now().isoformat(),
    })


# =========================================================================
#  Agent-facing endpoints
# =========================================================================

@api_view(["GET"])
@permission_classes([AllowAny])
def agent_dlp_config(request):
    """Return active DLP policies and rules for agents to consume."""
    policies = DlpPolicy.objects.filter(is_active=True).prefetch_related("rules")
    serializer = DlpPolicySerializer(policies, many=True)
    return Response({"policies": serializer.data, "fetched_at": timezone.now().isoformat()})


@api_view(["POST"])
@permission_classes([AllowAny])
def agent_submit_threats(request):
    """
    Receive DLP threats from agents.

    Stores the threat and publishes an event to the service bus
    so EVENT_M can create the actual Incident + Reporte.
    """
    serializer = DlpThreatSubmitSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    threats_data = serializer.validated_data["incidents"]
    agent_id = serializer.validated_data.get("agent_id")

    import uuid

    created = []
    skipped = 0

    for item in threats_data:
        fingerprint = item.get("fingerprint", "")
        if DlpThreat.objects.filter(fingerprint=fingerprint).exists():
            skipped += 1
            continue

        threat_agent_id = agent_id or item.get("agent_id")
        if not threat_agent_id:
            threat_agent_id = uuid.UUID(int=0)

        try:
            threat = DlpThreat.objects.create(
                fingerprint=fingerprint,
                agent_id=threat_agent_id,
                agent_hostname=item.get("agent_hostname", ""),
                policy_code=item.get("policy_code", ""),
                rule_name=item.get("rule_name", ""),
                classification=item.get("classification", ""),
                severity=item.get("severity", "high"),
                file_name=item.get("file_name", "") or "",
                file_path=item.get("file_path", "") or "",
                file_hash=item.get("file_hash", "") or "",
                file_size=item.get("metadata", {}).get("size", 0),
                actor=item.get("actor", ""),
                channel=item.get("channel", "filesystem"),
                summary=item.get("summary", "") or "",
                matched_keywords=item.get("matched_keywords", []),
                metadata=item.get("metadata", {}),
                detected_at=item.get("detected_at", timezone.now()),
            )
            created.append(threat)
        except Exception as e:
            logger.warning("dlp.threat.create.error fingerprint=%s error=%s", fingerprint, e)

    # Publish events to service bus
    published = 0
    for threat in created:
        try:
            _publish_dlp_event(threat)
            threat.event_published = True
            threat.save(update_fields=["event_published"])
            published += 1
        except Exception as e:
            logger.error("dlp.event.publish.failed threat=%s error=%s", threat.fingerprint, e)

    logger.info(
        "dlp.threats.received agent=%s created=%d published=%d skipped=%d",
        agent_id, len(created), published, skipped,
    )
    return Response({
        "status": "ok",
        "created": len(created),
        "published": published,
        "skipped": skipped,
    })


def _publish_dlp_event(threat):
    """Publish a DLP threat event to the service bus for EVENT_M to consume."""
    try:
        from CORE.service_bus import ServiceBus
        from CORE.events import ASSET_DLP_INCIDENT

        bus = ServiceBus.get_instance()
        bus.publish(
            channel="asset.dlp",
            event_type=ASSET_DLP_INCIDENT,
            payload={
                "fingerprint": threat.fingerprint,
                "agent_id": str(threat.agent_id),
                "agent_hostname": threat.agent_hostname,
                "classification": threat.classification,
                "severity": threat.severity,
                "file_name": threat.file_name,
                "file_path": threat.file_path,
                "file_hash": threat.file_hash,
                "actor": threat.actor,
                "channel": threat.channel,
                "summary": threat.summary,
                "matched_keywords": threat.matched_keywords,
                "policy_code": threat.policy_code,
                "rule_name": threat.rule_name,
                "detected_at": threat.detected_at.isoformat(),
            },
        )
    except Exception as e:
        logger.warning("dlp.service_bus.unavailable error=%s", e)
        raise


# =========================================================================
#  Management endpoints
# =========================================================================

@api_view(["GET"])
def threat_stats(request):
    total = DlpThreat.objects.count()
    by_severity = dict(
        DlpThreat.objects.values("severity")
        .annotate(c=Count("id"))
        .order_by()
        .values_list("severity", "c")
    )
    by_channel = dict(
        DlpThreat.objects.values("channel")
        .annotate(c=Count("id"))
        .order_by("-c")
        .values_list("channel", "c")[:10]
    )
    by_classification = dict(
        DlpThreat.objects.values("classification")
        .annotate(c=Count("id"))
        .order_by("-c")
        .values_list("classification", "c")[:10]
    )
    top_agents = list(
        DlpThreat.objects.values("agent_hostname")
        .annotate(c=Count("id"))
        .order_by("-c")
        .values_list("agent_hostname", "c")[:10]
    )
    today = DlpThreat.objects.filter(
        detected_at__date=timezone.now().date()
    ).count()

    return Response({
        "total": total,
        "today": today,
        "by_severity": by_severity,
        "by_channel": by_channel,
        "by_classification": by_classification,
        "top_agents": [{"hostname": h, "incidents": c} for h, c in top_agents],
    })


class DlpThreatViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DlpThreat.objects.all()
    serializer_class = DlpThreatSerializer
    lookup_field = "fingerprint"

    def get_queryset(self):
        qs = super().get_queryset()
        params = self.request.query_params

        severity_filter = params.get("severity")
        classification = params.get("classification")
        agent = params.get("agent_id")
        search = params.get("search")

        if severity_filter:
            qs = qs.filter(severity=severity_filter)
        if classification:
            qs = qs.filter(classification=classification)
        if agent:
            qs = qs.filter(agent_id=agent)
        if search:
            from django.db.models import Q
            qs = qs.filter(
                Q(file_name__icontains=search)
                | Q(file_path__icontains=search)
                | Q(actor__icontains=search)
                | Q(summary__icontains=search)
            )

        return qs
