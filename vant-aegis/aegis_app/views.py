import base64
import logging
from datetime import timedelta
from pathlib import Path

from django.db.models import Count, Q
from django.http import FileResponse, Http404
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

from .models import DlpPolicy, DlpRule, DlpThreat, DlpScanSummary
from .serializers import (
    DlpPolicySerializer, DlpRuleSerializer,
    DlpThreatListSerializer, DlpThreatDetailSerializer,
    DlpThreatIngestSerializer, DlpScanSummarySerializer,
    DlpAgentConfigSerializer, DlpThreatIngestMultipartSerializer,
)

logger = logging.getLogger(__name__)

ALLOWED_MIME_PREFIXES = (
    "text/", "application/pdf", "application/msword",
    "application/vnd.openxmlformats-officedocument",
    "application/vnd.ms-", "image/", "message/rfc822",
)
MAX_EVIDENCE_SIZE = 25 * 1024 * 1024


# =========================================================================
#  Helpers
# =========================================================================

def _get_agent_id(request):
    return getattr(request, "agent_id", "") or ""


def _get_username(request):
    claims = getattr(request, "user_claims", None)
    if claims:
        return claims.get("username", "api")
    return "api"


def _parse_detected_at(raw):
    if raw:
        try:
            detected_at = timezone.datetime.fromisoformat(
                raw.replace("Z", "+00:00")
            )
            if not timezone.is_aware(detected_at):
                detected_at = timezone.make_aware(detected_at)
            return detected_at
        except (ValueError, TypeError):
            pass
    return timezone.now()


def _publish_dlp_event(incident):
    try:
        from vant_common.bus import EventBus
        bus = EventBus("aegis")
        bus.publish_event("threats", "threat_detected", {
            "fingerprint": incident.fingerprint,
            "agent_id": str(incident.agent_id),
            "agent_hostname": incident.agent_hostname,
            "classification": incident.classification,
            "severity": incident.severity,
            "file_name": incident.file_name,
            "file_path": incident.file_path,
            "file_hash": incident.file_hash,
            "actor": incident.actor,
            "channel": incident.channel,
            "summary": incident.summary,
            "matched_keywords": incident.matched_keywords,
            "policy_code": incident.policy_code,
            "rule_name": incident.rule_name,
            "detected_at": incident.detected_at.isoformat(),
        })
    except Exception as e:
        logger.warning("aegis.service_bus.unavailable error=%s", e)
        raise


def _ingest_incidents(incidents_data, agent_id, uploaded_files=None):
    uploaded_files = uploaded_files or {}
    created_count = 0
    skipped_count = 0

    for inc_data in incidents_data:
        fingerprint = inc_data.get("fingerprint", "")
        if not fingerprint:
            skipped_count += 1
            continue

        detected_at = _parse_detected_at(inc_data.get("detected_at", ""))
        metadata = inc_data.get("metadata", {})

        incident, created = DlpThreat.objects.update_or_create(
            fingerprint=fingerprint,
            defaults={
                "agent_id": agent_id,
                "agent_hostname": inc_data.get("agent_hostname", ""),
                "policy_code": inc_data.get("policy_code", ""),
                "rule_name": inc_data.get("rule_name", ""),
                "classification": inc_data.get("classification", ""),
                "severity": inc_data.get("severity", "high"),
                "status": inc_data.get("status", "open"),
                "file_name": inc_data.get("file_name", "") or "",
                "file_path": inc_data.get("file_path", "") or "",
                "file_hash": inc_data.get("file_hash", "") or "",
                "file_size": metadata.get("size", 0),
                "actor": inc_data.get("actor", ""),
                "channel": inc_data.get("channel", "filesystem"),
                "summary": inc_data.get("summary", "") or "",
                "matched_keywords": inc_data.get("matched_keywords", []),
                "metadata": metadata,
                "detected_at": detected_at,
            },
        )

        if created:
            created_count += 1

            _save_evidence(incident, inc_data, fingerprint, uploaded_files)

            if incident.severity == "critical":
                try:
                    _publish_dlp_event(incident)
                    DlpThreat.objects.filter(fingerprint=fingerprint).update(event_published=True)
                except Exception as e:
                    logger.error("aegis.event.publish.failed fingerprint=%s error=%s", fingerprint, e)

    return created_count, skipped_count


def _save_evidence(incident, inc_data, fingerprint, uploaded_files):
    if incident.evidence_file:
        return

    file_content_b64 = inc_data.get("file_content_base64", "")
    if fingerprint in uploaded_files:
        try:
            uf = uploaded_files[fingerprint]
            if uf.size > MAX_EVIDENCE_SIZE:
                logger.warning("aegis.evidence.too_large fingerprint=%s size=%s", fingerprint, uf.size)
                return
            mime = uf.content_type or ""
            if not any(mime.startswith(p) for p in ALLOWED_MIME_PREFIXES):
                logger.warning("aegis.evidence.invalid_mime fingerprint=%s mime=%s", fingerprint, mime)
                return
            safe_ext = Path(inc_data.get("file_name", "file")).suffix or ".bin"
            safe_ext = "".join(c for c in safe_ext if c.isalnum() or c in ".-")
            if len(safe_ext) > 10:
                safe_ext = ".bin"
            filename = f"{fingerprint[:16]}{safe_ext}"
            incident.evidence_file.save(filename, uf, save=True)
        except Exception as e:
            logger.warning("aegis.evidence.save.failed fingerprint=%s error=%s", fingerprint, e)
    elif file_content_b64:
        try:
            raw = base64.b64decode(file_content_b64)
            if len(raw) > MAX_EVIDENCE_SIZE:
                logger.warning("aegis.evidence.too_large fingerprint=%s size=%s", fingerprint, len(raw))
                return
            mime_guess = inc_data.get("file_name", "").lower()
            if mime_guess.endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".com", ".php", ".jsp", ".war")):
                logger.warning("aegis.evidence.blocked_ext fingerprint=%s name=%s", fingerprint, mime_guess)
                return
            safe_ext = Path(inc_data.get("file_name", "file")).suffix or ".bin"
            safe_ext = "".join(c for c in safe_ext if c.isalnum() or c in ".-")
            if len(safe_ext) > 10:
                safe_ext = ".bin"
            filename = f"{fingerprint[:16]}{safe_ext}"
            from django.core.files.base import ContentFile
            incident.evidence_file.save(filename, ContentFile(raw), save=True)
        except Exception as e:
            logger.warning("aegis.evidence.save.failed fingerprint=%s error=%s", fingerprint, e)


# =========================================================================
#  Health
# =========================================================================

@api_view(["GET"])
def health_check(request):
    try:
        from django.db import connection
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False

    incident_count = DlpThreat.objects.count()
    policy_count = DlpPolicy.objects.filter(is_active=True).count()

    return Response({
        "status": "healthy" if db_ok else "degraded",
        "service": "aegis-dlp",
        "database": "connected" if db_ok else "disconnected",
        "total_incidents": incident_count,
        "active_policies": policy_count,
        "timestamp": timezone.now().isoformat(),
    })


# =========================================================================
#  Agent-facing endpoints
# =========================================================================

@api_view(["GET"])
def agent_dlp_config(request):
    if getattr(request, "auth_type", "") != "agent":
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("Valid agent token required")
    policies = DlpPolicy.objects.filter(is_active=True).prefetch_related("rules")
    serializer = DlpAgentConfigSerializer({"policies": policies, "fetched_at": timezone.now()})
    return Response(serializer.data)


@api_view(["POST"])
def ingest_dlp_threats(request):
    if getattr(request, "auth_type", "") != "agent":
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("Valid agent token required")

    serializer = DlpThreatIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    agent_id = data.get("agent_id", _get_agent_id(request))
    incidents_data = data["incidents"]

    if not incidents_data:
        return Response({"status": "ok", "ingested": 0})

    created_count, skipped_count = _ingest_incidents(incidents_data, agent_id)

    logger.info(
        "aegis.ingest agent=%s created=%d skipped=%d total=%d",
        agent_id, created_count, skipped_count, len(incidents_data),
    )
    return Response({
        "status": "ok",
        "ingested": created_count,
        "skipped": skipped_count,
        "total_received": len(incidents_data),
    }, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
def ingest_dlp_threats_multipart(request):
    if getattr(request, "auth_type", "") not in ("agent", "user"):
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("Valid token required")

    serializer = DlpThreatIngestMultipartSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    meta = serializer.validated_data["metadata"]
    agent_id = meta.get("agent_id", _get_agent_id(request))
    incidents_data = meta["incidents"]

    uploaded_files = {}
    for key in request.FILES:
        if key.startswith("file_"):
            fingerprint = key[5:]
            uploaded_files[fingerprint] = request.FILES[key]

    if not incidents_data:
        return Response({"status": "ok", "ingested": 0})

    created_count, skipped_count = _ingest_incidents(incidents_data, agent_id, uploaded_files)

    logger.info(
        "aegis.ingest.multipart agent=%s created=%d skipped=%d total=%d",
        agent_id, created_count, skipped_count, len(incidents_data),
    )
    return Response({
        "status": "ok",
        "ingested": created_count,
        "skipped": skipped_count,
        "total_received": len(incidents_data),
    }, status=status.HTTP_201_CREATED)


# =========================================================================
#  Statistics
# =========================================================================

@api_view(["GET"])
def dlp_statistics(request):
    if getattr(request, "auth_type", "") != "user":
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("User authentication required")

    hours = int(request.query_params.get("hours", 24))
    cutoff = timezone.now() - timedelta(hours=hours)
    qs = DlpThreat.objects.filter(detected_at__gte=cutoff)

    by_severity = list(qs.values("severity").annotate(count=Count("id")).order_by("-count"))
    by_classification = list(qs.values("classification").annotate(count=Count("id")).order_by("-count"))
    by_status = list(qs.values("status").annotate(count=Count("id")).order_by("-count"))
    by_channel = list(qs.values("channel").annotate(count=Count("id")).order_by("-count"))
    top_agents = list(qs.values("agent_id", "agent_hostname").annotate(count=Count("id")).order_by("-count")[:10])
    top_files = list(qs.values("file_name").annotate(count=Count("id")).order_by("-count")[:10])

    today = DlpThreat.objects.filter(
        detected_at__date=timezone.now().date()
    ).count()

    return Response({
        "total": DlpThreat.objects.count(),
        "today": today,
        "by_severity": {s["severity"]: s["count"] for s in by_severity},
        "by_classification": {c["classification"]: c["count"] for c in by_classification},
        "by_status": by_status,
        "by_channel": {ch["channel"]: ch["count"] for ch in by_channel},
        "top_agents": [
            {"agent_id": a["agent_id"], "hostname": a["agent_hostname"], "incidents": a["count"]}
            for a in top_agents
        ],
        "top_files": top_files,
    })


# =========================================================================
#  REST API viewsets
# =========================================================================

class DlpPolicyViewSet(viewsets.ModelViewSet):
    queryset = DlpPolicy.objects.all()
    serializer_class = DlpPolicySerializer
    lookup_field = "code"

    def get_queryset(self):
        qs = super().get_queryset()
        enabled = self.request.query_params.get("enabled")
        if enabled is not None:
            qs = qs.filter(is_active=enabled.lower() == "true")
        return qs

    @action(detail=True, methods=["get"])
    def rules(self, request, code=None):
        policy = self.get_object()
        rules = policy.rules.filter(is_active=True)
        serializer = DlpRuleSerializer(rules, many=True)
        return Response(serializer.data)


class DlpThreatViewSet(viewsets.ModelViewSet):
    http_method_names = ["get", "patch", "head", "options"]
    lookup_field = "pk"
    serializer_class = DlpThreatListSerializer

    def get_queryset(self):
        qs = DlpThreat.objects.all()
        params = self.request.query_params
        severity = params.get("severity")
        status_filter = params.get("status")
        classification = params.get("classification")
        agent_id = params.get("agent_id")
        channel = params.get("channel")
        search = params.get("q")
        hours = params.get("hours")

        if severity:
            qs = qs.filter(severity=severity)
        if status_filter:
            qs = qs.filter(status=status_filter)
        if classification:
            qs = qs.filter(classification=classification)
        if agent_id:
            qs = qs.filter(agent_id=agent_id)
        if channel:
            qs = qs.filter(channel=channel)
        if search:
            qs = qs.filter(
                Q(file_name__icontains=search)
                | Q(file_path__icontains=search)
                | Q(actor__icontains=search)
            )
        if hours:
            try:
                cutoff = timezone.now() - timedelta(hours=int(hours))
                qs = qs.filter(detected_at__gte=cutoff)
            except (ValueError, TypeError):
                pass
        return qs.order_by("-detected_at")

    def get_serializer_class(self):
        if self.action == "retrieve":
            return DlpThreatDetailSerializer
        return DlpThreatListSerializer

    @action(detail=True, methods=["patch"])
    def acknowledge(self, request, pk=None):
        incident = self.get_object()
        incident.status = "acknowledged"
        incident.acknowledged_at = timezone.now()
        incident.acknowledged_by = _get_username(request)
        incident.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
        return Response({"status": "acknowledged", "id": incident.id})

    @action(detail=True, methods=["patch"])
    def resolve(self, request, pk=None):
        incident = self.get_object()
        incident.status = request.data.get("status", "resolved")
        incident.resolved_at = timezone.now()
        incident.resolved_by = _get_username(request)
        incident.resolution_notes = request.data.get("notes", "")
        incident.save(update_fields=["status", "resolved_at", "resolved_by", "resolution_notes"])
        return Response({"status": incident.status, "id": incident.id})


class DlpScanSummaryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DlpScanSummary.objects.all()
    serializer_class = DlpScanSummarySerializer

    def get_queryset(self):
        qs = super().get_queryset()
        agent_id = self.request.query_params.get("agent_id")
        if agent_id:
            qs = qs.filter(agent_id=agent_id)
        return qs.order_by("-started_at")


# =========================================================================
#  Evidence download
# =========================================================================

@api_view(["GET"])
def evidence_download(request, pk):
    if getattr(request, "auth_type", "") != "user":
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("User authentication required")

    try:
        threat = DlpThreat.objects.get(pk=pk)
    except DlpThreat.DoesNotExist:
        raise Http404("Incident not found")

    if not threat.evidence_file:
        return Response(
            {"error": "No evidence file available for this incident"},
            status=status.HTTP_404_NOT_FOUND,
        )

    return FileResponse(
        threat.evidence_file.open("rb"),
        as_attachment=True,
        filename=threat.file_name or Path(threat.evidence_file.name).name,
    )
