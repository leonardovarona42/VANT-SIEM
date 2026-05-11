import base64
import logging
from datetime import timedelta
from pathlib import Path

from django.db.models import Count, Q
from django.utils import timezone
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.core.files.base import ContentFile
from django.conf import settings
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.response import Response

from .models import DlpPolicy, DlpRule, DlpThreat, DlpScanSummary
from .serializers import (
    DlpPolicySerializer, DlpRuleSerializer,
    DlpThreatListSerializer, DlpThreatDetailSerializer,
    DlpThreatIngestSerializer, DlpScanSummarySerializer,
    DlpAgentConfigSerializer, DlpThreatIngestMultipartSerializer,
)
from .forms import DlpPolicyForm, DlpRuleForm

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
#  Agent-facing endpoints (AllowAny)
# =========================================================================

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def agent_dlp_config(request):
    policies = DlpPolicy.objects.filter(is_active=True).prefetch_related("rules")
    serializer = DlpAgentConfigSerializer({"policies": policies, "fetched_at": timezone.now()})
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def ingest_dlp_threats(request):
    serializer = DlpThreatIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    agent_id = data.get("agent_id", "")
    incidents_data = data["incidents"]

    if not incidents_data:
        return Response({"status": "ok", "ingested": 0})

    created_count = 0
    skipped_count = 0

    for inc_data in incidents_data:
        fingerprint = inc_data.get("fingerprint", "")
        if not fingerprint:
            skipped_count += 1
            continue

        try:
            detected_at_str = inc_data.get("detected_at", "")
            if detected_at_str:
                detected_at = timezone.datetime.fromisoformat(
                    detected_at_str.replace("Z", "+00:00")
                )
                if not timezone.is_aware(detected_at):
                    detected_at = timezone.make_aware(detected_at)
            else:
                detected_at = timezone.now()
        except (ValueError, TypeError):
            detected_at = timezone.now()

        metadata = inc_data.get("metadata", {})
        file_content_b64 = inc_data.get("file_content_base64", "")
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
            if file_content_b64 and not incident.evidence_file:
                try:
                    raw = base64.b64decode(file_content_b64)
                    if len(raw) > MAX_EVIDENCE_SIZE:
                        logger.warning("aegis.evidence.too_large fingerprint=%s size=%s", fingerprint, len(raw))
                        continue
                    mime_guess = inc_data.get("file_name", "").lower()
                    if mime_guess.endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.com', '.php', '.jsp', '.war')):
                        logger.warning("aegis.evidence.blocked_ext fingerprint=%s name=%s", fingerprint, mime_guess)
                        continue
                    safe_ext = Path(inc_data.get("file_name", "file")).suffix or ".bin"
                    safe_ext = ''.join(c for c in safe_ext if c.isalnum() or c in '.-')
                    if len(safe_ext) > 10:
                        safe_ext = '.bin'
                    filename = f"{fingerprint[:16]}{safe_ext}"
                    incident.evidence_file.save(filename, ContentFile(raw), save=True)
                except Exception as e:
                    logger.warning("aegis.evidence.save.failed fingerprint=%s error=%s", fingerprint, e)
            try:
                _publish_dlp_event(incident)
                DlpThreat.objects.filter(fingerprint=fingerprint).update(event_published=True)
            except Exception as e:
                logger.error("aegis.event.publish.failed fingerprint=%s error=%s", fingerprint, e)

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


ALLOWED_MIME_PREFIXES = ('text/', 'application/pdf', 'application/msword',
    'application/vnd.openxmlformats-officedocument',
    'application/vnd.ms-', 'image/', 'message/rfc822')
MAX_EVIDENCE_SIZE = 25 * 1024 * 1024

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def ingest_dlp_threats_multipart(request):
    serializer = DlpThreatIngestMultipartSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    meta = serializer.validated_data["metadata"]
    agent_id = meta.get("agent_id", "")
    incidents_data = meta["incidents"]
    uploaded_files = {}

    for key in request.FILES:
        if key.startswith("file_"):
            fingerprint = key[5:]
            uploaded_files[fingerprint] = request.FILES[key]

    if not incidents_data:
        return Response({"status": "ok", "ingested": 0})

    created_count = 0
    skipped_count = 0

    for inc_data in incidents_data:
        fingerprint = inc_data.get("fingerprint", "")
        if not fingerprint:
            skipped_count += 1
            continue

        try:
            detected_at_str = inc_data.get("detected_at", "")
            if detected_at_str:
                detected_at = timezone.datetime.fromisoformat(
                    detected_at_str.replace("Z", "+00:00")
                )
                if not timezone.is_aware(detected_at):
                    detected_at = timezone.make_aware(detected_at)
            else:
                detected_at = timezone.now()
        except (ValueError, TypeError):
            detected_at = timezone.now()

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
            if fingerprint in uploaded_files and not incident.evidence_file:
                try:
                    uf = uploaded_files[fingerprint]
                    if uf.size > MAX_EVIDENCE_SIZE:
                        logger.warning("aegis.evidence.too_large fingerprint=%s size=%s", fingerprint, uf.size)
                        continue
                    mime = uf.content_type or ''
                    if not any(mime.startswith(p) for p in ALLOWED_MIME_PREFIXES):
                        logger.warning("aegis.evidence.invalid_mime fingerprint=%s mime=%s", fingerprint, mime)
                        continue
                    safe_ext = Path(inc_data.get("file_name", "file")).suffix or ".bin"
                    safe_ext = ''.join(c for c in safe_ext if c.isalnum() or c in '.-')
                    if len(safe_ext) > 10:
                        safe_ext = '.bin'
                    filename = f"{fingerprint[:16]}{safe_ext}"
                    incident.evidence_file.save(filename, uf, save=True)
                except Exception as e:
                    logger.warning("aegis.evidence.save.failed fingerprint=%s error=%s", fingerprint, e)
            try:
                _publish_dlp_event(incident)
                DlpThreat.objects.filter(fingerprint=fingerprint).update(event_published=True)
            except Exception as e:
                logger.error("aegis.event.publish.failed fingerprint=%s error=%s", fingerprint, e)

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


def _publish_dlp_event(incident):
    try:
        from CORE.arkangel import ServiceBus, ASSET_DLP_INCIDENT

        bus = ServiceBus.get_instance()
        bus.publish(
            channel="asset.dlp",
            event_type=ASSET_DLP_INCIDENT,
            payload={
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
            },
        )
    except Exception as e:
        logger.warning("aegis.service_bus.unavailable error=%s", e)
        raise


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


class DlpRuleViewSet(viewsets.ModelViewSet):
    queryset = DlpRule.objects.all()
    serializer_class = DlpRuleSerializer
    permission_classes = [IsAdminUser]


class DlpThreatViewSet(viewsets.ModelViewSet):
    http_method_names = ["get", "patch", "head", "options"]
    lookup_field = "pk"
    permission_classes = [IsAuthenticated]

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
        incident.acknowledged_by = request.user.username if request.user.is_authenticated else "api"
        incident.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
        return Response({"status": "acknowledged", "id": incident.id})

    @action(detail=True, methods=["patch"])
    def resolve(self, request, pk=None):
        incident = self.get_object()
        incident.status = request.data.get("status", "resolved")
        incident.resolved_at = timezone.now()
        incident.resolved_by = request.user.username if request.user.is_authenticated else "api"
        incident.resolution_notes = request.data.get("notes", "")
        incident.save(update_fields=["status", "resolved_at", "resolved_by", "resolution_notes"])
        return Response({"status": incident.status, "id": incident.id})


class DlpScanSummaryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DlpScanSummary.objects.all()
    serializer_class = DlpScanSummarySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        agent_id = self.request.query_params.get("agent_id")
        if agent_id:
            qs = qs.filter(agent_id=agent_id)
        return qs.order_by("-started_at")


# =========================================================================
#  Statistics
# =========================================================================

@api_view(["GET"])
@permission_classes([IsAdminUser])
def dlp_statistics(request):
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
        "top_agents": [{"agent_id": a["agent_id"], "hostname": a["agent_hostname"], "incidents": a["count"]} for a in top_agents],
        "top_files": top_files,
    })


# =========================================================================
#  UI Views (login_required)
# =========================================================================

@login_required
def dlp_dashboard(request):
    now = timezone.now()
    hours_24 = now - timedelta(hours=24)
    hours_7 = now - timedelta(hours=168)
    hours_30 = now - timedelta(hours=720)

    total_incidents = DlpThreat.objects.count()
    open_incidents = DlpThreat.objects.filter(status="open").count()
    incidents_24h = DlpThreat.objects.filter(detected_at__gte=hours_24).count()
    incidents_7d = DlpThreat.objects.filter(detected_at__gte=hours_7).count()
    incidents_30d = DlpThreat.objects.filter(detected_at__gte=hours_30).count()
    critical_open = DlpThreat.objects.filter(severity="critical", status="open").count()
    high_open = DlpThreat.objects.filter(severity="high", status="open").count()

    severity_dist = list(
        DlpThreat.objects.filter(detected_at__gte=hours_24)
        .values("severity").annotate(count=Count("id")).order_by("-count")
    )
    classification_dist = list(
        DlpThreat.objects.filter(detected_at__gte=hours_24)
        .values("classification").annotate(count=Count("id")).order_by("-count")
    )
    channel_dist = list(
        DlpThreat.objects.filter(detected_at__gte=hours_24)
        .values("channel").annotate(count=Count("id")).order_by("-count")
    )
    top_agents = list(
        DlpThreat.objects.filter(detected_at__gte=hours_24)
        .values("agent_id", "agent_hostname").annotate(count=Count("id")).order_by("-count")[:8]
    )
    recent_incidents = DlpThreat.objects.order_by("-detected_at")[:15]
    total_policies = DlpPolicy.objects.count()
    active_policies = DlpPolicy.objects.filter(is_active=True).count()
    total_rules = DlpRule.objects.count()

    context = {
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "incidents_24h": incidents_24h,
        "incidents_7d": incidents_7d,
        "incidents_30d": incidents_30d,
        "critical_open": critical_open,
        "high_open": high_open,
        "severity_dist": severity_dist,
        "classification_dist": classification_dist,
        "channel_dist": channel_dist,
        "top_agents": top_agents,
        "recent_incidents": recent_incidents,
        "total_policies": total_policies,
        "active_policies": active_policies,
        "total_rules": total_rules,
    }
    return render(request, "aegis/dashboard.html", context)


@login_required
def incidents_list(request):
    qs = DlpThreat.objects.all()
    severity = request.GET.get("severity")
    status_filter = request.GET.get("status")
    classification = request.GET.get("classification")
    channel = request.GET.get("channel")
    search = request.GET.get("q")

    if severity:
        qs = qs.filter(severity=severity)
    if status_filter:
        qs = qs.filter(status=status_filter)
    if classification:
        qs = qs.filter(classification=classification)
    if channel:
        qs = qs.filter(channel=channel)
    if search:
        qs = qs.filter(Q(file_name__icontains=search) | Q(file_path__icontains=search) | Q(actor__icontains=search))

    qs = qs.order_by("-detected_at")
    paginator = Paginator(qs, 50)
    page_num = request.GET.get("page", 1)
    page = paginator.get_page(page_num)

    return render(request, "aegis/incidents_list.html", {
        "incidents": page,
        "severity": severity,
        "status_filter": status_filter,
        "classification": classification,
        "channel": channel,
        "search": search,
    })


@login_required
def incident_detail(request, pk):
    incident = get_object_or_404(DlpThreat, pk=pk)
    return render(request, "aegis/incident_detail.html", {"incident": incident})


@login_required
def incident_acknowledge(request, pk):
    incident = get_object_or_404(DlpThreat, pk=pk)
    incident.status = "acknowledged"
    incident.acknowledged_at = timezone.now()
    incident.acknowledged_by = request.user.username
    incident.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
    messages.success(request, f"Incident {incident.file_name} acknowledged")
    return redirect("aegis-incident-detail", pk=incident.pk)


@login_required
def incident_resolve(request, pk):
    incident = get_object_or_404(DlpThreat, pk=pk)
    status_val = request.POST.get("status", "resolved")
    notes = request.POST.get("notes", "")
    incident.status = status_val
    incident.resolved_at = timezone.now()
    incident.resolved_by = request.user.username
    incident.resolution_notes = notes
    incident.save(update_fields=["status", "resolved_at", "resolved_by", "resolution_notes"])
    messages.success(request, f"Incident {incident.file_name} resolved")
    return redirect("aegis-incident-detail", pk=incident.pk)


@login_required
def policies_list(request):
    policies = DlpPolicy.objects.prefetch_related("rules").order_by("-created_at")
    return render(request, "aegis/policies_list.html", {"policies": policies})


@login_required
def policy_create(request):
    if request.method == "POST":
        form = DlpPolicyForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Policy created successfully")
            return redirect("aegis-policies")
    else:
        form = DlpPolicyForm()
    return render(request, "aegis/policy_form.html", {"form": form, "title": "Create Policy"})


@login_required
def policy_edit(request, code):
    policy = get_object_or_404(DlpPolicy, code=code)
    if request.method == "POST":
        form = DlpPolicyForm(request.POST, instance=policy)
        if form.is_valid():
            form.save()
            messages.success(request, "Policy updated successfully")
            return redirect("aegis-policies")
    else:
        form = DlpPolicyForm(instance=policy)
    return render(request, "aegis/policy_form.html", {"form": form, "title": f"Edit: {policy.name}"})


@login_required
def policy_delete(request, code):
    policy = get_object_or_404(DlpPolicy, code=code)
    if request.method == "POST":
        policy.delete()
        messages.success(request, f"Policy {code} deleted")
        return redirect("aegis-policies")
    return render(request, "aegis/policy_confirm_delete.html", {"policy": policy})


@login_required
def policy_rules(request, code):
    policy = get_object_or_404(DlpPolicy, code=code)
    if request.method == "POST":
        form = DlpRuleForm(request.POST)
        if form.is_valid():
            rule = form.save(commit=False)
            rule.policy = policy
            rule.save()
            messages.success(request, "Rule added successfully")
            return redirect("aegis-policy-rules", code=code)
    else:
        form = DlpRuleForm(initial={"policy": policy})
    rules = policy.rules.all().order_by("-created_at")
    return render(request, "aegis/policy_rules.html", {"policy": policy, "rules": rules, "form": form})


@login_required
def rule_delete(request, rule_id):
    rule = get_object_or_404(DlpRule, pk=rule_id)
    policy_code = rule.policy.code
    if request.method == "POST":
        rule.delete()
        messages.success(request, "Rule deleted")
    return redirect("aegis-policy-rules", code=policy_code)


@login_required
def scan_summaries(request):
    summaries = DlpScanSummary.objects.order_by("-started_at")[:100]
    return render(request, "aegis/scan_summaries.html", {"summaries": summaries})


@login_required
def evidence_download(request, pk):
    threat = get_object_or_404(DlpThreat, pk=pk)
    if not threat.evidence_file:
        messages.warning(request, "No hay archivo de evidencia disponible para esta amenaza.")
        return redirect("aegis-incident-detail", pk=pk)
    url = threat.evidence_file.url
    if url.startswith(('http://', 'https://')):
        messages.error(request, "URL de evidencia inválida.")
        return redirect("aegis-incident-detail", pk=pk)
    return redirect(url)
