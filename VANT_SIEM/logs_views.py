import json
import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, Any

import pytz
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db.models import Q, Count, Max
from django.db.models.functions import TruncHour, TruncDay
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

from .logs_models import LogEvent, LogSource

logger = logging.getLogger(__name__)


# --- Saved Visualizations / Dashboards (stored as JSON on LogSource.meta) ---

@login_required
def saved_visualizations_list(request):
    """List saved dashboards/visualizations for current user"""
    user_id = str(request.user.id)
    items = []
    for src in LogSource.objects.filter(source_type="dashboard").order_by("-registered_at"):
        meta = src.meta or {}
        if meta.get("owner_id") == user_id:
            items.append({"id": src.source_id, "name": meta.get("name", src.host_name), "config": meta.get("config", {}), "created_at": src.registered_at})
    return JsonResponse({"visualizations": items})


@csrf_exempt
@login_required
def saved_visualization_create(request):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    data = json.loads(request.body)
    src = LogSource.objects.create(
        source_id=f"dash_{request.user.id}_{timezone.now().timestamp()}",
        source_type="dashboard",
        host_name=data.get("name", "Dashboard"),
        meta={"owner_id": str(request.user.id), "config": data.get("config", {}), "name": data.get("name", "")},
    )
    return JsonResponse({"id": src.source_id, "status": "created"})


@csrf_exempt
@login_required
def saved_visualization_update(request, vis_id):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    try:
        src = LogSource.objects.get(source_id=vis_id, source_type="dashboard", meta__owner_id=str(request.user.id))
        data = json.loads(request.body)
        src.meta = {**(src.meta or {}), "config": data.get("config", src.meta.get("config", {})), "name": data.get("name", src.host_name)}
        src.save()
        return JsonResponse({"status": "updated"})
    except LogSource.DoesNotExist:
        return JsonResponse({"error": "Not found"}, status=404)


@csrf_exempt
@login_required
def saved_visualization_delete(request, vis_id):
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    try:
        src = LogSource.objects.get(source_id=vis_id, source_type="dashboard", meta__owner_id=str(request.user.id))
        src.delete()
        return JsonResponse({"status": "deleted"})
    except LogSource.DoesNotExist:
        return JsonResponse({"error": "Not found"}, status=404)


# --- Core Log Views ---

@login_required
def log_dashboard(request):
    """Main dashboard using os_events_raw"""
    now = timezone.now()
    hours_24 = now - timedelta(hours=24)
    hours_1 = now - timedelta(hours=1)

    total_events = LogEvent.objects.count()
    events_24h = LogEvent.objects.filter(event_time__gte=hours_24).count()
    events_1h = LogEvent.objects.filter(event_time__gte=hours_1).count()

    severity_counts = dict(
        LogEvent.objects.filter(event_time__gte=hours_24)
        .values_list("severity")
        .annotate(cnt=Count("id"))
        .order_by("-cnt")
    )

    source_counts = dict(
        LogEvent.objects.filter(event_time__gte=hours_24)
        .values_list("source_type")
        .annotate(cnt=Count("id"))
        .order_by("-cnt")[:10]
    )

    hourly = list(
        LogEvent.objects.filter(event_time__gte=now - timedelta(hours=48))
        .annotate(hour=TruncHour("event_time"))
        .values("hour")
        .annotate(cnt=Count("id"))
        .order_by("hour")
    )

    recent = LogEvent.objects.select_related().order_by("-event_time")[:50]

    top_hosts = dict(
        LogEvent.objects.filter(event_time__gte=hours_24, host_ip__isnull=False)
        .values_list("host_ip")
        .annotate(cnt=Count("id"))
        .order_by("-cnt")[:10]
    )

    context = {
        "total_events": total_events,
        "events_24h": events_24h,
        "events_1h": events_1h,
        "severity_counts": severity_counts,
        "source_counts": source_counts,
        "hourly": hourly,
        "recent": recent,
        "top_hosts": top_hosts,
    }
    return render(request, "logs/dashboard.html", context)


@login_required
def log_list(request):
    """Paginated list/search of all log events"""
    qs = LogEvent.objects.all()

    q = request.GET.get("q")
    if q:
        qs = qs.filter(Q(message__icontains=q) | Q(host_name__icontains=q) | Q(host_ip__icontains=q) | Q(source_name__icontains=q))

    source_type = request.GET.get("source_type")
    if source_type:
        qs = qs.filter(source_type=source_type)

    severity = request.GET.get("severity")
    if severity:
        qs = qs.filter(severity=severity)

    paginator = Paginator(qs, 50)
    page = paginator.get_page(request.GET.get("page"))

    # Distinct values for filters
    source_types = LogEvent.objects.values_list("source_type", flat=True).distinct().order_by("source_type")
    severities = LogEvent.objects.values_list("severity", flat=True).distinct().order_by("severity")

    context = {
        "logs": page,
        "source_types": source_types,
        "severities": severities,
        "active_source": source_type,
        "active_severity": severity,
        "q": q,
    }
    return render(request, "logs/list.html", context)


@login_required
def log_detail(request, event_id):
    """Single event detail view"""
    event = LogEvent.objects.filter(id=event_id).first()
    if not event:
        return redirect("log-list")
    context = {"event": event}
    return render(request, "logs/detail.html", context)


# --- APIs ---

@csrf_exempt
@login_required
def api_log_events(request):
    """JSON API for log events (datatables / charts)"""
    limit = int(request.GET.get("limit", 100))
    offset = int(request.GET.get("offset", 0))
    source_type = request.GET.get("source_type")
    severity = request.GET.get("severity")
    hours = int(request.GET.get("hours", 24))

    qs = LogEvent.objects.filter(event_time__gte=timezone.now() - timedelta(hours=hours))
    if source_type:
        qs = qs.filter(source_type=source_type)
    if severity:
        qs = qs.filter(severity=severity)

    total = qs.count()
    items = qs.order_by("-event_time")[offset: offset + limit]

    return JsonResponse({
        "total": total,
        "items": [
            {
                "id": e.id,
                "source_type": e.source_type,
                "source_name": e.source_name,
                "host_name": e.host_name,
                "host_ip": e.host_ip,
                "event_time": e.event_time.isoformat() if e.event_time else None,
                "severity": e.severity,
                "message": e.message[:200],
                "tags": e.tags,
            }
            for e in items
        ],
    })


@csrf_exempt
@login_required
def api_ingest_log(request):
    """Ingest a single log event from agent or collector"""
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    try:
        data = json.loads(request.body)
        event = LogEvent.objects.create(
            source_type=data.get("source_type", "unknown"),
            source_name=data.get("source_name", ""),
            host_name=data.get("host_name", ""),
            host_ip=data.get("host_ip"),
            severity=data.get("severity", "info"),
            event_category=data.get("event_category", ""),
            message=data.get("message", ""),
            raw_payload=data.get("raw_payload", {}),
            tags=data.get("tags", []),
        )
        return JsonResponse({"status": "ok", "id": event.id})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@login_required
def api_log_sources(request):
    """List registered log sources"""
    sources = LogSource.objects.all().order_by("-last_seen_at")
    return JsonResponse({
        "sources": [
            {
                "source_id": s.source_id,
                "source_type": s.source_type,
                "host_name": s.host_name,
                "enabled": s.enabled,
                "last_seen": s.last_seen_at.isoformat() if s.last_seen_at else None,
            }
            for s in sources
        ]
    })


@login_required
def log_sources_view(request):
    """UI for managing log sources"""
    sources = LogSource.objects.all().order_by("-last_seen_at")
    context = {"sources": sources}
    return render(request, "logs/sources.html", context)


@login_required
def log_statistics(request):
    """Statistics endpoint for charts"""
    hours = int(request.GET.get("hours", 24))
    cutoff = timezone.now() - timedelta(hours=hours)

    severity_timeline = list(
        LogEvent.objects.filter(event_time__gte=cutoff)
        .annotate(day=TruncDay("event_time"))
        .values("day", "severity")
        .annotate(cnt=Count("id"))
        .order_by("day")
    )

    top_ips = dict(
        LogEvent.objects.filter(event_time__gte=cutoff, host_ip__isnull=False)
        .values_list("host_ip")
        .annotate(cnt=Count("id"))
        .order_by("-cnt")[:20]
    )

    return JsonResponse({
        "severity_timeline": severity_timeline,
        "top_ips": top_ips,
        "period_hours": hours,
    })


# Legacy redirects for old URLs that may still exist in templates
@login_required
def legacy_dashboard_redirect(request):
    return redirect("log-dashboard")


@login_required
def legacy_snort_redirect(request):
    return redirect("log-list")


@login_required
def legacy_suricata_redirect(request):
    return redirect("log-list")
