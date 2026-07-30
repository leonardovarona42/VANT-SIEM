"""
VANT-SIEM Bus API Views.
Events, Groups, Subscriptions, Notifications, Email Config, Orchestration.
"""
import json
import logging
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests as http_requests
from django.db.models import Q
from django.http import JsonResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from bus_app.alert_dispatch import dispatch_alert
from bus_app.event_bus import STREAMS, get_event_bus
from bus_app.models import (
    AlertChannel,
    AlertHistory,
    EmailConfig,
    GroupAlertSubscription,
    GroupMember,
    NotificationGroup,
    NotificationLog,
    ServiceConfig,
    ServiceHealthLog,
    SystemEvent,
)
from bus_app.serializers import (
    AlertChannelSerializer,
    AlertHistorySerializer,
    CreateEventSerializer,
    EmailConfigSerializer,
    GroupAlertSubscriptionSerializer,
    GroupMemberSerializer,
    NotificationGroupSerializer,
    NotificationLogSerializer,
    ServiceConfigSerializer,
    ServiceHealthLogSerializer,
    SystemEventSerializer,
)
from vant_common.auth import verify_service_secret

logger = logging.getLogger("bus_app.views")


def _require_service_auth(request):
    return verify_service_secret(request)



def _dispatch_notifications(event):
    subs = GroupAlertSubscription.objects.filter(
        event_type=event.event_type,
        is_active=True,
    ).select_related("group")

    for sub in subs:
        if not sub.group.is_active:
            continue

        members = GroupMember.objects.filter(group=sub.group)
        for member in members:
            NotificationLog.objects.create(
                event=event,
                group=sub.group,
                channel=sub.channel,
                recipient_user_id=member.user_id,
                recipient_email=member.email or "",
                status="pending",
            )

    pending = NotificationLog.objects.filter(status="pending", event=event)
    email_cfg = EmailConfig.objects.filter(is_active=True).first()

    if email_cfg and pending.filter(channel="email").exists():
        _send_email_notifications(pending.filter(channel="email"), event, email_cfg)


def _send_email_notifications(logs, event, email_cfg):
    for log in logs:
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[VANT-SIEM] {event.get_event_type_display()}"
            msg["From"] = email_cfg.from_address
            msg["To"] = log.recipient_email or "admin@vant.local"

            payload = event.payload or {}
            actor = payload.get("creado_por") or event.actor_username or "Sistema"

            if event.event_type in ("servicio_fallo", "servicio_recuperado"):
                hostname = payload.get("hostname", "Desconocido")
                ip = payload.get("ip_address", "-")
                svc_name = payload.get("display_name") or payload.get("service_name", "?")
                old_state = payload.get("old_state", "?")
                new_state = payload.get("new_state", "?")
                body = (
                    f"Evento: {event.get_event_type_display()}\n"
                    f"Severidad: {event.get_severity_display()}\n\n"
                    f"Agente: {hostname} ({ip})\n"
                    f"Servicio: {svc_name}\n"
                    f"Estado anterior: {old_state}\n"
                    f"Estado actual: {new_state}\n\n"
                    f"Este evento fue generado por el monitoreo automático de servicios.\n"
                )
            elif event.event_type == "paquete_actualizacion":
                hostname = payload.get("hostname", "Desconocido")
                ip = payload.get("ip_address", "-")
                packages = payload.get("packages", [])
                pkg_text = ""
                if packages:
                    pkg_text = "\nPaquetes con actualizaciones disponibles:\n"
                    for p in packages[:20]:
                        pkg_text += f"  - {p.get('package', '?')} ({p.get('current', '?')} -> {p.get('available', '?')})\n"
                    if len(packages) > 20:
                        pkg_text += f"  ... y {len(packages) - 20} más\n"
                body = (
                    f"Evento: Actualizaciones Disponibles\n"
                    f"Severidad: {event.get_severity_display()}\n\n"
                    f"Agente: {hostname} ({ip})\n"
                    f"Total: {len(packages)} paquete(s)\n"
                    f"{pkg_text}"
                )
            elif event.event_type == "amenaza_dlp":
                hostname = payload.get("hostname", "Desconocido")
                classification = payload.get("classification", "N/A")
                severity = payload.get("severity", "high")
                rule_name = payload.get("rule_name") or payload.get("policy_code", "N/A")
                channel = payload.get("channel", "filesystem")
                file_name = payload.get("file_name", "N/A")
                file_path = payload.get("file_path", "")
                actor = payload.get("actor", "N/A")
                summary = payload.get("summary", "Sin detalles")
                detected_at = payload.get("detected_at", "")
                reporte_id = payload.get("reporte_id", "")
                keywords = payload.get("matched_keywords", [])
                kw_text = ""
                if keywords:
                    kw_text = f"\nPalabras clave: {', '.join(str(k) for k in keywords[:10])}"
                reporte_text = ""
                if reporte_id:
                    reporte_text = f"\nReporte SOC automatico: #{reporte_id}"
                body = (
                    f"Evento: Amenaza DLP Detectada\n"
                    f"Severidad: {severity.upper()}\n\n"
                    f"Agente: {hostname}\n"
                    f"Clasificacion: {classification}\n"
                    f"Regla: {rule_name}\n"
                    f"Canal: {channel}\n"
                    f"Actor: {actor}\n"
                    f"Fecha: {detected_at}\n\n"
                    f"Archivo: {file_name}\n"
                    f"Ruta: {file_path}\n"
                    f"Resumen: {summary}"
                    f"{kw_text}"
                    f"{reporte_text}"
                )
            else:
                reportes = payload.get("reportes", [])
                reportes_text = ""
                if reportes:
                    reportes_text = "\nReportes asociados:\n"
                    for r in reportes:
                        reportes_text += f"  - Reporte #{r.get('id', '?')} - {r.get('nombre', 'Sin nombre')} [{r.get('estado', '?')}]\n"
                body = (
                    f"Evento: {event.get_event_type_display()}\n"
                    f"Severidad: {event.get_severity_display()}\n"
                    f"Fuente: {event.source_service}\n"
                    f"Creado por: {actor}\n"
                    f"Codigo: {payload.get('codigo', 'N/A')}\n"
                    f"Incidente: {payload.get('nombre', 'N/A')}\n"
                    f"Estado: {payload.get('estado', 'N/A')}\n"
                    f"Descripcion: {payload.get('descripcion', 'N/A')}\n"
                    f"{reportes_text}"
                )
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(email_cfg.smtp_host, email_cfg.smtp_port, timeout=15)
            try:
                if email_cfg.use_tls:
                    server.starttls()
                if email_cfg.smtp_user and email_cfg.smtp_password:
                    server.login(email_cfg.smtp_user, email_cfg.smtp_password)
                server.sendmail(email_cfg.from_address, [log.recipient_email or "admin@vant.local"], msg.as_string())
            finally:
                server.quit()

            log.status = "sent"
            log.sent_at = timezone.now()
            log.save(update_fields=["status", "sent_at"])
        except Exception as e:
            logger.error("email send failed for log %s: %s", log.id, e)
            log.status = "failed"
            log.error_message = str(e)
            log.save(update_fields=["status", "error_message"])


# ============================================================================
#  EVENTS
# ============================================================================

@api_view(["POST"])
def event_receive(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    serializer = CreateEventSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    event = SystemEvent.objects.create(**data)

    bus = get_event_bus()
    bus.publish_event(
        "events",
        event.event_type,
        {
            "event_id": event.id,
            "entity_type": event.entity_type,
            "entity_id": event.entity_id,
            "actor_username": event.actor_username,
            "payload": event.payload,
            "severity": event.severity,
        },
    )

    _dispatch_notifications(event)

    return Response(SystemEventSerializer(event).data, status=status.HTTP_201_CREATED)


@api_view(["GET"])
def event_list(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    qs = SystemEvent.objects.all()

    event_type = request.query_params.get("event_type")
    if event_type:
        qs = qs.filter(event_type=event_type)

    entity_type = request.query_params.get("entity_type")
    if entity_type:
        qs = qs.filter(entity_type=entity_type)

    severity = request.query_params.get("severity")
    if severity:
        qs = qs.filter(severity=severity)

    source = request.query_params.get("source")
    if source:
        qs = qs.filter(source_service=source)

    search = request.query_params.get("q")
    if search:
        qs = qs.filter(
            Q(actor_username__icontains=search)
            | Q(entity_id__icontains=search)
            | Q(payload__icontains=search)
        )

    hostname = request.query_params.get("hostname")
    if hostname:
        qs = qs.filter(payload__hostname__icontains=hostname)

    service_name = request.query_params.get("service_name")
    if service_name:
        qs = qs.filter(
            Q(payload__service_name__icontains=service_name)
            | Q(payload__display_name__icontains=service_name)
        )

    page = int(request.query_params.get("page", 1))
    page_size = min(int(request.query_params.get("page_size", 50)), 200)
    total = qs.count()
    start = (page - 1) * page_size
    events = qs[start : start + page_size]

    return Response({
        "count": total,
        "page": page,
        "page_size": page_size,
        "results": SystemEventSerializer(events, many=True).data,
    })


@api_view(["GET"])
def event_detail(request, event_id):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        event = SystemEvent.objects.get(id=event_id)
    except SystemEvent.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)
    return Response(SystemEventSerializer(event).data)


# ============================================================================
#  GROUPS
# ============================================================================

@api_view(["GET", "POST"])
def group_list_create(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":
        groups = NotificationGroup.objects.all()
        return Response(NotificationGroupSerializer(groups, many=True).data)

    serializer = NotificationGroupSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    group = serializer.save()
    return Response(NotificationGroupSerializer(group).data, status=status.HTTP_201_CREATED)


@api_view(["GET", "PUT", "DELETE"])
def group_detail(request, group_id):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        group = NotificationGroup.objects.get(id=group_id)
    except NotificationGroup.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        return Response(NotificationGroupSerializer(group).data)

    if request.method == "PUT":
        serializer = NotificationGroupSerializer(group, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        group = serializer.save()
        return Response(NotificationGroupSerializer(group).data)

    group.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["GET", "POST", "DELETE"])
def group_members(request, group_id):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        group = NotificationGroup.objects.get(id=group_id)
    except NotificationGroup.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        members = GroupMember.objects.filter(group=group)
        return Response(GroupMemberSerializer(members, many=True).data)

    if request.method == "POST":
        serializer = GroupMemberSerializer(data={**request.data, "group": group.id})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        member = serializer.save()
        return Response(GroupMemberSerializer(member).data, status=status.HTTP_201_CREATED)

    user_id = request.query_params.get("user_id") or request.data.get("user_id")
    if not user_id:
        return Response({"error": "user_id required"}, status=status.HTTP_400_BAD_REQUEST)
    deleted, _ = GroupMember.objects.filter(group=group, user_id=user_id).delete()
    if deleted:
        return Response(status=status.HTTP_204_NO_CONTENT)
    return Response({"error": "member not found"}, status=status.HTTP_404_NOT_FOUND)


# ============================================================================
#  SUBSCRIPTIONS
# ============================================================================

@api_view(["GET", "POST"])
def subscription_list_create(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":
        group_id = request.query_params.get("group")
        qs = GroupAlertSubscription.objects.select_related("group").all()
        if group_id:
            qs = qs.filter(group_id=group_id)
        return Response(GroupAlertSubscriptionSerializer(qs, many=True).data)

    serializer = GroupAlertSubscriptionSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    sub = serializer.save()
    return Response(GroupAlertSubscriptionSerializer(sub).data, status=status.HTTP_201_CREATED)


@api_view(["DELETE"])
def subscription_delete(request, sub_id):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    deleted, _ = GroupAlertSubscription.objects.filter(id=sub_id).delete()
    if deleted:
        return Response(status=status.HTTP_204_NO_CONTENT)
    return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)


# ============================================================================
#  NOTIFICATIONS
# ============================================================================

@api_view(["GET"])
def notification_list(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    qs = NotificationLog.objects.select_related("event", "group").all()

    user_id = request.query_params.get("user_id")
    if user_id:
        qs = qs.filter(recipient_user_id=user_id)

    group_id = request.query_params.get("group_id")
    if group_id:
        qs = qs.filter(group_id=group_id)

    unread = request.query_params.get("unread")
    if unread == "1":
        qs = qs.filter(status__in=["pending", "sent"])

    page = int(request.query_params.get("page", 1))
    page_size = min(int(request.query_params.get("page_size", 50)), 200)
    total = qs.count()
    start = (page - 1) * page_size
    logs = qs[start : start + page_size]

    return Response({
        "count": total,
        "results": NotificationLogSerializer(logs, many=True).data,
    })


@api_view(["PUT"])
def notification_mark_read(request, notif_id):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        log = NotificationLog.objects.get(id=notif_id)
    except NotificationLog.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)
    log.status = "read"
    log.read_at = timezone.now()
    log.save(update_fields=["status", "read_at"])
    return Response({"status": "read"})


@api_view(["PUT"])
def notification_mark_all_read(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    user_id = request.query_params.get("user_id")
    if not user_id:
        return Response({"error": "user_id required"}, status=status.HTTP_400_BAD_REQUEST)

    now = timezone.now()
    updated = NotificationLog.objects.filter(
        recipient_user_id=user_id,
        status__in=["pending", "sent"],
    ).update(status="read", read_at=now)

    return Response({"marked_read": updated})


# ============================================================================
#  EMAIL CONFIG
# ============================================================================

@api_view(["GET", "PUT"])
def email_config(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    cfg, _ = EmailConfig.objects.get_or_create(id=1)

    if request.method == "GET":
        return Response(EmailConfigSerializer(cfg).data)

    serializer = EmailConfigSerializer(cfg, data=request.data, partial=True)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    cfg = serializer.save()
    return Response(EmailConfigSerializer(cfg).data)


@api_view(["POST"])
def email_config_test(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    cfg, _ = EmailConfig.objects.get_or_create(id=1)
    to_email = request.data.get("to_email", cfg.from_address)

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = "[VANT-SIEM] Test Email"
        msg["From"] = cfg.from_address
        msg["To"] = to_email
        msg.attach(MIMEText("This is a test email from VANT-SIEM Bus.", "plain"))

        server = smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=15)
        try:
            if cfg.use_tls:
                server.starttls()
            if cfg.smtp_user and cfg.smtp_password:
                server.login(cfg.smtp_user, cfg.smtp_password)
            server.sendmail(cfg.from_address, [to_email], msg.as_string())
        finally:
            server.quit()

        return Response({"status": "sent", "to": to_email})
    except Exception as e:
        return Response({"status": "failed", "error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# ============================================================================
#  ORCHESTRATION — SERVICES
# ============================================================================

@api_view(["GET", "POST"])
def service_list_create(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    if request.method == "GET":
        services = ServiceConfig.objects.all()
        return Response(ServiceConfigSerializer(services, many=True).data)

    serializer = ServiceConfigSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    svc = serializer.save()
    return Response(ServiceConfigSerializer(svc).data, status=status.HTTP_201_CREATED)


@api_view(["GET", "PUT", "DELETE"])
def service_detail(request, svc_id):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        svc = ServiceConfig.objects.get(id=svc_id)
    except ServiceConfig.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == "GET":
        return Response(ServiceConfigSerializer(svc).data)

    if request.method == "PUT":
        serializer = ServiceConfigSerializer(svc, data=request.data, partial=True)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        svc = serializer.save()
        return Response(ServiceConfigSerializer(svc).data)

    svc.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["GET"])
def service_health_history(request, svc_id):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    try:
        svc = ServiceConfig.objects.get(id=svc_id)
    except ServiceConfig.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)

    limit = min(int(request.query_params.get("limit", 50)), 200)
    logs = ServiceHealthLog.objects.filter(service=svc)[:limit]
    return Response(ServiceHealthLogSerializer(logs, many=True).data)


def _systemctl_action(svc, action):
    import subprocess
    cmd = f"echo 1qazxsw2 | sudo -S systemctl {action} {svc.systemd_service}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


@api_view(["POST"])
def service_action(request, svc_id, action):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    if action not in ("restart", "stop", "start"):
        return Response({"error": "invalid action"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        svc = ServiceConfig.objects.get(id=svc_id)
    except ServiceConfig.DoesNotExist:
        return Response({"error": "not found"}, status=status.HTTP_404_NOT_FOUND)

    ok, output = _systemctl_action(svc, action)

    event_type = f"servicio_{action}"
    event = SystemEvent.objects.create(
        event_type=event_type,
        source_service="bus",
        entity_type="servicio",
        entity_id=str(svc.id),
        payload={"service": svc.name, "systemd_service": svc.systemd_service, "action": action, "success": ok, "output": output[:500]},
        severity="info" if ok else "high",
    )

    bus = get_event_bus()
    bus.publish_event("events", event.event_type, {"event_id": event.id, "service": svc.name, "action": action, "success": ok})

    _dispatch_notifications(event)

    svc.last_health_check = None
    svc.last_health_status = "unknown"
    svc.save(update_fields=["last_health_check", "last_health_status"])

    return Response({"status": "ok" if ok else "error", "action": action, "service": svc.name, "output": output[:500]})


# ============================================================================
#  LEGACY ALERTS (backward compat)
# ============================================================================

@api_view(["POST"])
def send_alert(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    severity = request.data.get("severity", "info")
    title = request.data.get("title", "")
    message = request.data.get("message", "")
    source = request.data.get("source", "")
    metadata = request.data.get("metadata", {})

    bus = get_event_bus()
    bus.publish_alert(severity, title, message, source, metadata)
    dispatched = dispatch_alert(severity, title, message, source, metadata)

    return Response({"status": "ok", "severity": severity, "dispatched_to": dispatched})


@api_view(["GET"])
def alert_history(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    limit = min(int(request.query_params.get("limit", 50)), 500)
    qs = AlertHistory.objects.all()
    severity = request.query_params.get("severity")
    if severity:
        qs = qs.filter(severity=severity)
    return Response(AlertHistorySerializer(qs[:limit], many=True).data)


@api_view(["GET", "POST"])
def alert_config(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    if request.method == "GET":
        return Response(AlertChannelSerializer(AlertChannel.objects.all(), many=True).data)
    serializer = AlertChannelSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    ch = serializer.save()
    return Response(AlertChannelSerializer(ch).data)


@api_view(["GET"])
def recent_events(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    count = min(int(request.query_params.get("count", 50)), 500)
    stream_key = request.query_params.get("stream", "events")
    bus = get_event_bus()
    events = bus.get_recent_events(stream_key, count=count)
    return Response({"stream": stream_key, "events": events, "count": len(events)})


@api_view(["GET"])
def stream_events(request, stream):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    if stream not in STREAMS:
        return Response({"error": f"unknown stream: {stream}"}, status=status.HTTP_400_BAD_REQUEST)
    count = min(int(request.query_params.get("count", 100)), 1000)
    bus = get_event_bus()
    events = bus.get_recent_events(stream, count=count)
    return Response({"stream": stream, "events": events, "count": len(events)})


@api_view(["GET"])
def bus_stats(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)
    bus = get_event_bus()
    return Response({
        "streams": bus.get_all_stream_counts(),
        "total_events": SystemEvent.objects.count(),
        "total_notifications": NotificationLog.objects.count(),
        "unread_notifications": NotificationLog.objects.filter(status__in=["pending", "sent"]).count(),
        "groups": NotificationGroup.objects.filter(is_active=True).count(),
        "services_healthy": ServiceConfig.objects.filter(last_health_status="healthy").count(),
        "services_down": ServiceConfig.objects.filter(last_health_status="down").count(),
        "services_total": ServiceConfig.objects.filter(is_active=True).count(),
    })


@api_view(["GET"])
def dashboard_summary(request):
    if not _require_service_auth(request):
        return Response({"error": "unauthorized"}, status=status.HTTP_401_UNAUTHORIZED)

    recent = SystemEvent.objects.all()[:20]
    services = ServiceConfig.objects.filter(is_active=True)
    unread = NotificationLog.objects.filter(status__in=["pending", "sent"]).count()

    return Response({
        "recent_events": SystemEventSerializer(recent, many=True).data,
        "services": ServiceConfigSerializer(services, many=True).data,
        "unread_notifications": unread,
    })


@api_view(["GET"])
def health(request):
    bus = get_event_bus()
    bus_health = bus.health_check()
    return Response({"status": "ok", "service": "vant-bus", **bus_health})
