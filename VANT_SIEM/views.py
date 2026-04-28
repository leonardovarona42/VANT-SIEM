from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.utils.decorators import method_decorator
from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.urls import reverse_lazy
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.utils import timezone
from django.core.files.base import ContentFile
from .models import Notification, UserPermission, UserApprovalRequest, NotificationPreference, EmailConfiguration, EmailAlert, EmailLog, AnalysisAPIConfig, NotificationSettings, NotificationChannel, NotificationTemplate, NotificationLog, NotificationQueue, OllamaConfig, LDAPConfig, NetworkSite, NetworkVLAN, NetworkSubnet, NetworkIPAddress, NetworkChangeEvent
from .logging_system import event_logger
from .email_service import send_user_alert, send_system_alert
from .enhanced_notification_service import enhanced_notification_service
import json
import requests
from django.core.paginator import Paginator
from django.db.models import Count
from datetime import timedelta
from django.core import signing
from django.conf import settings
import socket
import subprocess
import ipaddress
import shutil
import os
import ssl
import hmac
import hashlib
import time
from pathlib import Path
# Optional LDAP support (activated via LDAPConfig)
try:
    from ldap3 import Server, Connection, ALL, Tls, SUBTREE
except Exception:
    Server = Connection = Tls = SUBTREE = None
# IDS features removed per user request


def _split_newline_csv(value):
    return [item.strip() for item in (value or "").replace(";", ",").split(",") if item.strip()]


def _network_subnet_capacity(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return 0
    if network.version == 4 and network.prefixlen <= 30:
        return max(network.num_addresses - 2, 0)
    return network.num_addresses


def _network_dashboard_context():
    subnet_rows = []
    for subnet in NetworkSubnet.objects.select_related("site", "vlan").prefetch_related("ip_addresses").order_by("site__name", "cidr"):
        capacity = _network_subnet_capacity(subnet.cidr)
        assigned_count = subnet.ip_addresses.exclude(status="available").count()
        usage = round((assigned_count / capacity) * 100, 1) if capacity else 0
        subnet_rows.append(
            {
                "obj": subnet,
                "capacity": capacity,
                "assigned_count": assigned_count,
                "usage": usage,
            }
        )

    return {
        "sites": NetworkSite.objects.order_by("name"),
        "vlans": NetworkVLAN.objects.select_related("site").order_by("site__name", "vlan_id")[:100],
        "subnets": subnet_rows,
        "ip_addresses": NetworkIPAddress.objects.select_related("subnet", "subnet__site").order_by("-updated_at")[:120],
        "recent_changes": NetworkChangeEvent.objects.select_related("actor").order_by("-created_at")[:12],
        "sites_total": NetworkSite.objects.count(),
        "vlans_total": NetworkVLAN.objects.count(),
        "subnets_total": NetworkSubnet.objects.count(),
        "ips_total": NetworkIPAddress.objects.count(),
        "assigned_ips_total": NetworkIPAddress.objects.exclude(status="available").count(),
        "conflict_ips_total": NetworkIPAddress.objects.filter(status="conflict").count(),
    }


@login_required
def network_management_dashboard(request):
    context = _network_dashboard_context()
    return render(request, "network_management.html", context)


@login_required
@require_POST
def network_site_create(request):
    name = (request.POST.get("name") or "").strip()
    code = (request.POST.get("code") or "").strip().upper()
    location = (request.POST.get("location") or "").strip()
    description = (request.POST.get("description") or "").strip()
    if not name or not code:
        messages.error(request, "Site y code son obligatorios para crear la sede.")
        return redirect("network-management")
    site = NetworkSite.objects.create(
        name=name,
        code=code,
        location=location,
        description=description,
        created_by=request.user,
    )
    NetworkChangeEvent.objects.create(
        event_type="site_created",
        summary=f"Site {site.code} creado",
        details={"site": site.name, "location": site.location},
        actor=request.user,
    )
    messages.success(request, f"Site {site.code} creado correctamente.")
    return redirect("network-management")


@login_required
@require_POST
def network_vlan_create(request):
    site_id = request.POST.get("site_id")
    name = (request.POST.get("name") or "").strip()
    vlan_id_raw = (request.POST.get("vlan_id") or "").strip()
    vrf = (request.POST.get("vrf") or "").strip()
    description = (request.POST.get("description") or "").strip()
    if not site_id or not name or not vlan_id_raw:
        messages.error(request, "Site, VLAN ID y nombre son obligatorios.")
        return redirect("network-management")
    try:
        vlan_id = int(vlan_id_raw)
    except ValueError:
        messages.error(request, "El VLAN ID debe ser numerico.")
        return redirect("network-management")
    site = get_object_or_404(NetworkSite, pk=site_id)
    vlan = NetworkVLAN.objects.create(
        site=site,
        vlan_id=vlan_id,
        name=name,
        vrf=vrf,
        description=description,
    )
    NetworkChangeEvent.objects.create(
        event_type="vlan_created",
        summary=f"VLAN {vlan.vlan_id} creada en {site.code}",
        details={"site": site.code, "name": vlan.name, "vrf": vlan.vrf},
        actor=request.user,
    )
    messages.success(request, f"VLAN {vlan.vlan_id} creada correctamente.")
    return redirect("network-management")


@login_required
@require_POST
def network_subnet_create(request):
    site = get_object_or_404(NetworkSite, pk=request.POST.get("site_id"))
    vlan_id = request.POST.get("vlan_id")
    name = (request.POST.get("name") or "").strip()
    cidr = (request.POST.get("cidr") or "").strip()
    gateway_ip = (request.POST.get("gateway_ip") or "").strip()
    dhcp_range_start = (request.POST.get("dhcp_range_start") or "").strip()
    dhcp_range_end = (request.POST.get("dhcp_range_end") or "").strip()
    notes = (request.POST.get("notes") or "").strip()
    dns_servers = _split_newline_csv(request.POST.get("dns_servers"))
    status = (request.POST.get("status") or "active").strip()
    dhcp_enabled = request.POST.get("dhcp_enabled") == "on"
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        messages.error(request, "El CIDR indicado no es valido.")
        return redirect("network-management")
    if gateway_ip:
        try:
            if ipaddress.ip_address(gateway_ip) not in network:
                raise ValueError
        except ValueError:
            messages.error(request, "La puerta de enlace no pertenece a la subred.")
            return redirect("network-management")
    vlan = None
    if vlan_id:
        vlan = get_object_or_404(NetworkVLAN, pk=vlan_id)
    subnet = NetworkSubnet.objects.create(
        site=site,
        vlan=vlan,
        name=name or cidr,
        cidr=str(network),
        gateway_ip=gateway_ip or None,
        dhcp_enabled=dhcp_enabled,
        dhcp_range_start=dhcp_range_start or None,
        dhcp_range_end=dhcp_range_end or None,
        dns_servers=dns_servers,
        status=status,
        notes=notes,
        created_by=request.user,
    )
    NetworkChangeEvent.objects.create(
        event_type="subnet_created",
        summary=f"Subred {subnet.cidr} creada",
        details={"site": site.code, "vlan": vlan.vlan_id if vlan else None},
        actor=request.user,
    )
    messages.success(request, f"Subred {subnet.cidr} creada correctamente.")
    return redirect("network-management")


@login_required
@require_POST
def network_ip_create(request):
    subnet = get_object_or_404(NetworkSubnet, pk=request.POST.get("subnet_id"))
    ip_raw = (request.POST.get("ip_address") or "").strip()
    hostname = (request.POST.get("hostname") or "").strip()
    dns_name = (request.POST.get("dns_name") or "").strip()
    mac_address = (request.POST.get("mac_address") or "").strip()
    device_role = (request.POST.get("device_role") or "").strip()
    assigned_to = (request.POST.get("assigned_to") or "").strip()
    status = (request.POST.get("status") or "assigned").strip()
    source = (request.POST.get("source") or "").strip()
    description = (request.POST.get("description") or "").strip()
    try:
        ip_value = ipaddress.ip_address(ip_raw)
        network = ipaddress.ip_network(subnet.cidr, strict=False)
        if ip_value not in network:
            raise ValueError
    except ValueError:
        messages.error(request, "La direccion IP no pertenece a la subred seleccionada.")
        return redirect("network-management")
    ip_item = NetworkIPAddress.objects.create(
        subnet=subnet,
        ip_address=str(ip_value),
        hostname=hostname,
        dns_name=dns_name,
        mac_address=mac_address,
        device_role=device_role,
        assigned_to=assigned_to,
        status=status,
        source=source,
        description=description,
        created_by=request.user,
        last_seen=timezone.now(),
    )
    NetworkChangeEvent.objects.create(
        event_type="ip_created",
        summary=f"IP {ip_item.ip_address} registrada en {subnet.cidr}",
        details={"hostname": hostname, "status": status, "assigned_to": assigned_to},
        actor=request.user,
    )
    messages.success(request, f"IP {ip_item.ip_address} registrada correctamente.")
    return redirect("network-management")


@login_required
def devices_management(request):
    return render(request, "devices_management.html")


@login_required
def inventory_service_dashboard(request):
    from inventory.models import AgentDevice, AgentHardwareComponent, AgentNetworkIdentity, AgentSoftwareRecord, AgentTimelineEvent

    agents = AgentDevice.objects.order_by("-last_seen")[:40]
    recent_timeline = AgentTimelineEvent.objects.exclude(category="dlp").order_by("-observed_at")[:80]
    recent_hardware = AgentHardwareComponent.objects.select_related("agent").order_by("-last_seen")[:60]
    recent_software = AgentSoftwareRecord.objects.select_related("agent").filter(is_present=True).order_by("-last_seen")[:60]
    recent_users = []
    seen_users = set()
    for agent in AgentDevice.objects.order_by("-last_inventory_at", "-last_seen")[:50]:
        inventory = agent.latest_inventory or {}
        for user in inventory.get("users") or []:
            username = (user.get("username") or "").strip()
            if not username:
                continue
            key = (agent.agent_id, username.lower(), user.get("session_id", ""))
            if key in seen_users:
                continue
            seen_users.add(key)
            recent_users.append(
                {
                    "agent": agent,
                    "username": username,
                    "session_name": user.get("session_name", ""),
                    "session_id": user.get("session_id", ""),
                    "state": user.get("state", ""),
                    "idle_time": user.get("idle_time", ""),
                    "logon_time": user.get("logon_time", ""),
                    "raw": user.get("raw", ""),
                }
            )
            if len(recent_users) >= 60:
                break
        if len(recent_users) >= 60:
            break
    agent_cards = []
    for agent in agents:
        agent_cards.append(
            {
                "agent": agent,
                "hardware_count": agent.hardware_components.filter(status="active").count(),
                "software_count": agent.software_records.filter(is_present=True).count(),
                "network_count": agent.network_identities.filter(is_active=True).count(),
                "timeline_count": agent.timeline_events.exclude(category="dlp").count(),
                "latest_inventory": agent.latest_inventory or {},
            }
        )
    context = {
        "agents_total": AgentDevice.objects.count(),
        "agents_online": AgentDevice.objects.filter(status="online").count(),
        "hardware_total": AgentHardwareComponent.objects.filter(status="active").count(),
        "software_total": AgentSoftwareRecord.objects.filter(is_present=True).count(),
        "network_total": AgentNetworkIdentity.objects.filter(is_active=True).count(),
        "users_total": len(recent_users),
        "timeline_total": AgentTimelineEvent.objects.exclude(category="dlp").count(),
        "recent_agents": agent_cards,
        "recent_timeline": recent_timeline,
        "recent_hardware": recent_hardware,
        "recent_software": recent_software,
        "recent_users": recent_users,
        "top_software": AgentSoftwareRecord.objects.filter(is_present=True).order_by("-last_seen")[:40],
    }
    return render(request, "inventory_service_dashboard.html", context)


@login_required
@require_GET
def inventory_dashboard_api(request):
    return JsonResponse({"ok": True, **_serialize_inventory_dashboard()})


@login_required
def inventory_assets_dashboard(request):
    from inventory.models import AgentDevice, AgentHardwareComponent, AgentNetworkIdentity, AgentSoftwareRecord

    recent_users = []
    seen_users = set()
    for agent in AgentDevice.objects.order_by("-last_inventory_at", "-last_seen")[:80]:
        inventory = agent.latest_inventory or {}
        for user in inventory.get("users") or []:
            username = (user.get("username") or "").strip()
            if not username:
                continue
            key = (agent.agent_id, username.lower(), user.get("session_id", ""))
            if key in seen_users:
                continue
            seen_users.add(key)
            recent_users.append(
                {
                    "agent": agent,
                    "username": username,
                    "session_name": user.get("session_name", ""),
                    "session_id": user.get("session_id", ""),
                    "state": user.get("state", ""),
                    "idle_time": user.get("idle_time", ""),
                    "logon_time": user.get("logon_time", ""),
                    "raw": user.get("raw", ""),
                }
            )
            if len(recent_users) >= 60:
                break
        if len(recent_users) >= 60:
            break

    context = {
        "hardware_components": AgentHardwareComponent.objects.select_related("agent").order_by("-last_seen")[:300],
        "software_records": AgentSoftwareRecord.objects.select_related("agent").order_by("-last_seen")[:300],
        "network_identities": AgentNetworkIdentity.objects.select_related("agent").order_by("-last_seen")[:300],
        "recent_users": recent_users,
    }
    return render(request, "inventory_assets_dashboard.html", context)


@login_required
def dlp_service_dashboard(request):
    from inventory.models import AegisDlpIncident, AegisDlpPolicy, AegisDlpRule
    from inventory.services import ensure_default_aegis_policy

    ensure_default_aegis_policy()

    incidents = AegisDlpIncident.objects.select_related("agent", "policy", "rule").order_by("-detected_at")[:50]
    incidents_qs = AegisDlpIncident.objects.all()
    context = {
        "policies_total": AegisDlpPolicy.objects.filter(enabled=True).count(),
        "rules_total": AegisDlpRule.objects.filter(enabled=True).count(),
        "incidents_open": incidents_qs.filter(status="open").count(),
        "incidents_total": incidents_qs.count(),
        "incidents_critical": incidents_qs.filter(severity="critical").count(),
        "incidents_high": incidents_qs.filter(severity="high").count(),
        "incidents_recent": incidents,
        "policies": AegisDlpPolicy.objects.prefetch_related("rules").order_by("name"),
        "enabled_policies": AegisDlpPolicy.objects.filter(enabled=True).prefetch_related("rules").order_by("name"),
    }
    return render(request, "dlp_service_dashboard.html", context)


@login_required
@require_GET
def dlp_dashboard_api(request):
    return JsonResponse({"ok": True, **_serialize_dlp_dashboard()})


def _split_list_field(value):
    if isinstance(value, list):
        return [item for item in value if str(item).strip()]
    raw = (value or "").replace(";", ",").replace("\n", ",")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _serialize_inventory_dashboard():
    from inventory.models import AgentDevice, AgentHardwareComponent, AgentNetworkIdentity, AgentSoftwareRecord, AgentTimelineEvent

    recent_agents = []
    recent_users = []
    for agent in AgentDevice.objects.order_by("-last_seen")[:40]:
        latest_inventory = agent.latest_inventory or {}
        users = latest_inventory.get("users") or []
        agent_users = []
        for user in users:
            username = (user or {}).get("username", "")
            if username:
                agent_users.append(
                    {
                        "username": username,
                        "raw": (user or {}).get("raw", ""),
                        "session": (user or {}).get("session", ""),
                        "session_name": (user or {}).get("session_name", ""),
                        "session_id": (user or {}).get("session_id", ""),
                        "state": (user or {}).get("state", ""),
                        "logon_time": (user or {}).get("logon_time", ""),
                        "agent_id": agent.agent_id,
                        "host_name": agent.host_name,
                    }
                )
        recent_users.extend(agent_users)
        recent_agents.append(
            {
                "agent_id": agent.agent_id,
                "host_name": agent.host_name,
                "host_ip": agent.host_ip,
                "status": agent.status,
                "last_seen": agent.last_seen.isoformat() if agent.last_seen else "",
                "last_inventory_at": agent.last_inventory_at.isoformat() if agent.last_inventory_at else "",
                "hardware_count": agent.hardware_components.filter(status="active").count(),
                "software_count": agent.software_records.filter(is_present=True).count(),
                "network_count": agent.network_identities.filter(is_active=True).count(),
                "timeline_count": agent.timeline_events.exclude(category="dlp").count(),
                "logged_users": agent_users,
                "latest_inventory": latest_inventory,
            }
        )

    recent_timeline = []
    for event in AgentTimelineEvent.objects.exclude(category="dlp").order_by("-observed_at")[:80]:
        recent_timeline.append(
            {
                "title": event.title,
                "description": event.description,
                "category": event.category,
                "severity": event.severity,
                "observed_at": event.observed_at.isoformat() if event.observed_at else "",
                "agent_id": event.agent.agent_id,
                "host_name": event.agent.host_name,
            }
        )

    recent_hardware = []
    for item in AgentHardwareComponent.objects.select_related("agent").order_by("-last_seen")[:60]:
        recent_hardware.append(
            {
                "agent_id": item.agent.agent_id,
                "host_name": item.agent.host_name,
                "component_type": item.component_type,
                "name": item.name,
                "serial_number": item.serial_number,
                "status": item.status,
            }
        )

    recent_software = []
    for item in AgentSoftwareRecord.objects.select_related("agent").filter(is_present=True).order_by("-last_seen")[:60]:
        recent_software.append(
            {
                "agent_id": item.agent.agent_id,
                "host_name": item.agent.host_name,
                "name": item.name,
                "version": item.version,
                "publisher": item.publisher,
                "is_present": item.is_present,
                "last_seen": item.last_seen.isoformat() if item.last_seen else "",
            }
        )

    top_software = []
    for item in AgentSoftwareRecord.objects.select_related("agent").filter(is_present=True).order_by("-last_seen")[:40]:
        top_software.append(
            {
                "agent_id": item.agent.agent_id,
                "host_name": item.agent.host_name,
                "name": item.name,
                "version": item.version,
                "publisher": item.publisher,
                "last_seen": item.last_seen.isoformat() if item.last_seen else "",
            }
        )

    return {
        "stats": {
            "agents_total": AgentDevice.objects.count(),
            "agents_online": AgentDevice.objects.filter(status="online").count(),
            "hardware_total": AgentHardwareComponent.objects.filter(status="active").count(),
            "software_total": AgentSoftwareRecord.objects.filter(is_present=True).count(),
            "network_total": AgentNetworkIdentity.objects.filter(is_active=True).count(),
            "timeline_total": AgentTimelineEvent.objects.exclude(category="dlp").count(),
            "users_total": len(recent_users),
        },
        "recent_agents": recent_agents,
        "recent_timeline": recent_timeline,
        "recent_hardware": recent_hardware,
        "recent_software": recent_software,
        "top_software": top_software,
        "recent_users": recent_users[:50],
    }


def _serialize_dlp_policy(policy):
    rules = []
    for rule in policy.rules.all().order_by("name"):
        rules.append(
            {
                "id": rule.id,
                "name": rule.name,
                "classification": rule.classification,
                "severity": rule.severity,
                "match_type": rule.match_type,
                "pattern": rule.pattern,
                "tags": rule.tags or [],
                "enabled": rule.enabled,
            }
        )
    return {
        "id": policy.id,
        "name": policy.name,
        "code": policy.code,
        "description": policy.description,
        "enabled": policy.enabled,
        "severity": policy.severity,
        "scan_paths": policy.scan_paths or [],
        "monitored_extensions": policy.monitored_extensions or [],
        "max_file_size_mb": policy.max_file_size_mb,
        "rule_count": len([rule for rule in rules if rule["enabled"]]),
        "rules": rules,
    }


def _serialize_dlp_incident(incident):
    metadata = incident.metadata or {}
    incident_meta = metadata.get("metadata") if isinstance(metadata.get("metadata"), dict) else {}
    return {
        "id": incident.id,
        "detected_at": incident.detected_at.isoformat() if incident.detected_at else "",
        "agent_id": incident.agent.agent_id,
        "host_name": incident.agent.host_name,
        "host_ip": incident.agent.host_ip,
        "policy_name": incident.policy.name if incident.policy else "",
        "policy_code": incident.policy.code if incident.policy else "",
        "rule_name": incident.rule.name if incident.rule else "",
        "classification": incident.classification,
        "severity": incident.severity,
        "file_name": incident.file_name,
        "file_path": incident.file_path,
        "channel": incident.channel,
        "status": incident.status,
        "actor": incident.actor,
        "reported_by": incident.reported_by,
        "reported_at": incident.reported_at.isoformat() if incident.reported_at else "",
        "reporte_id": incident.reporte_id,
        "incidente_id": incident.incidente_id,
        "matched_keywords": metadata.get("matched_keywords") or [],
        "file_hash": incident.file_hash,
        "metadata": metadata,
        "artifact_meta": incident_meta,
        "preview_available": Path(incident.file_path).exists() if incident.file_path else False,
    }


def _serialize_dlp_dashboard():
    from inventory.models import AegisDlpIncident, AegisDlpPolicy, AegisDlpRule
    from inventory.services import ensure_default_aegis_policy

    ensure_default_aegis_policy()

    policies = AegisDlpPolicy.objects.prefetch_related("rules").order_by("name")
    incidents = AegisDlpIncident.objects.select_related("agent", "policy", "rule").order_by("-detected_at")[:50]
    return {
        "stats": {
            "policies_total": AegisDlpPolicy.objects.filter(enabled=True).count(),
            "rules_total": AegisDlpRule.objects.filter(enabled=True).count(),
            "incidents_open": AegisDlpIncident.objects.filter(status="open").count(),
            "incidents_total": AegisDlpIncident.objects.count(),
            "incidents_critical": AegisDlpIncident.objects.filter(severity="critical").count(),
            "incidents_high": AegisDlpIncident.objects.filter(severity="high").count(),
        },
        "policies": [_serialize_dlp_policy(policy) for policy in policies],
        "incidents": [_serialize_dlp_incident(incident) for incident in incidents],
    }


def _osic_reporter_name(user):
    full_name = (user.get_full_name() or "").strip()
    if full_name:
        return full_name
    return getattr(user, "username", "") or "Operador VANT-SIEM"


def _osic_reporter_email(user):
    email = (getattr(user, "email", "") or "").strip()
    if email:
        return email
    username = getattr(user, "username", "operador")
    return f"{username}@vant-siem.local"


def _ensure_osic_eventm_defaults():
    from EVENT_M.models import Area, Categoria, Responsable, Servicio, Subcategoria

    responsable_defaults = {
        "telefono_particular": "N/A",
        "telefono_corp": "N/A",
        "descripcion": "Responsable generado automaticamente por OSIC-Threads.",
    }
    cuadro_centro, _ = Responsable.objects.get_or_create(
        email="osic-cuadro@vant-siem.local",
        defaults={
            "nombres": "Centro",
            "apellidos": "OSIC",
            "tipo": "Cuadro Centro",
            **responsable_defaults,
        },
    )
    rsi, _ = Responsable.objects.get_or_create(
        email="osic-rsi@vant-siem.local",
        defaults={
            "nombres": "Analista",
            "apellidos": "OSIC",
            "tipo": "RSI",
            **responsable_defaults,
        },
    )
    admin, _ = Responsable.objects.get_or_create(
        email="osic-admin@vant-siem.local",
        defaults={
            "nombres": "Administrador",
            "apellidos": "OSIC",
            "tipo": "Admin",
            **responsable_defaults,
        },
    )
    area, _ = Area.objects.get_or_create(
        nombre="OSIC Threat Operations",
        defaults={
            "acronimo": "OSIC",
            "cuadro_centro": cuadro_centro,
            "rsi": rsi,
            "admin": admin,
        },
    )
    if not area.acronimo:
        area.acronimo = "OSIC"
        area.cuadro_centro = area.cuadro_centro_id and area.cuadro_centro or cuadro_centro
        area.rsi = area.rsi_id and area.rsi or rsi
        area.admin = area.admin_id and area.admin or admin
        area.save()

    servicio, _ = Servicio.objects.get_or_create(
        nombre="Aegis DLP",
        defaults={
            "descripcion": "Servicio soberano de prevencion de fuga de informacion y triage OSIC.",
            "host": None,
            "monitorear": False,
        },
    )
    categoria, _ = Categoria.objects.get_or_create(
        nombre="Fuga de Informacion",
        defaults={"descripcion": "Categoria para detecciones de exfiltracion, clasificacion y DLP."},
    )
    subcategoria, _ = Subcategoria.objects.get_or_create(
        categoria=categoria,
        nombre="OSIC Threat",
        defaults={
            "descripcion": "Deteccion automatica de documento sensible o clasificado por Aegis DLP.",
            "nivel_peligrosidad": 9,
        },
    )
    return area, servicio, subcategoria


def _build_osic_summary(incident):
    agent = incident.agent
    metadata = incident.metadata or {}
    artifact_meta = metadata.get("metadata") if isinstance(metadata.get("metadata"), dict) else {}
    matched_keywords = metadata.get("matched_keywords") or []
    parts = [
        f"OSIC-Thread detectado por Aegis DLP en {agent.host_name or agent.agent_id}.",
        f"IP observada: {agent.host_ip or 'N/D'}.",
        f"Actor observado: {incident.actor or 'N/D'}.",
        f"Clasificacion: {incident.classification or 'sensible'} ({incident.severity}).",
        f"Canal: {incident.channel or 'filesystem'}.",
        f"Archivo: {incident.file_name or 'N/D'}.",
        f"Ruta: {incident.file_path or 'N/D'}.",
        f"Hash: {incident.file_hash or 'N/D'}.",
        f"Politica: {incident.policy.code if incident.policy else 'N/D'}.",
        f"Regla: {incident.rule.name if incident.rule else 'N/D'}.",
    ]
    if matched_keywords:
        parts.append(f"Coincidencias: {', '.join(matched_keywords)}.")
    if artifact_meta:
        parts.append(
            "Metadatos: "
            f"tamano={artifact_meta.get('size', 'N/D')}, "
            f"creado={artifact_meta.get('created_at', 'N/D')}, "
            f"modificado={artifact_meta.get('modified_at', 'N/D')}."
        )
    return "\n".join(parts)


def _build_osic_evidence_payload(incident):
    metadata = incident.metadata or {}
    return {
        "osic_thread_id": incident.id,
        "agent": {
            "agent_id": incident.agent.agent_id,
            "host_name": incident.agent.host_name,
            "host_ip": incident.agent.host_ip,
        },
        "classification": incident.classification,
        "severity": incident.severity,
        "status": incident.status,
        "actor": incident.actor,
        "channel": incident.channel,
        "file": {
            "name": incident.file_name,
            "path": incident.file_path,
            "hash": incident.file_hash,
        },
        "policy": {
            "name": incident.policy.name if incident.policy else "",
            "code": incident.policy.code if incident.policy else "",
        },
        "rule": {
            "name": incident.rule.name if incident.rule else "",
            "classification": incident.rule.classification if incident.rule else "",
        },
        "matched_keywords": metadata.get("matched_keywords") or [],
        "metadata": metadata.get("metadata") if isinstance(metadata.get("metadata"), dict) else metadata,
        "detected_at": incident.detected_at.isoformat() if incident.detected_at else "",
        "generated_at": timezone.now().isoformat(),
    }


def _preview_osic_document(incident):
    response = {
        "available": False,
        "content": "",
        "content_type": "metadata",
        "message": "El archivo original no esta disponible en el servidor; se muestra evidencia tecnica y metadatos.",
    }
    raw_path = (incident.file_path or "").strip()
    if not raw_path:
        return response
    file_path = Path(raw_path)
    if not file_path.exists() or not file_path.is_file():
        return response
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")[:5000]
        response.update(
            {
                "available": True,
                "content": content,
                "content_type": "text",
                "message": "Vista previa local obtenida desde el servidor.",
            }
        )
    except Exception as exc:
        response["message"] = f"No fue posible leer el archivo localmente: {exc}"
    return response


def _create_osic_event_report(request, incident):
    from EVENT_M.models import Incidente, Reporte
    from inventory.models import AgentTimelineEvent

    if incident.incidente_id and incident.reporte_id:
        return incident.reporte, incident.incidente, False

    area, servicio, subcategoria = _ensure_osic_eventm_defaults()
    reporter_name = _osic_reporter_name(request.user)
    reporter_email = _osic_reporter_email(request.user)
    summary = _build_osic_summary(incident)
    evidence_payload = _build_osic_evidence_payload(incident)
    evidence_name = f"osic-thread-{incident.id}.json"
    evidence_blob = json.dumps(evidence_payload, indent=2, ensure_ascii=False)

    with transaction.atomic():
        reporte = Reporte.objects.create(
            nombre_informante=reporter_name,
            email_informante=reporter_email,
            area=area,
            descripcion=summary,
            estado_solucion="Atendido",
        )
        incidente_event = Incidente.objects.create(
            nombre_incidente=f"OSIC Threat en {incident.agent.host_name or incident.agent.agent_id}",
            descripcion=summary,
            reporte=reporte,
            estado_solucion="abierto",
            notificado_osri="no",
        )
        incidente_event.servicios.add(servicio)
        incidente_event.areas.add(area)
        incidente_event.subcategorias.add(subcategoria)
        incidente_event.evidencia.save(evidence_name, ContentFile(evidence_blob.encode("utf-8")), save=True)

        incident.status = "contained"
        incident.reporte = reporte
        incident.incidente = incidente_event
        incident.reported_by = reporter_name
        incident.reported_at = timezone.now()
        incident.save(
            update_fields=[
                "status",
                "reporte",
                "incidente",
                "reported_by",
                "reported_at",
            ]
        )

        AgentTimelineEvent.objects.create(
            agent=incident.agent,
            category="dlp",
            event_type="osic_reported",
            title=f"OSIC-Thread {incident.id} reportado a EVENT_M",
            description=summary,
            severity=incident.severity or "high",
            actor=reporter_name,
            file_path=incident.file_path,
            file_hash=incident.file_hash,
            observed_at=timezone.now(),
            source_service="osic_threads",
            metadata={
                "reporte_id": reporte.id,
                "incidente_id": incidente_event.id,
                "reported_by": reporter_name,
            },
        )

    return reporte, incidente_event, True

@login_required
def dlp_rule_save(request, policy_id, rule_id=None):
    from inventory.models import AegisDlpPolicy, AegisDlpRule

    policy = get_object_or_404(AegisDlpPolicy, id=policy_id)
    rule = get_object_or_404(AegisDlpRule, id=rule_id, policy=policy) if rule_id else None

    if request.method == "POST":
        payload = {
            "name": request.POST.get("name", "").strip(),
            "enabled": request.POST.get("enabled") == "on",
            "classification": request.POST.get("classification", "").strip(),
            "severity": request.POST.get("severity", "high").strip() or "high",
            "match_type": request.POST.get("match_type", "keyword").strip() or "keyword",
            "pattern": request.POST.get("pattern", "").strip(),
            "tags": _split_list_field(request.POST.get("tags", "")),
        }
        if rule:
            for key, value in payload.items():
                setattr(rule, key, value)
            rule.save()
            messages.success(request, "Regla actualizada.")
        else:
            AegisDlpRule.objects.create(policy=policy, **payload)
            messages.success(request, "Regla creada.")
        return redirect("dlp-policy-list")

    policies = AegisDlpPolicy.objects.prefetch_related("rules").order_by("name")
    return render(
        request,
        "dlp_policy_list.html",
        {"policies": policies, "edit_policy": policy, "edit_rule": rule},
    )


@login_required
def dlp_rule_delete(request, policy_id, rule_id):
    from inventory.models import AegisDlpPolicy, AegisDlpRule

    policy = get_object_or_404(AegisDlpPolicy, id=policy_id)
    rule = get_object_or_404(AegisDlpRule, id=rule_id, policy=policy)
    if request.method == "POST":
        rule.delete()
        messages.success(request, "Regla eliminada.")
    return redirect("dlp-policy-list")


@login_required
def dlp_policy_list(request):
    from inventory.models import AegisDlpPolicy
    from inventory.services import ensure_default_aegis_policy

    ensure_default_aegis_policy()

    if request.method == "POST":
        policy_id = request.POST.get("policy_id", "").strip()
        action = request.POST.get("action", "").strip() or "save"
        if action == "delete" and policy_id:
            AegisDlpPolicy.objects.filter(id=policy_id).delete()
            messages.success(request, "Política eliminada.")
            return redirect("dlp-policy-list")

        policy = AegisDlpPolicy.objects.filter(id=policy_id).first() if policy_id else None
        payload = {
            "name": request.POST.get("name", "").strip(),
            "code": request.POST.get("code", "").strip(),
            "description": request.POST.get("description", "").strip(),
            "enabled": request.POST.get("enabled") == "on",
            "severity": request.POST.get("severity", "high").strip() or "high",
            "scan_paths": _split_list_field(request.POST.get("scan_paths", "")),
            "monitored_extensions": _split_list_field(request.POST.get("monitored_extensions", "")),
            "max_file_size_mb": int(request.POST.get("max_file_size_mb", 10) or 10),
        }
        if policy:
            for key, value in payload.items():
                setattr(policy, key, value)
            policy.save()
            messages.success(request, "Política actualizada.")
        else:
            AegisDlpPolicy.objects.create(**payload)
            messages.success(request, "Política creada.")
        return redirect("dlp-policy-list")

    policies = AegisDlpPolicy.objects.prefetch_related("rules").order_by("name")
    return render(request, "dlp_policy_list.html", {"policies": policies})


@login_required
def dlp_policy_create(request):
    from inventory.models import AegisDlpPolicy, AegisDlpRule
    from inventory.services import ensure_default_aegis_policy

    ensure_default_aegis_policy()

    if request.method == "POST":
        scan_paths = [item.strip() for item in request.POST.get("scan_paths", "").splitlines() if item.strip()]
        monitored_extensions = [item.strip() for item in request.POST.get("monitored_extensions", "").split(",") if item.strip()]
        tags = [item.strip() for item in request.POST.get("rule_tags", "").split(",") if item.strip()]
        policy = AegisDlpPolicy.objects.create(
            name=request.POST.get("name", "").strip(),
            code=request.POST.get("code", "").strip(),
            description=request.POST.get("description", "").strip(),
            enabled=request.POST.get("enabled") == "on",
            severity=request.POST.get("severity", "high").strip() or "high",
            scan_paths=scan_paths,
            monitored_extensions=monitored_extensions,
            max_file_size_mb=int(request.POST.get("max_file_size_mb", 10) or 10),
        )
        if request.POST.get("rule_name", "").strip() and request.POST.get("rule_pattern", "").strip():
            AegisDlpRule.objects.create(
                policy=policy,
                name=request.POST.get("rule_name", "").strip(),
                enabled=True,
                classification=request.POST.get("rule_classification", "").strip(),
                severity=request.POST.get("rule_severity", "high").strip() or "high",
                match_type=request.POST.get("rule_match_type", "keyword").strip() or "keyword",
                pattern=request.POST.get("rule_pattern", "").strip(),
                tags=tags,
            )
        messages.success(request, f'Politica DLP "{policy.name}" creada exitosamente.')
        return redirect("dlp-policy-list")

    return render(request, "dlp_policy_form.html", {"mode": "create"})


@login_required
def dlp_policy_edit(request, policy_id):
    from inventory.models import AegisDlpPolicy, AegisDlpRule
    from inventory.services import ensure_default_aegis_policy

    ensure_default_aegis_policy()

    policy = get_object_or_404(AegisDlpPolicy, id=policy_id)
    if request.method == "POST":
        action = request.POST.get("action", "save")
        if action == "add_rule":
            tags = [item.strip() for item in request.POST.get("rule_tags", "").split(",") if item.strip()]
            if request.POST.get("rule_name", "").strip() and request.POST.get("rule_pattern", "").strip():
                AegisDlpRule.objects.create(
                    policy=policy,
                    name=request.POST.get("rule_name", "").strip(),
                    enabled=True,
                    classification=request.POST.get("rule_classification", "").strip(),
                    severity=request.POST.get("rule_severity", "high").strip() or "high",
                    match_type=request.POST.get("rule_match_type", "keyword").strip() or "keyword",
                    pattern=request.POST.get("rule_pattern", "").strip(),
                    tags=tags,
                )
                messages.success(request, "Regla DLP agregada.")
            return redirect("dlp-policy-edit", policy_id=policy.id)

        policy.name = request.POST.get("name", "").strip()
        policy.code = request.POST.get("code", "").strip()
        policy.description = request.POST.get("description", "").strip()
        policy.enabled = request.POST.get("enabled") == "on"
        policy.severity = request.POST.get("severity", "high").strip() or "high"
        policy.scan_paths = [item.strip() for item in request.POST.get("scan_paths", "").splitlines() if item.strip()]
        policy.monitored_extensions = [item.strip() for item in request.POST.get("monitored_extensions", "").split(",") if item.strip()]
        policy.max_file_size_mb = int(request.POST.get("max_file_size_mb", 10) or 10)
        policy.save()
        messages.success(request, f'Politica "{policy.name}" actualizada.')
        return redirect("dlp-policy-edit", policy_id=policy.id)

    return render(request, "dlp_policy_form.html", {"mode": "edit", "policy": policy})


@login_required
def dlp_incident_list(request):
    from inventory.models import AegisDlpIncident

    incidents = AegisDlpIncident.objects.select_related("agent", "policy", "rule").order_by("-detected_at")
    status_filter = request.GET.get("status", "").strip()
    if status_filter:
        incidents = incidents.filter(status=status_filter)
    incident_payload = [_serialize_dlp_incident(item) for item in incidents[:200]]
    return render(
        request,
        "dlp_incident_list.html",
        {
            "incidents": incidents[:200],
            "incident_payload": incident_payload,
            "status_filter": status_filter,
        },
    )


@login_required
@require_POST
def dlp_incident_update(request, incident_id):
    from inventory.models import AegisDlpIncident

    incident = get_object_or_404(AegisDlpIncident, id=incident_id)
    new_status = request.POST.get("status", "").strip()
    if new_status in {"open", "reviewing", "contained", "closed"}:
        incident.status = new_status
        incident.save(update_fields=["status"])
        payload = {
            "ok": True,
            "message": f"OSIC-Thread {incident.id} actualizado a {new_status}.",
            "incident": _serialize_dlp_incident(incident),
        }
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse(payload)
        messages.success(request, payload["message"])
    else:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse({"ok": False, "message": "Estado DLP invalido."}, status=400)
        messages.error(request, "Estado DLP invalido.")
    return redirect("dlp-incident-list")


@login_required
@require_GET
def dlp_incident_feed(request):
    from inventory.models import AegisDlpIncident

    incidents = AegisDlpIncident.objects.select_related("agent", "policy", "rule").order_by("-detected_at")
    status_filter = request.GET.get("status", "").strip().lower()
    if status_filter:
        incidents = incidents.filter(status=status_filter)
    classification = request.GET.get("classification", "").strip().lower()
    if classification:
        incidents = incidents.filter(classification__icontains=classification)
    limit = min(max(int(request.GET.get("limit", 120) or 120), 1), 300)
    return JsonResponse(
        {
            "ok": True,
            "incidents": [_serialize_dlp_incident(item) for item in incidents[:limit]],
        }
    )


@login_required
@require_GET
def dlp_incident_preview(request, incident_id):
    from inventory.models import AegisDlpIncident

    incident = get_object_or_404(AegisDlpIncident.objects.select_related("agent", "policy", "rule"), id=incident_id)
    preview = _preview_osic_document(incident)
    return JsonResponse(
        {
            "ok": True,
            "incident": _serialize_dlp_incident(incident),
            "preview": preview,
            "summary": _build_osic_summary(incident),
        }
    )


@login_required
@require_POST
def dlp_incident_report(request, incident_id):
    from inventory.models import AegisDlpIncident

    incident = get_object_or_404(AegisDlpIncident.objects.select_related("agent", "policy", "rule"), id=incident_id)
    reporte, incidente_event, created = _create_osic_event_report(request, incident)
    message = (
        f"OSIC-Thread {incident.id} reportado a EVENT_M como incidente {incidente_event.codigo_incidente}."
        if created
        else f"OSIC-Thread {incident.id} ya estaba vinculado al incidente {incidente_event.codigo_incidente}."
    )
    payload = {
        "ok": True,
        "created": created,
        "message": message,
        "incident": _serialize_dlp_incident(incident),
        "event_report": {
            "reporte_id": reporte.id,
            "incidente_id": incidente_event.id,
            "codigo_incidente": incidente_event.codigo_incidente,
            "detail_url": reverse("incidente-detail", kwargs={"pk": incidente_event.id}),
        },
    }
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(payload)
    messages.success(request, message)
    return redirect("dlp-incident-list")


def _inventory_components(payload):
    payload = payload or {}
    hardware = payload.get("hardware") or []
    software = payload.get("software") or []
    network = payload.get("network") or []
    users = payload.get("users") or []
    usb_devices = payload.get("usb_devices") or []

    def _first_component(component_type):
        for item in hardware:
            if (item.get("component_type") or "").lower() == component_type:
                return item
        return {}

    return {
        "hardware": hardware,
        "software": software,
        "network": network,
        "users": users,
        "usb_devices": usb_devices,
        "bios": _first_component("bios"),
        "system": _first_component("system"),
        "cpu": _first_component("cpu"),
        "board": _first_component("board"),
        "disk": _first_component("disk"),
        "network_identity": _first_component("network"),
        "usb": _first_component("usb"),
    }


DEFAULT_AGENT_SHARED_SECRET = "VANT-SIEM-AGENT-BOOTSTRAP-2026"


def _derive_secret_from_superuser():
    user = User.objects.filter(is_superuser=True).order_by("id").first()
    if not user or not user.username:
        return DEFAULT_AGENT_SHARED_SECRET
    return hashlib.sha256(user.username.encode("utf-8")).hexdigest()


def _load_agent_shared_secret():
    env_secret = os.environ.get('VANT_AGENT_SHARED_SECRET', '').strip()
    if env_secret:
        return env_secret
    return _derive_secret_from_superuser()


def _load_agent_allowlist():
    raw = os.environ.get('VANT_AGENT_ALLOWED', '').strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(',') if item.strip()]


def _agent_is_allowed(agent_id='', host_name=''):
    allowlist = _load_agent_allowlist()
    if not allowlist:
        return True
    normalized = {item.strip().lower() for item in allowlist if item.strip()}
    agent_id_norm = (agent_id or '').strip().lower()
    host_name_norm = (host_name or '').strip().lower()
    return agent_id_norm in normalized or host_name_norm in normalized


def _get_bearer_token(request):
    auth = request.headers.get('Authorization', '')
    if auth.lower().startswith('bearer '):
        return auth.split(' ', 1)[1].strip()
    return ''


def _authorize_agent_request(request, agent_id=None):
    token = _get_bearer_token(request)
    if not token:
        return None
    try:
        data = signing.loads(token, salt='vant-siem-agent-token', max_age=86400 * 30)
    except Exception:
        return None
    if agent_id and data.get('agent_id') != agent_id:
        return None
    return data


@csrf_exempt
@require_POST
def agent_enroll(request):
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    agent_id = payload.get('agent_id', '').strip()
    host_name = payload.get('host_name', '').strip()
    timestamp = str(payload.get('timestamp', '')).strip()
    signature = payload.get('signature', '').strip()

    if not timestamp or not signature:
        return JsonResponse({'ok': False, 'error': 'Firma incompleta'}, status=403)

    try:
        ts = int(timestamp)
    except Exception:
        return JsonResponse({'ok': False, 'error': 'Timestamp invalido'}, status=403)

    if abs(int(time.time()) - ts) > 300:
        return JsonResponse({'ok': False, 'error': 'Timestamp expirado'}, status=403)

    secret = _load_agent_shared_secret().encode('utf-8')
    message = f"{agent_id}:{host_name}:{timestamp}".encode('utf-8')
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return JsonResponse({'ok': False, 'error': 'Firma invalida'}, status=403)

    if not _agent_is_allowed(agent_id=agent_id, host_name=host_name):
        return JsonResponse({'ok': False, 'error': 'Agente no autorizado'}, status=403)

    agent_token_payload = {
        'agent_id': agent_id,
        'host_name': host_name,
        'issued_at': timezone.now().isoformat(),
    }
    agent_token = signing.dumps(agent_token_payload, salt='vant-siem-agent-token')

    return JsonResponse(
        {
            'ok': True,
            'token': agent_token,
            'token_type': 'signed',
            'expires_in': 86400 * 30,
        }
    )


@csrf_exempt
@require_GET
def agent_bootstrap_secret(request):
    agent_id = request.headers.get("X-Agent-Id", "").strip()
    host_name = request.headers.get("X-Agent-Host", "").strip()
    if not agent_id:
        return JsonResponse({'ok': False, 'error': 'X-Agent-Id requerido'}, status=400)

    if not _agent_is_allowed(agent_id=agent_id, host_name=host_name):
        return JsonResponse({'ok': False, 'error': 'Agente no autorizado'}, status=403)

    secret = _load_agent_shared_secret()
    return JsonResponse({'ok': True, 'secret': secret})


@csrf_exempt
@require_POST
def agent_heartbeat(request):
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    agent_id = payload.get('agent_id', '').strip()
    auth = _authorize_agent_request(request, agent_id=agent_id)
    if not auth:
        return JsonResponse({'ok': False, 'error': 'Token invalido'}, status=403)

    host_name = payload.get('host_name', '').strip()
    host_ip = payload.get('host_ip', '').strip()
    agent_version = payload.get('agent_version', '').strip()
    ips = payload.get('ips') or []

    from inventory.models import AgentDevice

    device, _ = AgentDevice.objects.get_or_create(agent_id=agent_id)
    device.host_name = host_name or device.host_name
    device.host_ip = host_ip or device.host_ip
    device.agent_version = agent_version or device.agent_version
    device.last_seen = timezone.now()
    device.status = "online"

    known_ips = device.known_ips or []
    for ip in ips:
        if ip and ip not in known_ips:
            known_ips.append(ip)
    device.known_ips = known_ips
    device.save()

    return JsonResponse({'ok': True})


@csrf_exempt
@require_POST
def agent_inventory(request):
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    agent_id = payload.get('agent_id', '').strip()
    auth = _authorize_agent_request(request, agent_id=agent_id)
    if not auth:
        return JsonResponse({'ok': False, 'error': 'Token invalido'}, status=403)

    inventory = payload.get('inventory') or {}
    from inventory.models import AgentDevice
    from inventory.services import process_agent_inventory

    device, _ = AgentDevice.objects.get_or_create(agent_id=agent_id)
    device.last_seen = timezone.now()
    device.save()

    process_agent_inventory(device, inventory)
    return JsonResponse({'ok': True})


@csrf_exempt
@require_POST
def agent_dlp_incidents(request):
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    agent_id = payload.get('agent_id', '').strip()
    auth = _authorize_agent_request(request, agent_id=agent_id)
    if not auth:
        return JsonResponse({'ok': False, 'error': 'Token invalido'}, status=403)

    from inventory.models import AgentDevice
    from inventory.services import process_dlp_incidents

    device, _ = AgentDevice.objects.get_or_create(agent_id=agent_id)
    device.last_seen = timezone.now()
    device.save()

    created = process_dlp_incidents(device, payload)
    return JsonResponse({'ok': True, 'incidents': len(created)})


@csrf_exempt
@require_POST
def agent_dlp_config(request):
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    agent_id = payload.get('agent_id', '').strip()
    auth = _authorize_agent_request(request, agent_id=agent_id)
    if not auth:
        return JsonResponse({'ok': False, 'error': 'Token invalido'}, status=403)

    from inventory.services import get_aegis_policy_payload

    return JsonResponse({'ok': True, 'config': get_aegis_policy_payload()})


@csrf_exempt
@require_POST
def agent_commands_pull(request):
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    agent_id = payload.get('agent_id', '').strip()
    auth = _authorize_agent_request(request, agent_id=agent_id)
    if not auth:
        return JsonResponse({'ok': False, 'error': 'Token invalido'}, status=403)

    from inventory.models import AgentDevice, AgentCommand

    device, _ = AgentDevice.objects.get_or_create(agent_id=agent_id)
    cmd = (
        AgentCommand.objects.filter(agent=device, status='pending')
        .order_by('created_at')
        .first()
    )
    if not cmd:
        return JsonResponse({'ok': True, 'command': None})

    cmd.status = 'issued'
    cmd.save(update_fields=['status'])
    return JsonResponse({'ok': True, 'command': cmd.command, 'command_id': cmd.id})


@csrf_exempt
@require_POST
def agent_commands_ack(request):
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    command_id = payload.get('command_id')
    status = payload.get('status', 'done')
    if not command_id:
        return JsonResponse({'ok': False, 'error': 'command_id requerido'}, status=400)

    from inventory.models import AgentCommand

    try:
        cmd = AgentCommand.objects.get(id=command_id)
    except AgentCommand.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'command_id invalido'}, status=404)

    cmd.status = status
    cmd.executed_at = timezone.now()
    cmd.save(update_fields=['status', 'executed_at'])
    return JsonResponse({'ok': True})


@login_required
@require_POST
def agent_command_issue(request):
    if not request.user.is_superuser:
        return JsonResponse({'ok': False, 'error': 'No autorizado'}, status=403)
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}
    agent_id = payload.get('agent_id', '').strip()
    command = payload.get('command', '').strip()
    if command not in ('stop', 'restart', 'activate'):
        return JsonResponse({'ok': False, 'error': 'Comando invalido'}, status=400)

    from inventory.models import AgentDevice, AgentCommand

    try:
        device = AgentDevice.objects.get(agent_id=agent_id)
    except AgentDevice.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'Agente no encontrado'}, status=404)

    cmd = AgentCommand.objects.create(agent=device, command=command, status='pending')
    return JsonResponse({'ok': True, 'command_id': cmd.id})


@login_required
def agent_list(request):
    from inventory.models import AgentDevice
    devices = AgentDevice.objects.all().order_by('-last_seen')
    payload = []
    for d in devices:
        status = d.status
        if d.last_seen:
            delta = timezone.now() - d.last_seen
            if delta.total_seconds() > 120:
                status = "offline"
        payload.append(
            {
                'agent_id': d.agent_id,
                'host_name': d.host_name,
                'host_ip': d.host_ip,
                'agent_version': d.agent_version,
                'last_seen': d.last_seen.isoformat() if d.last_seen else '',
                'status': status,
            }
        )
    return JsonResponse({'ok': True, 'devices': payload})


@login_required
def agent_detail(request, agent_id):
    from inventory.models import AegisDlpIncident, AgentDevice, AgentInventorySnapshot, AgentTimelineEvent
    try:
        device = AgentDevice.objects.get(agent_id=agent_id)
    except AgentDevice.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'Agente no encontrado'}, status=404)

    snapshots = (
        AgentInventorySnapshot.objects.filter(agent=device)
        .order_by('-created_at')[:10]
    )
    history = [
        {
            'created_at': s.created_at.isoformat(),
            'payload': s.payload,
        }
        for s in snapshots
    ]
    timeline = [
        {
            'category': event.category,
            'event_type': event.event_type,
            'title': event.title,
            'description': event.description,
            'severity': event.severity,
            'actor': event.actor,
            'file_path': event.file_path,
            'file_hash': event.file_hash,
            'observed_at': event.observed_at.isoformat(),
            'source_service': event.source_service,
            'metadata': event.metadata or {},
        }
        for event in AgentTimelineEvent.objects.filter(agent=device).order_by('-observed_at')[:100]
    ]
    dlp_incidents = [
        {
            'classification': incident.classification,
            'severity': incident.severity,
            'file_name': incident.file_name,
            'file_path': incident.file_path,
            'file_hash': incident.file_hash,
            'actor': incident.actor,
            'channel': incident.channel,
            'status': incident.status,
            'detected_at': incident.detected_at.isoformat(),
            'metadata': incident.metadata or {},
        }
        for incident in AegisDlpIncident.objects.filter(agent=device).order_by('-detected_at')[:100]
    ]
    return JsonResponse(
        {
            'ok': True,
            'device': {
                'agent_id': device.agent_id,
                'host_name': device.host_name,
                'host_ip': device.host_ip,
                'agent_version': device.agent_version,
                'status': device.status,
                'last_seen': device.last_seen.isoformat() if device.last_seen else '',
                'last_inventory_at': device.last_inventory_at.isoformat() if device.last_inventory_at else '',
                'last_dlp_at': device.last_dlp_at.isoformat() if device.last_dlp_at else '',
                'known_ips': device.known_ips or [],
                'latest_inventory': device.latest_inventory or {},
            },
            'history': history,
            'timeline': timeline,
            'dlp_incidents': dlp_incidents,
        }
    )


@login_required
def agent_detail_page(request, agent_id):
    from inventory.models import AegisDlpIncident, AgentDevice, AgentInventorySnapshot, AgentHardwareComponent, AgentNetworkIdentity, AgentSoftwareRecord, AgentTimelineEvent
    try:
        device = AgentDevice.objects.get(agent_id=agent_id)
    except AgentDevice.DoesNotExist:
        return render(request, "agent_detail.html", {"error": "Agente no encontrado"})

    latest = (
        AgentInventorySnapshot.objects.filter(agent=device)
        .order_by("-created_at")
        .first()
    )
    latest_inventory = latest.payload if latest else (device.latest_inventory or {})
    inventory_summary = _inventory_components(latest_inventory)
    context = {
        "device": device,
        "latest_snapshot": latest_inventory,
        "latest_inventory": latest_inventory,
        "latest_at": latest.created_at if latest else None,
        "inventory_summary": inventory_summary,
        "hardware_components": AgentHardwareComponent.objects.filter(agent=device).order_by("component_type", "name"),
        "software_records": AgentSoftwareRecord.objects.filter(agent=device).order_by("-last_seen"),
        "network_identities": AgentNetworkIdentity.objects.filter(agent=device).order_by("-last_seen"),
        "timeline_events": AgentTimelineEvent.objects.filter(agent=device).order_by("-observed_at")[:100],
        "dlp_incidents": AegisDlpIncident.objects.filter(agent=device).order_by("-detected_at")[:100],
        "latest_inventory_json": json.dumps(latest_inventory, ensure_ascii=False),
    }
    return render(request, "agent_detail_inventory.html", context)


@login_required
def agent_inventory_csv(request, agent_id):
    from inventory.models import AgentDevice, AgentInventorySnapshot
    try:
        device = AgentDevice.objects.get(agent_id=agent_id)
    except AgentDevice.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'Agente no encontrado'}, status=404)

    snapshots = AgentInventorySnapshot.objects.filter(agent=device).order_by('-created_at')
    rows = ["created_at,payload_json"]
    for s in snapshots:
        payload = json.dumps(s.payload, ensure_ascii=False).replace('"', '""')
        rows.append(f"\"{s.created_at.isoformat()}\",\"{payload}\"")
    resp = JsonResponse({})
    resp.content = "\n".join(rows).encode("utf-8")
    resp["Content-Type"] = "text/csv; charset=utf-8"
    resp["Content-Disposition"] = f'attachment; filename="inventory_{agent_id}.csv"'
    return resp


@login_required
def agent_apps_csv(request, agent_id):
    from inventory.models import AgentDevice, AgentInventorySnapshot, AgentSoftwareRecord
    try:
        device = AgentDevice.objects.get(agent_id=agent_id)
    except AgentDevice.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'Agente no encontrado'}, status=404)

    snapshot = (
        AgentInventorySnapshot.objects.filter(agent=device)
        .order_by('-created_at')
        .first()
    )
    apps = []
    if snapshot and snapshot.payload:
        apps = snapshot.payload.get("software") or []
        if not apps:
            raw = snapshot.payload.get("installed_apps")
            if isinstance(raw, str):
                try:
                    apps = json.loads(raw)
                except Exception:
                    apps = []
            elif isinstance(raw, list):
                apps = raw
    if not apps:
        apps = [
            {
                "name": item.name,
                "version": item.version,
                "publisher": item.publisher,
            }
            for item in AgentSoftwareRecord.objects.filter(agent=device, is_present=True).order_by("name")
        ]

    def _app_field(app, *keys):
        if not isinstance(app, dict):
            return ""
        for key in keys:
            value = app.get(key)
            if value:
                return value
        return ""

    rows = ["name,version,publisher"]
    for app in apps or []:
        name = _app_field(app, "name", "DisplayName", "Name")
        version = _app_field(app, "version", "DisplayVersion", "Version")
        publisher = _app_field(app, "publisher", "Publisher", "Vendor")
        rows.append(f"\"{name}\",\"{version}\",\"{publisher}\"")
    resp = JsonResponse({})
    resp.content = "\n".join(rows).encode("utf-8")
    resp["Content-Type"] = "text/csv; charset=utf-8"
    resp["Content-Disposition"] = f'attachment; filename="apps_{agent_id}.csv"'
    return resp


@login_required
def agent_inventory_compare(request, agent_id):
    from inventory.models import AgentDevice, AgentInventorySnapshot
    try:
        device = AgentDevice.objects.get(agent_id=agent_id)
    except AgentDevice.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'Agente no encontrado'}, status=404)

    from_ts = request.GET.get("from")
    to_ts = request.GET.get("to")
    if from_ts and to_ts:
        try:
            from_dt = timezone.datetime.fromisoformat(from_ts)
            to_dt = timezone.datetime.fromisoformat(to_ts)
            snapshots = list(
                AgentInventorySnapshot.objects.filter(
                    agent=device, created_at__in=[from_dt, to_dt]
                ).order_by("-created_at")
            )
        except Exception:
            snapshots = []
    else:
        snapshots = list(
            AgentInventorySnapshot.objects.filter(agent=device)
            .order_by('-created_at')[:2]
        )
    if len(snapshots) < 2:
        return JsonResponse({'ok': False, 'error': 'No hay suficientes snapshots'}, status=400)

    def _apps_from_snapshot(snap):
        payload = snap.payload or {}
        raw = payload.get("software") or payload.get("installed_apps")
        if isinstance(raw, str):
            try:
                return json.loads(raw) or []
            except Exception:
                return []
        if isinstance(raw, list):
            return raw
        return []

    def _normalize(apps):
        names = set()
        for app in apps:
            if isinstance(app, dict):
                name = app.get("name") or app.get("DisplayName")
                if name:
                    names.add(name)
        return names

    apps_new = _normalize(_apps_from_snapshot(snapshots[0]))
    apps_old = _normalize(_apps_from_snapshot(snapshots[1]))

    added = sorted(list(apps_new - apps_old))
    removed = sorted(list(apps_old - apps_new))

    return JsonResponse(
        {
            'ok': True,
            'from': snapshots[1].created_at.isoformat(),
            'to': snapshots[0].created_at.isoformat(),
            'apps_added': added,
            'apps_removed': removed,
        }
    )


@csrf_exempt
@require_POST
def agent_authorize_stop(request):
    allow_http = os.environ.get("VANT_AGENT_ALLOW_HTTP_CONTROL", "0") == "1"
    if not request.is_secure() and not settings.DEBUG and not allow_http:
        return JsonResponse({'ok': False, 'error': 'HTTPS requerido'}, status=403)
    try:
        payload = json.loads(request.body.decode('utf-8')) if request.body else {}
    except Exception:
        payload = {}

    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''

    user = authenticate(request, username=username, password=password)
    if user is None or not user.is_superuser:
        return JsonResponse({'ok': False, 'error': 'Credenciales invalidas'}, status=403)

    return JsonResponse({'ok': True})

def find_command_path(command):
    """Find the full path of a command, checking common locations"""
    # First try shutil.which (Python 3.3+)
    if hasattr(shutil, 'which'):
        path = shutil.which(command)
        if path:
            return path

    # Fallback: check common paths manually
    common_paths = [
        '/bin',
        '/usr/bin',
        '/usr/local/bin',
        '/sbin',
        '/usr/sbin',
        '/usr/local/sbin'
    ]

    for base_path in common_paths:
        full_path = os.path.join(base_path, command)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return full_path

    return None


def _ldap_authenticate(username, password):
    if not username or not password:
        return None, 'Credenciales incompletas'
    if Server is None or Connection is None:
        return None, 'LDAP no disponible (instala ldap3)'

    config = LDAPConfig.objects.filter(is_active=True).order_by('-is_default', '-updated_at').first()
    if not config:
        return None, 'LDAP deshabilitado'

    use_ssl = bool(config.use_ssl)
    tls = None
    if use_ssl or config.use_starttls:
        if config.cert_path:
            tls = Tls(
                ca_certs_file=config.cert_path,
                validate=ssl.CERT_REQUIRED,
                version=ssl.PROTOCOL_TLS_CLIENT,
            )
        else:
            tls = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLS_CLIENT)

    server = Server(config.servidor, port=int(config.puerto or 389), use_ssl=use_ssl, tls=tls, get_info=ALL)

    # Bind to search user (handle StartTLS before bind)
    try:
        conn = Connection(server, user=config.bind_dn or None, password=config.bind_password or None, auto_bind=False)
        conn.open()
        if config.use_starttls and not use_ssl:
            conn.start_tls()
        conn.bind()
    except Exception as exc:
        return None, f'LDAP bind fallido: {exc}'

    search_filter = (config.user_search_filter or '(uid={username})').replace('{username}', username)
    try:
        conn.search(
            search_base=config.user_search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[
                config.username_attr,
                config.first_name_attr,
                config.last_name_attr,
                config.email_attr,
            ],
        )
    except Exception as exc:
        return None, f'LDAP search fallido: {exc}'

    if not conn.entries:
        return None, 'Usuario LDAP no encontrado'

    entry = conn.entries[0]
    user_dn = entry.entry_dn

    # Bind as user to verify password
    try:
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=False)
        user_conn.open()
        if config.use_starttls and not use_ssl:
            user_conn.start_tls()
        user_conn.bind()
    except Exception:
        return None, 'Credenciales LDAP inválidas'

    # Map attributes
    def _get_attr(name, fallback=''):
        try:
            val = entry[name].value
            return val or fallback
        except Exception:
            return fallback

    mapped_username = _get_attr(config.username_attr, username) or username
    first_name = _get_attr(config.first_name_attr, '')
    last_name = _get_attr(config.last_name_attr, '')
    email = _get_attr(config.email_attr, '')

    user = User.objects.filter(username=mapped_username).first()
    if not user:
        if not config.auto_create_user:
            return None, 'Usuario no existe en el sistema'
        user = User.objects.create(
            username=mapped_username,
            first_name=first_name or '',
            last_name=last_name or '',
            email=email or '',
            is_active=True,
        )
        user.set_unusable_password()
        user.save(update_fields=['password'])
    else:
        updated = False
        if first_name and user.first_name != first_name:
            user.first_name = first_name
            updated = True
        if last_name and user.last_name != last_name:
            user.last_name = last_name
            updated = True
        if email and user.email != email:
            user.email = email
            updated = True
        if updated:
            user.save(update_fields=['first_name', 'last_name', 'email'])

    return user, None

# Vista principal del dashboard
@login_required
def dashboard_view(request):
    return render(request, 'dashboard.html')

# Vista de login
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = None
        ldap_error = None
        ldap_cfg = LDAPConfig.objects.filter(is_active=True).order_by('-is_default', '-updated_at').first()
        if ldap_cfg:
            user, ldap_error = _ldap_authenticate(username, password)
        if user is None:
            from django.contrib.auth import authenticate
            user = authenticate(request, username=username, password=password)
        
        if user is not None:
            # Verificar permiso de autenticación (excepción: superusuario)
            from .models import UserPermission
            if not user.is_superuser:
                has_login_perm = UserPermission.objects.filter(user=user, permission_type='CAN_LOGIN', granted=True).exists()
                if not has_login_perm:
                    messages.error(request, 'Tu cuenta no tiene permiso para autenticarse. Contacta a un administrador.')
                    return render(request, 'login.html')
            
            login(request, user)
            # Limpiar mensajes de errores de login anteriores
            storage = messages.get_messages(request)
            for _ in storage:
                pass  # Consumir los mensajes para limpiarlos
            # Log del login
            event_logger.log_event(
                user=user,
                event_type='LOGIN',
                description=f'Usuario {user.username} inició sesión',
                details={'ip_address': request.META.get('REMOTE_ADDR')}
            )
            return redirect('dashboard')
        else:
            # Log de intento de login fallido
            event_logger.log_event(
                user=None,
                event_type='LOGIN_FAILED',
                description=f'Intento de login fallido para usuario: {username}',
                details={'ip_address': request.META.get('REMOTE_ADDR')}
            )
            if ldap_cfg and ldap_error:
                messages.error(request, ldap_error)
            else:
                messages.error(request, 'Credenciales inválidas')
    
    return render(request, 'login.html')

# Vista de logout
def logout_view(request):
    user = request.user
    logout(request)
    # Log del logout
    event_logger.log_event(
        user=user,
        event_type='LOGOUT',
        description=f'Usuario {user.username if user.is_authenticated else "Anonymous"} cerró sesión'
    )
    return redirect('login')

# Vista para cambiar contrasena
@login_required
def password_change_view(request):
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        new_password1 = request.POST.get('new_password1')
        new_password2 = request.POST.get('new_password2')
        
        user = request.user
        
        # Verificar contrasena actual
        if not user.check_password(old_password):
            messages.error(request, 'La contrasena actual es incorrecta.')
            return render(request, 'password_change.html')
        
        # Verificar que las nuevas contrasenas coincidan
        if new_password1 != new_password2:
            messages.error(request, 'Las nuevas contrasenas no coinciden.')
            return render(request, 'password_change.html')
        
        # Verificar longitud minima
        if len(new_password1) < 8:
            messages.error(request, 'La contrasena debe tener al menos 8 caracteres.')
            return render(request, 'password_change.html')
        
        # Cambiar la contrasena
        user.set_password(new_password1)
        user.save()
        
        # Actualizar la sesion para mantener al usuario logueado
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, user)
        
        messages.success(request, 'Contrasena cambiada exitosamente.')
        return redirect('dashboard')
    
    return render(request, 'password_change.html')



# ==================== GESTIÓN DE USUARIOS ====================

@login_required
def user_management(request):
    """Vista principal de gestión de usuarios"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    users = User.objects.all().order_by('-date_joined')
    pending_requests = UserApprovalRequest.objects.filter(status='PENDING').order_by('-created_at')
    
    context = {
        'users': users,
        'pending_requests': pending_requests,
    }
    return render(request, 'user_management.html', context)

@login_required
def create_user_request(request):
    """Crear solicitud de nuevo usuario"""
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        password = request.POST.get('password')
        
        # Obtener permisos seleccionados
        selected_permissions = request.POST.getlist('permissions')
        
        # Verificar si el usuario ya existe
        if User.objects.filter(username=username).exists():
            messages.error(request, 'El nombre de usuario ya existe')
            return redirect('user-management')
        
        # Verificar si ya hay una solicitud pendiente
        if UserApprovalRequest.objects.filter(username=username, status='PENDING').exists():
            messages.error(request, 'Ya existe una solicitud pendiente para este usuario')
            return redirect('user-management')
        
        # Crear solicitud (sin is_staff ni is_superuser)
        user_request = UserApprovalRequest.objects.create(
            requested_by=request.user,
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=make_password(password),
            is_staff=False,  # Siempre False
            is_superuser=False  # Siempre False
        )
        
        # Guardar permisos solicitados en el campo details
        user_request.details = {
            'requested_permissions': selected_permissions
        }
        user_request.save()
        
        # Log del evento
        event_logger.log_event(
            user=request.user,
            event_type='USER_CREATE_REQUEST',
            description=f'Solicitud de creación de usuario: {username}',
            details={
                'requested_username': username,
                'requested_email': email,
                'requested_permissions': selected_permissions
            },
            target_model='UserApprovalRequest',
            target_id=user_request.id
        )
        
        messages.success(request, f'Solicitud de creación de usuario "{username}" enviada para aprobación')
        return redirect('user-management')
    
    return render(request, 'create_user_request.html')

@login_required
def approve_user_request(request, request_id):
    """Aprobar solicitud de usuario"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta acción')
        return redirect('user-management')
    
    user_request = get_object_or_404(UserApprovalRequest, id=request_id, status='PENDING')
    
    try:
        with transaction.atomic():
            # Aprobar y crear usuario
            new_user = user_request.approve(request.user)
            
            # Asegurar que el usuario esté activo para poder autenticarse
            if not new_user.is_active:
                new_user.is_active = True
                new_user.save(update_fields=['is_active'])
            
            # Crear preferencias de notificación por defecto
            NotificationPreference.objects.get_or_create(user=new_user)
            
            # Asignar permisos solicitados
            requested_permissions = user_request.details.get('requested_permissions', []) if user_request.details else []
            
            for perm_type in requested_permissions:
                UserPermission.objects.create(
                    user=new_user,
                    permission_type=perm_type,
                    granted=True,
                    granted_by=request.user
                )
            
            # Garantizar permiso mínimo para acceso a la aplicación
            if not UserPermission.objects.filter(user=new_user, permission_type='VIEW_DASHBOARD').exists():
                UserPermission.objects.create(
                    user=new_user,
                    permission_type='VIEW_DASHBOARD',
                    granted=True,
                    granted_by=request.user
                )
            
            # Log del evento
            event_logger.log_event(
                user=request.user,
                event_type='USER_APPROVED',
                description=f'Usuario {new_user.username} aprobado y creado',
                details={
                    'approved_username': new_user.username,
                    'approved_email': new_user.email,
                    'assigned_permissions': requested_permissions
                },
                target_model='User',
                target_id=new_user.id
            )
            
            # Enviar correo de notificación al usuario aprobado
            subject = f"VANT-SIEM - Cuenta de Usuario Aprobada"
            body = f"""
            <html>
            <body>
                <h2>¡Bienvenido a VANT-SIEM!</h2>
                <p>Hola {new_user.first_name},</p>
                <p>Tu solicitud de cuenta de usuario ha sido <strong>aprobada</strong> por {request.user.username}.</p>
                
                <h3>Detalles de tu cuenta:</h3>
                <ul>
                    <li><strong>Usuario:</strong> {new_user.username}</li>
                    <li><strong>Email:</strong> {new_user.email}</li>
                    <li><strong>Permisos asignados:</strong> {len(requested_permissions)} permisos específicos</li>
                </ul>
                
                <p>Ya puedes acceder al sistema con tus credenciales.</p>
                
                <hr>
                <p><em>VANT-SIEM - Sistema de Gestión de Incidentes de Seguridad</em></p>
            </body>
            </html>
            """
            
            send_user_alert(
                user=new_user,
                alert_type='USER_APPROVED',
                subject=subject,
                body=body,
                priority='HIGH'
            )
            
            messages.success(request, f'Usuario "{new_user.username}" aprobado y creado exitosamente con {len(requested_permissions)} permisos')
    
    except Exception as e:
        messages.error(request, f'Error al aprobar usuario: {str(e)}')
    
    return redirect('user-management')

@login_required
def reject_user_request(request, request_id):
    """Rechazar solicitud de usuario"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta acción')
        return redirect('user-management')
    
    user_request = get_object_or_404(UserApprovalRequest, id=request_id, status='PENDING')
    reason = request.POST.get('reason', '')
    
    user_request.reject(request.user, reason)
    
    # Log del evento
    event_logger.log_event(
        user=request.user,
        event_type='USER_REJECTED',
        description=f'Solicitud de usuario {user_request.username} rechazada',
        details={
            'rejected_username': user_request.username,
            'reason': reason
        },
        target_model='UserApprovalRequest',
        target_id=user_request.id
    )
    
    messages.success(request, f'Solicitud de usuario "{user_request.username}" rechazada')
    return redirect('user-management')

# ==================== GESTIÓN DE PERMISOS ====================

@login_required
def user_permissions(request, user_id):
    """Gestionar permisos de un usuario específico"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    user = get_object_or_404(User, id=user_id)
    permissions = UserPermission.objects.filter(user=user)
    
    # Crear permisos faltantes
    existing_permissions = set(perm.permission_type for perm in permissions)
    all_permission_types = [choice[0] for choice in UserPermission.PERMISSION_TYPES]
    
    for perm_type in all_permission_types:
        if perm_type not in existing_permissions:
            UserPermission.objects.create(
                user=user,
                permission_type=perm_type,
                granted=False
            )
    
    permissions = UserPermission.objects.filter(user=user).order_by('permission_type')
    
    context = {
        'target_user': user,
        'permissions': permissions,
    }
    return render(request, 'user_permissions.html', context)

@login_required
@require_http_methods(["POST"])
def update_user_permission(request, user_id, permission_id):
    """Actualizar un permiso específico de usuario"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    
    permission = get_object_or_404(UserPermission, id=permission_id, user_id=user_id)
    granted = request.POST.get('granted') == 'true'
    
    permission.granted = granted
    permission.granted_by = request.user
    permission.save()
    
    # Log del evento
    event_logger.log_event(
        user=request.user,
        event_type='PERMISSION_CHANGED',
        description=f'Permiso {permission.get_permission_type_display()} {"otorgado" if granted else "revocado"} a {permission.user.username}',
        details={
            'target_user': permission.user.username,
            'permission_type': permission.permission_type,
            'granted': granted
        },
        target_model='UserPermission',
        target_id=permission.id
    )
    
    return JsonResponse({'success': True})

# ==================== SISTEMA DE NOTIFICACIONES ====================

@login_required
def notifications(request):
    """Vista de notificaciones del usuario"""
    notifications = Notification.objects.filter(user=request.user).order_by('-created_at')
    
    context = {
        'notifications': notifications,
    }
    return render(request, 'notifications.html', context)

@login_required
@require_http_methods(["GET"])
def get_notifications(request):
    """API para obtener notificaciones no leídas"""
    unread_count = Notification.objects.filter(user=request.user, is_read=False).count()
    recent_notifications = Notification.objects.filter(user=request.user).order_by('-created_at')[:5]
    
    notifications_data = []
    for notification in recent_notifications:
        notifications_data.append({
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'event_type': notification.event_type,
            'is_read': notification.is_read,
            'created_at': notification.created_at.strftime('%d/%m/%Y %H:%M'),
        })
    
    return JsonResponse({
        'unread_count': unread_count,
        'notifications': notifications_data
    })

@login_required
@require_http_methods(["POST"])
def mark_notification_read(request, notification_id):
    """Marcar notificación como leída"""
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.mark_as_read()
    
    return JsonResponse({'success': True})

@login_required
@require_http_methods(["POST"])
def mark_all_notifications_read(request):
    """Marcar todas las notificaciones como leídas"""
    Notification.objects.filter(user=request.user, is_read=False).update(
        is_read=True,
        read_at=timezone.now()
    )
    
    return JsonResponse({'success': True})

# ==================== SISTEMA DE LOGS ====================

@login_required
def system_logs(request):
    """Vista de logs del sistema"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    # Obtener parámetros de filtrado
    event_type = request.GET.get('event_type', '')
    user_id = request.GET.get('user_id', '')
    limit = int(request.GET.get('limit', 100))
    
    # Obtener logs
    logs = event_logger.get_recent_events(limit)
    
    # Filtrar logs
    if event_type:
        logs = [log for log in logs if log['event_type'] == event_type]
    
    if user_id:
        logs = [log for log in logs if log['user']['id'] == int(user_id)]
    
    # Obtener usuarios para el filtro
    users = User.objects.all().order_by('username')
    
    # Obtener tipos de eventos únicos
    event_types = set()
    for log in event_logger.get_recent_events(1000):
        event_types.add(log['event_type'])
    event_types = sorted(list(event_types))
    
    context = {
        'logs': logs,
        'users': users,
        'event_types': event_types,
        'current_event_type': event_type,
        'current_user_id': user_id,
        'current_limit': limit,
    }
    return render(request, 'system_logs.html', context)

# ==================== CONTROL DEL SISTEMA DE LOGGING ====================

@login_required
def logging_control(request):
    """Vista para controlar el sistema de logging (solo superusuarios)"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    # Obtener estado actual del sistema
    status, message = event_logger.get_logging_status(request.user)
    
    context = {
        'logging_status': status,
        'status_message': message,
    }
    return render(request, 'logging_control.html', context)

@login_required
@require_http_methods(["POST"])
def start_logging_system(request):
    """Iniciar el sistema de logging"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos para realizar esta acción'})
    
    success, message = event_logger.start_logging(request.user)
    
    return JsonResponse({
        'success': success,
        'message': message
    })

@login_required
@require_http_methods(["POST"])
def stop_logging_system(request):
    """Detener el sistema de logging"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos para realizar esta acción'})
    
    success, message = event_logger.stop_logging(request.user)
    
    return JsonResponse({
        'success': success,
        'message': message
    })

@login_required
@require_http_methods(["GET"])
def get_logging_status_api(request):
    """API para obtener el estado del sistema de logging"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos para realizar esta acción'})
    
    status, message = event_logger.get_logging_status(request.user)
    
    return JsonResponse({
        'success': True,
        'status': status,
        'message': message
    })


# ==================== GESTIÓN DE CONFIGURACIÓN DE CORREO ====================

@login_required
def email_configuration(request):
    """Gestión de configuración de correo"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    configs = EmailConfiguration.objects.all()
    active_config = configs.filter(is_active=True).first()
    
    context = {
        'configs': configs,
        'active_config': active_config,
    }
    return render(request, 'email_configuration.html', context)

@login_required
def create_email_config(request):
    """Crear nueva configuración de correo"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta acción')
        return redirect('email-configuration')
    
    if request.method == 'POST':
        name = request.POST.get('name')
        smtp_server = request.POST.get('smtp_server')
        smtp_port = int(request.POST.get('smtp_port', 587))
        use_tls = request.POST.get('use_tls') == 'on'
        use_ssl = request.POST.get('use_ssl') == 'on'
        username = request.POST.get('username')
        password = request.POST.get('password')
        from_email = request.POST.get('from_email')
        from_name = request.POST.get('from_name', 'VANT-SIEM')
        is_active = request.POST.get('is_active') == 'on'
        
        # Si se marca como activa, desactivar las demás
        if is_active:
            EmailConfiguration.objects.filter(is_active=True).update(is_active=False)
        
        try:
            config = EmailConfiguration.objects.create(
                name=name,
                smtp_server=smtp_server,
                smtp_port=smtp_port,
                use_tls=use_tls,
                use_ssl=use_ssl,
                username=username,
                password=password,
                from_email=from_email,
                from_name=from_name,
                is_active=is_active,
                created_by=request.user
            )
            
            # Log del evento
            event_logger.log_event(
                user=request.user,
                event_type='EMAIL_CONFIG_CREATED',
                description=f'Configuración de correo creada: {name}',
                details={
                    'config_name': name,
                    'smtp_server': smtp_server,
                    'from_email': from_email,
                    'is_active': is_active
                },
                target_model='EmailConfiguration',
                target_id=config.id
            )
            
            messages.success(request, f'Configuración de correo "{name}" creada exitosamente')
            return redirect('email-configuration')
            
        except Exception as e:
            messages.error(request, f'Error al crear configuración: {str(e)}')
    
    return render(request, 'create_email_config.html')

@login_required
@require_http_methods(["POST"])
def activate_email_config(request, config_id):
    """Activar una configuración de correo"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    
    config = get_object_or_404(EmailConfiguration, id=config_id)
    
    try:
        # Desactivar todas las configuraciones
        EmailConfiguration.objects.filter(is_active=True).update(is_active=False)
        
        # Activar la seleccionada
        config.is_active = True
        config.save()
        
        # Log del evento
        event_logger.log_event(
            user=request.user,
            event_type='EMAIL_CONFIG_ACTIVATED',
            description=f'Configuración de correo activada: {config.name}',
            details={'config_name': config.name},
            target_model='EmailConfiguration',
            target_id=config.id
        )
        
        return JsonResponse({'success': True, 'message': f'Configuración "{config.name}" activada'})
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def edit_email_config(request, config_id):
    """Editar una configuración de correo existente"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para realizar esta acción')
        return redirect('email-configuration')
    
    config = get_object_or_404(EmailConfiguration, id=config_id)
    
    if request.method == 'POST':
        name = request.POST.get('name')
        smtp_server = request.POST.get('smtp_server')
        smtp_port = int(request.POST.get('smtp_port', config.smtp_port or 587))
        use_tls = request.POST.get('use_tls') == 'on'
        use_ssl = request.POST.get('use_ssl') == 'on'
        username = request.POST.get('username')
        password = request.POST.get('password') or config.password
        from_email = request.POST.get('from_email')
        from_name = request.POST.get('from_name', config.from_name or 'VANT-SIEM')
        is_active = request.POST.get('is_active') == 'on'
        
        # Si se marca como activa, desactivar las demás
        if is_active:
            EmailConfiguration.objects.exclude(id=config.id).filter(is_active=True).update(is_active=False)
        
        try:
            config.name = name
            config.smtp_server = smtp_server
            config.smtp_port = smtp_port
            config.use_tls = use_tls
            config.use_ssl = use_ssl
            config.username = username
            config.password = password
            config.from_email = from_email
            config.from_name = from_name
            config.is_active = is_active
            config.save()
            
            # Log del evento
            event_logger.log_event(
                user=request.user,
                event_type='EMAIL_CONFIG_UPDATED',
                description=f'Configuración de correo actualizada: {name}',
                details={
                    'config_name': name,
                    'smtp_server': smtp_server,
                    'from_email': from_email,
                    'is_active': is_active
                },
                target_model='EmailConfiguration',
                target_id=config.id
            )
            
            messages.success(request, f'Configuración de correo "{name}" actualizada exitosamente')
            return redirect('email-configuration')
        except Exception as e:
            messages.error(request, f'Error al actualizar configuración: {str(e)}')
    
    context = {
        'config': config,
    }
    return render(request, 'edit_email_config.html', context)


# ==================== GESTIÓN DE ALERTAS POR CORREO ====================

@login_required
def email_alerts_management(request):
    """Gestión de alertas por correo para usuarios"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    users = User.objects.filter(is_active=True).order_by('username')
    alert_types = EmailAlert.ALERT_TYPES
    
    # Obtener alertas existentes
    alerts = EmailAlert.objects.select_related('user').order_by('user__username', 'alert_type')
    
    context = {
        'users': users,
        'alert_types': alert_types,
        'alerts': alerts,
    }
    return render(request, 'email_alerts_management.html', context)

@login_required
@require_http_methods(["POST"])
def update_email_alert(request):
    """Actualizar configuración de alerta por correo"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    
    user_id = request.POST.get('user_id')
    alert_type = request.POST.get('alert_type')
    enabled = request.POST.get('enabled') == 'true'
    priority = request.POST.get('priority', 'MEDIUM')
    send_immediately = request.POST.get('send_immediately') == 'true'
    send_daily_summary = request.POST.get('send_daily_summary') == 'true'
    send_weekly_summary = request.POST.get('send_weekly_summary') == 'true'
    
    user = get_object_or_404(User, id=user_id)
    
    try:
        alert, created = EmailAlert.objects.get_or_create(
            user=user,
            alert_type=alert_type,
            defaults={
                'priority': priority,
                'enabled': enabled,
                'send_immediately': send_immediately,
                'send_daily_summary': send_daily_summary,
                'send_weekly_summary': send_weekly_summary,
            }
        )
        
        if not created:
            alert.enabled = enabled
            alert.priority = priority
            alert.send_immediately = send_immediately
            alert.send_daily_summary = send_daily_summary
            alert.send_weekly_summary = send_weekly_summary
            alert.save()
        
        # Log del evento
        event_logger.log_event(
            user=request.user,
            event_type='EMAIL_ALERT_UPDATED',
            description=f'Alerta de correo actualizada para {user.username}',
            details={
                'target_user': user.username,
                'alert_type': alert_type,
                'enabled': enabled,
                'priority': priority
            },
            target_model='EmailAlert',
            target_id=alert.id
        )
        
        action = 'creada' if created else 'actualizada'
        return JsonResponse({
            'success': True, 
            'message': f'Alerta {action} exitosamente para {user.username}'
        })
        
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def email_logs(request):
    """Visualizar logs de correos enviados"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    # Filtros
    status_filter = request.GET.get('status', '')
    alert_type_filter = request.GET.get('alert_type', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    
    logs = EmailLog.objects.select_related('to_user').all()
    
    if status_filter:
        logs = logs.filter(status=status_filter)
    if alert_type_filter:
        logs = logs.filter(alert_type=alert_type_filter)
    if date_from:
        logs = logs.filter(created_at__date__gte=date_from)
    if date_to:
        logs = logs.filter(created_at__date__lte=date_to)
    
    # Paginación
    from django.core.paginator import Paginator
    paginator = Paginator(logs, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'status_choices': EmailLog.STATUS_CHOICES,
        'alert_type_choices': EmailAlert.ALERT_TYPES,
        'current_filters': {
            'status': status_filter,
            'alert_type': alert_type_filter,
            'date_from': date_from,
            'date_to': date_to,
        }
    }
    return render(request, 'email_logs.html', context)

@login_required
@require_http_methods(["POST"])
def test_email_config(request, config_id):
    """Probar una configuración de correo"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    
    try:
        from .email_service import email_service
        success, message = email_service.test_configuration(config_id)
        
        return JsonResponse({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        })

@login_required
@require_http_methods(["GET"])
def get_user_email_alerts(request):
    """Obtener configuración de alertas por correo para un usuario"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    
    user_id = request.GET.get('user_id')
    if not user_id:
        return JsonResponse({'success': False, 'error': 'user_id requerido'})
    
    user = get_object_or_404(User, id=user_id)
    # Mapear alertas existentes por tipo
    existing = {a.alert_type: a for a in EmailAlert.objects.filter(user=user)}
    
    alerts = []
    for value, label in EmailAlert.ALERT_TYPES:
        alert = existing.get(value)
        alerts.append({
            'alert_type': value,
            'label': label,
            'enabled': bool(alert.enabled) if alert else False,
            'priority': alert.priority if alert else 'MEDIUM',
            'send_immediately': bool(alert.send_immediately) if alert else True,
            'send_daily_summary': bool(alert.send_daily_summary) if alert else False,
            'send_weekly_summary': bool(alert.send_weekly_summary) if alert else False,
        })
    
    return JsonResponse({'success': True, 'alerts': alerts})

@login_required
def analysis_ip_view(request):
    return render(request, 'analysis_ip.html')

@login_required
def analysis_indicator_view(request):
    return render(request, 'analysis_indicator.html')

@login_required
def analysis_mac_view(request):
    return render(request, 'analysis_mac.html')

# persist in analyze_ip
@login_required
@require_POST
def analyze_ip(request):
    ip = request.POST.get('ip', '').strip()
    if not ip:
        return JsonResponse({'success': False, 'error': 'IP requerida'})
    from .models import AnalysisAPIConfig, AbuseIPDBAnalysisRecord
    cfg = AnalysisAPIConfig.objects.filter(is_active=True).first()
    if not cfg or not cfg.abuseipdb_api_key:
        return JsonResponse({'success': False, 'error': 'API de AbuseIPDB no configurada'})
    try:
        resp = requests.get('https://api.abuseipdb.com/api/v2/check', params={'ipAddress': ip, 'maxAgeInDays': 90}, headers={'Key': cfg.abuseipdb_api_key, 'Accept': 'application/json'}, timeout=15)
        status = resp.status_code

        # Try to parse JSON response
        try:
            data = resp.json()
        except ValueError:
            # If response is not JSON, create error data
            data = {'error': f'API returned non-JSON response (status {status})', 'response_text': resp.text[:500]}

        # Save record
        try:
            AbuseIPDBAnalysisRecord.objects.create(ip_address=ip, status_code=status, result=data, requested_by=request.user)
        except Exception as save_error:
            # Log save error but don't fail the request
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to save AbuseIPDB record: {save_error}")

        # Return success only for 200 status
        if status == 200:
            return JsonResponse({'success': True, 'data': data})
        else:
            # Return error with API response data
            error_msg = data.get('error', {}).get('message', f'API returned status {status}')
            return JsonResponse({'success': False, 'error': error_msg, 'data': data})

    except requests.exceptions.Timeout:
        return JsonResponse({'success': False, 'error': 'Timeout al conectar con AbuseIPDB'})
    except requests.exceptions.RequestException as e:
        return JsonResponse({'success': False, 'error': f'Error de conexión: {str(e)}'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error interno: {str(e)}'})

# persist in analyze_indicator
@login_required
@require_POST
def analyze_indicator(request):
    indicator = request.POST.get('indicator', '').strip()
    if not indicator:
        return JsonResponse({'success': False, 'error': 'Indicador requerido'})
    from .models import AnalysisAPIConfig, VTAnalysisRecord
    cfg = AnalysisAPIConfig.objects.filter(is_active=True).first()
    if not cfg or not cfg.virustotal_api_key:
        return JsonResponse({'success': False, 'error': 'API de VirusTotal no configurada'})
    try:
        headers = {'x-apikey': cfg.virustotal_api_key, 'Accept': 'application/json', 'User-Agent': 'VANT-SIEM/1.0 (+email: admin@example.com)'}
        indicator_type = 'domain'
        # Determinar tipo básico y construir endpoint
        if '://' in indicator or ('/' in indicator and '.' in indicator):
            # URL: VT requiere ID base64 urlsafe sin '='
            import base64
            indicator_type = 'url'
            url_id = base64.urlsafe_b64encode(indicator.encode('utf-8')).decode('utf-8').strip('=')
            vt_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        elif len(indicator) in (32, 40, 64):
            indicator_type = 'file'
            vt_url = f'https://www.virustotal.com/api/v3/files/{indicator}'
        else:
            vt_url = f'https://www.virustotal.com/api/v3/domains/{indicator}'

        resp = requests.get(vt_url, headers=headers, timeout=15)
        status = resp.status_code

        # Try to parse JSON response
        try:
            data = resp.json()
        except ValueError:
            # If response is not JSON, create error data
            data = {'error': f'API returned non-JSON response (status {status})', 'response_text': resp.text[:500]}

        # Save record
        try:
            VTAnalysisRecord.objects.create(indicator=indicator, indicator_type=indicator_type, status_code=status, result=data, requested_by=request.user)
        except Exception as save_error:
            # Log save error but don't fail the request
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to save VT record: {save_error}")

        if status == 200:
            return JsonResponse({'success': True, 'data': data})
        else:
            # Return error with API response data
            vt_error = data.get('error', {}) if isinstance(data, dict) else {}
            vt_msg = vt_error.get('message') or f'HTTP {status}'
            return JsonResponse({'success': False, 'error': vt_msg, 'data': data})

    except requests.exceptions.Timeout:
        return JsonResponse({'success': False, 'error': 'Timeout al conectar con VirusTotal'})
    except requests.exceptions.RequestException as e:
        return JsonResponse({'success': False, 'error': f'Error de conexión: {str(e)}'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error interno: {str(e)}'})

# persist in analyze_mac
@login_required
@require_POST
def analyze_mac(request):
    mac = request.POST.get('mac', '').strip()
    if not mac:
        return JsonResponse({'success': False, 'error': 'MAC requerida'})
    from .models import AnalysisAPIConfig, MacVendorsAnalysisRecord
    cfg = AnalysisAPIConfig.objects.filter(is_active=True).first()
    api_key = cfg.macvendors_api_key if cfg else ''
    try:
        url = f'https://api.macvendors.com/{mac}'
        resp = requests.get(url, timeout=10)
        status = resp.status_code

        if status == 200:
            vendor = resp.text.strip()
            data = {'vendor': vendor}
        else:
            data = {'error': f'HTTP {status}', 'response_text': resp.text[:200]}

        # Save record
        try:
            MacVendorsAnalysisRecord.objects.create(mac_address=mac, vendor=(vendor if status==200 else ''), status_code=status, result=data, requested_by=request.user)
        except Exception as save_error:
            # Log save error but don't fail the request
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to save MacVendors record: {save_error}")

        if status == 200:
            return JsonResponse({'success': True, 'data': data})
        else:
            return JsonResponse({'success': False, 'error': f'HTTP {status}: {resp.text[:100] if resp.text else "No response"}'})

    except requests.exceptions.Timeout:
        return JsonResponse({'success': False, 'error': 'Timeout al conectar con MacVendors'})
    except requests.exceptions.RequestException as e:
        return JsonResponse({'success': False, 'error': f'Error de conexión: {str(e)}'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Error interno: {str(e)}'})

# Internal listings
@login_required
def analysis_internal_vt(request):
    from .models import VTAnalysisRecord
    qs = VTAnalysisRecord.objects.all()
    p = Paginator(qs, 25)
    page = p.get_page(request.GET.get('page'))
    return render(request, 'analysis_internal_vt.html', {'page_obj': page})

@login_required
def analysis_internal_abuseipdb(request):
    from .models import AbuseIPDBAnalysisRecord
    qs = AbuseIPDBAnalysisRecord.objects.all()
    p = Paginator(qs, 25)
    page = p.get_page(request.GET.get('page'))
    return render(request, 'analysis_internal_abuseipdb.html', {'page_obj': page})

@login_required
def analysis_internal_macvendors(request):
    from .models import MacVendorsAnalysisRecord
    qs = MacVendorsAnalysisRecord.objects.all()
    p = Paginator(qs, 25)
    page = p.get_page(request.GET.get('page'))
    return render(request, 'analysis_internal_macvendors.html', {'page_obj': page})

@login_required
def analysis_internal_vt_detail(request, pk):
    from .models import VTAnalysisRecord
    rec = get_object_or_404(VTAnalysisRecord, pk=pk)
    return render(request, 'analysis_internal_vt_detail.html', {'rec': rec})

@login_required
def analysis_internal_abuseipdb_detail(request, pk):
    from .models import AbuseIPDBAnalysisRecord
    rec = get_object_or_404(AbuseIPDBAnalysisRecord, pk=pk)
    return render(request, 'analysis_internal_abuseipdb_detail.html', {'rec': rec})

@login_required
def analysis_internal_macvendors_detail(request, pk):
    from .models import MacVendorsAnalysisRecord
    rec = get_object_or_404(MacVendorsAnalysisRecord, pk=pk)
    return render(request, 'analysis_internal_macvendors_detail.html', {'rec': rec})

@login_required
@require_GET
def analysis_config(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    from .models import AnalysisAPIConfig
    cfg = AnalysisAPIConfig.objects.first()
    return render(request, 'analysis_config.html', {'cfg': cfg})

@login_required
@require_POST
def analysis_config_save(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    from .models import AnalysisAPIConfig
    cfg, _ = AnalysisAPIConfig.objects.get_or_create(id=1, defaults={'created_by': request.user})
    cfg.virustotal_api_key = request.POST.get('virustotal_api_key', '').strip()
    cfg.abuseipdb_api_key = request.POST.get('abuseipdb_api_key', '').strip()
    cfg.macvendors_api_key = request.POST.get('macvendors_api_key', '').strip()
    cfg.is_active = True
    cfg.save()
    return JsonResponse({'success': True, 'message': 'APIs guardadas'})

@login_required
@require_GET
def analysis_services_hub(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    from .models import AnalysisAPIConfig
    cfg = AnalysisAPIConfig.objects.first()
    return render(request, 'analysis_services_hub.html', {'cfg': cfg})

@login_required
@require_GET
def virustotal_config(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    from .models import AnalysisAPIConfig
    cfg = AnalysisAPIConfig.objects.first()
    return render(request, 'config_virustotal.html', {'cfg': cfg})

@login_required
@require_POST
def virustotal_config_save(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    from .models import AnalysisAPIConfig
    cfg, _ = AnalysisAPIConfig.objects.get_or_create(id=1, defaults={'created_by': request.user})
    cfg.virustotal_api_key = request.POST.get('virustotal_api_key', '').strip()
    cfg.save(update_fields=['virustotal_api_key'])
    return JsonResponse({'success': True})

@login_required
@require_POST
def virustotal_test(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    from .models import AnalysisAPIConfig
    cfg = AnalysisAPIConfig.objects.first()
    if not cfg or not cfg.virustotal_api_key:
        return JsonResponse({'success': False, 'error': 'API key no configurada'})
    try:
        headers = {'x-apikey': cfg.virustotal_api_key}
        resp = requests.get('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', headers=headers, timeout=10)
        ok = resp.status_code in (200, 401, 403)
        return JsonResponse({'success': ok, 'status': resp.status_code})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_GET
def abuseipdb_config(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    from .models import AnalysisAPIConfig
    cfg = AnalysisAPIConfig.objects.first()
    return render(request, 'config_abuseipdb.html', {'cfg': cfg})

@login_required
@require_POST
def abuseipdb_config_save(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    from .models import AnalysisAPIConfig
    cfg, _ = AnalysisAPIConfig.objects.get_or_create(id=1, defaults={'created_by': request.user})
    cfg.abuseipdb_api_key = request.POST.get('abuseipdb_api_key', '').strip()
    cfg.save(update_fields=['abuseipdb_api_key'])
    return JsonResponse({'success': True})

@login_required
@require_POST
def abuseipdb_test(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    from .models import AnalysisAPIConfig
    cfg = AnalysisAPIConfig.objects.first()
    if not cfg or not cfg.abuseipdb_api_key:
        return JsonResponse({'success': False, 'error': 'API key no configurada'})
    try:
        resp = requests.get('https://api.abuseipdb.com/api/v2/check', params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 1}, headers={'Key': cfg.abuseipdb_api_key, 'Accept': 'application/json'}, timeout=10)
        ok = resp.status_code in (200, 401, 403)
        return JsonResponse({'success': ok, 'status': resp.status_code})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_GET
def macvendors_config(request):
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    from .models import AnalysisAPIConfig
    cfg = AnalysisAPIConfig.objects.first()
    return render(request, 'config_macvendors.html', {'cfg': cfg})

@login_required
@require_POST
def macvendors_config_save(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    from .models import AnalysisAPIConfig
    cfg, _ = AnalysisAPIConfig.objects.get_or_create(id=1, defaults={'created_by': request.user})
    cfg.macvendors_api_key = request.POST.get('macvendors_api_key', '').strip()
    cfg.save(update_fields=['macvendors_api_key'])
    return JsonResponse({'success': True})

@login_required
@require_POST
def macvendors_test(request):
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})
    try:
        resp = requests.get('https://api.macvendors.com/44:38:39:ff:ef:57', timeout=10)
        ok = resp.status_code in (200, 400, 404)
        return JsonResponse({'success': ok, 'status': resp.status_code})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def save_vt_record(request):
    payload = request.POST
    indicator = (payload.get('indicator') or '').strip()
    indicator_type = (payload.get('indicator_type') or '').strip()
    data = payload.get('data')
    if not indicator or data is None:
        try:
            import json as _json
            payload = _json.loads(request.body.decode('utf-8')) if request.body else {}
            indicator = (payload.get('indicator') or '').strip()
            indicator_type = (payload.get('indicator_type') or '').strip()
            data = payload.get('data')
        except Exception:
            pass
    if not indicator or data is None:
        return JsonResponse({'success': False, 'error': 'Datos incompletos'})
    try:
        if isinstance(data, str):
            import json as _json
            data = _json.loads(data)
        from .models import VTAnalysisRecord
        VTAnalysisRecord.objects.create(indicator=indicator, indicator_type=indicator_type, status_code=int(payload.get('status_code') or 200), result=data, requested_by=request.user)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def save_abuseipdb_record(request):
    payload = request.POST
    ip = (payload.get('ip') or '').strip()
    data = payload.get('data')
    if not ip or data is None:
        try:
            import json as _json
            payload = _json.loads(request.body.decode('utf-8')) if request.body else {}
            ip = (payload.get('ip') or '').strip()
            data = payload.get('data')
        except Exception:
            pass
    if not ip or data is None:
        return JsonResponse({'success': False, 'error': 'Datos incompletos'})
    try:
        if isinstance(data, str):
            import json as _json
            data = _json.loads(data)
        from .models import AbuseIPDBAnalysisRecord
        AbuseIPDBAnalysisRecord.objects.create(ip_address=ip, status_code=int(payload.get('status_code') or 200), result=data, requested_by=request.user)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def save_macvendors_record(request):
    payload = request.POST
    mac = (payload.get('mac') or '').strip()
    vendor = (payload.get('vendor') or '').strip()
    data = payload.get('data')
    if not mac or data is None:
        try:
            import json as _json
            payload = _json.loads(request.body.decode('utf-8')) if request.body else {}
            mac = (payload.get('mac') or '').strip()
            vendor = (payload.get('vendor') or '').strip()
            data = payload.get('data')
        except Exception:
            pass
    if not mac or data is None:
        return JsonResponse({'success': False, 'error': 'Datos incompletos'})
    try:
        if isinstance(data, str):
            import json as _json
            data = _json.loads(data)
        from .models import MacVendorsAnalysisRecord
        MacVendorsAnalysisRecord.objects.create(mac_address=mac, vendor=vendor, status_code=int(payload.get('status_code') or 200), result=data, requested_by=request.user)
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# ==================== CHAT CON IA ====================

def _generate_fallback_response(message, specific_data, context_parts):
    """Genera respuesta de respaldo cuando Ollama no está disponible"""
    message_lower = message.lower()

    # Detectar tipo de consulta y responder basado en datos específicos
    if ('reporte' in message_lower or 'reportes' in message_lower) and any(word in message_lower for word in ['nuevo', 'nuevos', 'reciente', 'recientes', 'revisa']):
        if 'recent_reports' in specific_data and specific_data['recent_reports']:
            reports = specific_data['recent_reports']
            response = f"📋 Encontré {len(reports)} reportes recientes:\n\n"
            for i, report in enumerate(reports[:5], 1):
                response += f"{i}. **{report['titulo']}** - {report['estado']} ({report['fecha']})\n"
            if len(reports) > 5:
                response += f"... y {len(reports) - 5} más.\n"
            response += "\n💡 Recomendación: Revisar estos reportes prioritarios."
        else:
            response = "📋 No hay reportes recientes en los últimos 7 días."

    elif ('incidente' in message_lower or 'incidentes' in message_lower) and any(word in message_lower for word in ['nuevo', 'nuevos', 'reciente', 'recientes', 'activo', 'activos']):
        if 'incidents' in specific_data and specific_data['incidents']:
            incidents = specific_data['incidents']
            response = f"🚨 Encontré {len(incidents)} incidentes recientes/activos:\n\n"
            for i, incident in enumerate(incidents[:5], 1):
                response += f"{i}. **{incident['titulo']}** - {incident['estado']} ({incident['fecha']})\n"
            if len(incidents) > 5:
                response += f"... y {len(incidents) - 5} más.\n"
            response += "\n⚠️ Monitorear especialmente los incidentes recientes."
        else:
            response = "🚨 No hay incidentes recientes o activos."

    elif any(word in message_lower for word in ['amenaza', 'amenazas', 'alerta', 'alertas', 'ataque', 'ataques', 'intrusion']):
        if 'critical_alerts' in specific_data and specific_data['critical_alerts']:
            alerts = specific_data['critical_alerts']
            response = f"⚠️ Alertas críticas detectadas ({len(alerts)}):\n\n"
            for i, alert in enumerate(alerts, 1):
                response += f"{i}. {alert['mensaje']} - {alert['timestamp']}\n"
            response += "\n🔍 Revisar logs detallados inmediatamente."
        else:
            # Verificar si hay alguna actividad de IDS en general
            total_alerts = IDSAlert.objects.all().count()
            total_snort = SnortLog.objects.all().count()
            total_suricata = SuricataEveAlert.objects.all().count()

            if total_alerts > 0 or total_snort > 0 or total_suricata > 0:
                response = f"📊 Sistema operativo. Encontré datos históricos:\n"
                response += f"• Alertas IDS totales: {total_alerts}\n"
                response += f"• Logs Snort: {total_snort}\n"
                response += f"• Logs Suricata: {total_suricata}\n"
                response += "\n💡 No hay actividad reciente, pero el sistema tiene datos históricos."
            else:
                response = "⚠️ No se detectaron alertas o actividad de IDS/IPS."

    elif any(phrase in message_lower for phrase in ['estado del sistema', 'que esta pasando', 'qué está pasando', 'como esta', 'cómo está']):
        response = "📊 Estado del sistema VANT-SIEM:\n\n"
        for part in context_parts:
            if 'CONTEXTO ACTUAL DEL SISTEMA:' in part:
                system_info = part.split('CONTEXTO ACTUAL DEL SISTEMA:')[1].strip()
                response += system_info + "\n\n"
                break
        response += "✅ Sistema operativo monitoreando la red."

    else:
        # Verificar qué datos están disponibles en el sistema
        total_alerts = IDSAlert.objects.all().count()
        total_snort = SnortLog.objects.all().count()
        total_suricata = SuricataEveAlert.objects.all().count()
        total_reportes = Reporte.objects.all().count()
        total_incidentes = Incidente.objects.all().count()

        # Verificar datos recientes (últimas 24 horas)
        last_24h = timezone.now() - timezone.timedelta(hours=24)
        recent_alerts = IDSAlert.objects.filter(timestamp__gte=last_24h).count()
        recent_snort = SnortLog.objects.filter(timestamp__gte=last_24h).count()
        recent_suricata = SuricataEveAlert.objects.filter(timestamp__gte=last_24h).count()

        response = "🤖 VANT-IA: Sistema operativo - Análisis automático disponible\n\n"
        response += f"📊 **Estado de datos en el sistema:**\n"
        response += f"• Alertas IDS totales: {total_alerts} ({recent_alerts} últimas 24h)\n"
        response += f"• Logs Snort totales: {total_snort} ({recent_snort} últimas 24h)\n"
        response += f"• Logs Suricata totales: {total_suricata} ({recent_suricata} últimas 24h)\n"
        response += f"• Reportes: {total_reportes}\n"
        response += f"• Incidentes: {total_incidentes}\n\n"

        # Evaluar disponibilidad de datos
        has_recent_data = (recent_alerts > 0 or recent_snort > 0 or recent_suricata > 0)
        has_any_data = (total_alerts > 0 or total_snort > 0 or total_suricata > 0)

        if has_recent_data:
            response += "✅ **Sistema con datos de seguridad recientes**\n"
            response += "💡 **Consultas disponibles:**\n"
            response += "• 'analizar alertas recientes' - Ver amenazas activas\n"
            response += "• 'ver reportes nuevos' - Consultar reportes recientes\n"
            response += "• 'estado del sistema' - Resumen general\n"
            response += "• 'incidentes activos' - Gestionar incidentes\n"
        elif has_any_data:
            response += "⚠️ **Sistema con datos históricos, pero sin actividad reciente**\n"
            response += "💡 **Consultas disponibles:**\n"
            response += "• 'analizar alertas' - Revisar datos históricos\n"
            response += "• 'ver reportes' - Consultar reportes existentes\n"
            response += "• 'estado del sistema' - Resumen general\n"
        else:
            response += "🔄 **Sistema esperando datos de IDS/IPS**\n"
            response += "💡 **Para comenzar:**\n"
            response += "• Configure la ingesta de logs de Snort y Suricata\n"
            response += "• Verifique que los servicios IDS estén ejecutándose\n"
            response += "• Revise la configuración de parsers en ids_ingest\n"

        response += "\n🔄 **Nota:** IA completa disponible cuando se restaure conexión con Ollama."

    return response


@csrf_exempt
@login_required
@require_POST
def ollama_chat(request):
    """Endpoint para chat con IA usando Ollama"""
    try:
        # Debug logging
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Chat request received. User authenticated: {request.user.is_authenticated}")
        if request.user.is_authenticated:
            logger.info(f"User: {request.user.username} (ID: {request.user.id})")
        else:
            logger.warning("Request received but user not authenticated")
            return JsonResponse({'success': False, 'error': 'Usuario no autenticado'})

        data = json.loads(request.body)
        message = data.get('message', '').strip()
        history = data.get('history', [])

        logger.info(f"Chat message: '{message}' (length: {len(message)})")
        logger.info(f"Chat history length: {len(history)}")

        if not message:
            logger.warning("Empty message received")
            return JsonResponse({'success': False, 'error': 'Mensaje requerido'})

        # Verificar permisos de configuración
        from .ollama_service import ollama_service
        if not ollama_service.can_read_snort_logs and not ollama_service.can_read_suricata_logs:
            return JsonResponse({
                'success': False,
                'error': 'No tienes permisos para acceder a datos de logs'
            })

        # Construir contexto dinámico basado en datos disponibles
        context_parts = []
        specific_data = {}

        try:
            # Estadísticas de seguridad actuales
            from opensearch_ui.models import IDSAlert, SnortLog, SuricataEveAlert
            from EVENT_M.models import Reporte, Incidente
            from django.utils import timezone
            from django.db.models import Count

            now = timezone.now()
            last_hour = now - timezone.timedelta(hours=1)
            last_24h = now - timezone.timedelta(hours=24)
            last_7d = now - timezone.timedelta(days=7)  # Más amplio para encontrar datos

            # Alertas recientes (última hora, si no hay, buscar en últimas 24h)
            recent_alerts = IDSAlert.objects.filter(timestamp__gte=last_hour).count()
            if recent_alerts == 0:
                recent_alerts = IDSAlert.objects.filter(timestamp__gte=last_24h).count()

            critical_alerts = IDSAlert.objects.filter(
                timestamp__gte=last_hour, severity='Critical'
            ).count()
            if critical_alerts == 0:
                critical_alerts = IDSAlert.objects.filter(
                    timestamp__gte=last_24h, severity='Critical'
                ).count()

            # Actividad de logs (última hora, si no hay, buscar en últimas 24h)
            snort_logs_hour = SnortLog.objects.filter(timestamp__gte=last_hour).count()
            if snort_logs_hour == 0:
                snort_logs_hour = SnortLog.objects.filter(timestamp__gte=last_24h).count()

            suricata_logs_hour = SuricataEveAlert.objects.filter(timestamp__gte=last_hour).count()
            if suricata_logs_hour == 0:
                suricata_logs_hour = SuricataEveAlert.objects.filter(timestamp__gte=last_24h).count()

            # Top amenazas recientes (si no hay en 24h, buscar en 7 días)
            top_threats = list(
                IDSAlert.objects.filter(timestamp__gte=last_24h)
                .values('message')
                .annotate(count=Count('id'))
                .order_by('-count')[:3]
            )
            if not top_threats:
                top_threats = list(
                    IDSAlert.objects.filter(timestamp__gte=last_7d)
                    .values('message')
                    .annotate(count=Count('id'))
                    .order_by('-count')[:3]
                )

            # Consultas específicas basadas en el mensaje del usuario
            message_lower = message.lower()

            # Si pregunta por reportes
            if 'reporte' in message_lower or 'reportes' in message_lower:
                try:
                    # Obtener TODOS los reportes para análisis completo
                    all_reports = Reporte.objects.all().order_by('-fecha_hora')[:50]

                    if all_reports.exists():
                        reports_data = []
                        for report in all_reports:
                            reports_data.append({
                                'id': report.id,
                                'titulo': report.nombre_informante,
                                'descripcion': report.descripcion or 'Sin descripción',
                                'estado': report.estado_solucion,
                                'area': report.area.nombre if report.area else 'Sin área',
                                'categoria': report.categoria.nombre if report.categoria else 'Sin categoría',
                                'responsable': report.responsable.nombre if report.responsable else 'Sin asignar',
                                'fecha': report.fecha_hora.strftime('%d/%m/%Y %H:%M'),
                                'dias_antiguedad': (now.date() - report.fecha_hora.date()).days
                            })

                        specific_data['all_reports'] = reports_data
                        specific_data['recent_reports'] = [r for r in reports_data if r['dias_antiguedad'] <= 7]

                        # Mostrar resumen completo
                        total_reports = len(reports_data)
                        recent_count = len(specific_data['recent_reports'])
                        context_parts.append(f"""
REPORTES EN SISTEMA:
- Total de reportes: {total_reports}
- Reportes recientes (últimos 7 días): {recent_count}
- Estados: {', '.join(set([r['estado'] for r in reports_data[:10]]))}

DETALLES DE REPORTES MÁS RECIENTES:
{chr(10).join([f"- ID {r['id']}: {r['titulo']} | Estado: {r['estado']} | Área: {r['area']} | {r['fecha']}" for r in reports_data[:10]])}""")
                    else:
                        context_parts.append("\nNo se encontraron reportes en el sistema.")
                except Exception as e:
                    context_parts.append(f"\nError consultando reportes: {str(e)}")

            # Si pregunta por incidentes
            elif 'incidente' in message_lower or 'incidentes' in message_lower:
                try:
                    # Obtener TODOS los incidentes para análisis completo
                    all_incidents = Incidente.objects.all().order_by('-fecha_hora')[:50]

                    if all_incidents.exists():
                        incidents_data = []
                        for incident in all_incidents:
                            incidents_data.append({
                                'id': incident.id,
                                'titulo': incident.nombre_incidente,
                                'descripcion': incident.descripcion or 'Sin descripción',
                                'estado': incident.estado_solucion,
                                'categoria': incident.categoria.nombre if incident.categoria else 'Sin categoría',
                                'area': incident.area.nombre if incident.area else 'Sin área',
                                'responsable': incident.responsable.nombre if incident.responsable else 'Sin asignar',
                                'prioridad': incident.prioridad or 'Media',
                                'fecha': incident.fecha_hora.strftime('%d/%m/%Y %H:%M'),
                                'dias_antiguedad': (now.date() - incident.fecha_hora.date()).days
                            })

                        specific_data['all_incidents'] = incidents_data
                        specific_data['active_incidents'] = [i for i in incidents_data if i['estado'] in ['abierto', 'investigacion', 'mitigacion']]
                        specific_data['recent_incidents'] = [i for i in incidents_data if i['dias_antiguedad'] <= 7]

                        # Mostrar resumen completo
                        total_incidents = len(incidents_data)
                        active_count = len(specific_data['active_incidents'])
                        recent_count = len(specific_data['recent_incidents'])
                        context_parts.append(f"""
INCIDENTES EN SISTEMA:
- Total de incidentes: {total_incidents}
- Incidentes activos: {active_count}
- Incidentes recientes (últimos 7 días): {recent_count}
- Estados: {', '.join(set([i['estado'] for i in incidents_data[:10]]))}

DETALLES DE INCIDENTES MÁS RECIENTES:
{chr(10).join([f"- ID {i['id']}: {i['titulo']} | Estado: {i['estado']} | Prioridad: {i['prioridad']} | {i['fecha']}" for i in incidents_data[:10]])}""")
                    else:
                        context_parts.append("\nNo se encontraron incidentes en el sistema.")
                except Exception as e:
                    context_parts.append(f"\nError consultando incidentes: {str(e)}")

            # Si pregunta por amenazas o alertas
            elif any(word in message_lower for word in ['amenaza', 'amenazas', 'alerta', 'alertas', 'ataque', 'ataques', 'intrusion', 'intrusiones', 'analizar']):
                try:
                    # Alertas críticas recientes (últimas 24h, si no hay, buscar en 7 días)
                    critical_recent = IDSAlert.objects.filter(
                        timestamp__gte=last_24h,
                        severity='Critical'
                    ).order_by('-timestamp')[:5]

                    if not critical_recent.exists():
                        # Si no hay en 24h, buscar en 7 días
                        critical_recent = IDSAlert.objects.filter(
                            timestamp__gte=last_7d,
                            severity='Critical'
                        ).order_by('-timestamp')[:5]

                    # También buscar alertas de cualquier severidad si no hay críticas
                    if not critical_recent.exists():
                        critical_recent = IDSAlert.objects.filter(
                            timestamp__gte=last_24h
                        ).order_by('-timestamp')[:5]

                    if not critical_recent.exists():
                        critical_recent = IDSAlert.objects.filter(
                            timestamp__gte=last_7d
                        ).order_by('-timestamp')[:5]

                    if critical_recent.exists():
                        alerts_data = []
                        for alert in critical_recent:
                            alerts_data.append({
                                'mensaje': alert.message[:100],
                                'severidad': alert.severity,
                                'ip_origen': alert.src_ip,
                                'ip_destino': alert.dest_ip,
                                'timestamp': alert.timestamp.strftime('%d/%m/%Y %H:%M')
                            })

                        specific_data['critical_alerts'] = alerts_data
                        context_parts.append(f"""
ALERTAS CRÍTICAS RECIENTES:
{chr(10).join([f"- {a['mensaje']} - {a['timestamp']}" for a in alerts_data])}""")
                    else:
                        context_parts.append("\nNo se encontraron alertas críticas recientes.")
                except Exception as e:
                    context_parts.append(f"\nError consultando alertas: {str(e)}")

            # Contexto general del sistema
            context_parts.insert(0, f"""
CONTEXTO ACTUAL DEL SISTEMA:
- Alertas últimas 24h: {IDSAlert.objects.filter(timestamp__gte=last_24h).count()}
- Alertas última hora: {recent_alerts} ({critical_alerts} críticas)
- Logs Snort/hora: {snort_logs_hour}
- Logs Suricata/hora: {suricata_logs_hour}
- Reportes totales: {Reporte.objects.count()}
- Incidentes activos: {Incidente.objects.filter(estado__in=['ABIERTO', 'EN_PROGRESO']).count()}
- Principales amenazas: {', '.join([t['message'][:50] for t in top_threats[:2]]) if top_threats else 'Ninguna destacada'}""")

        except Exception as e:
            context_parts.append("\nCONTEXTO: Información de seguridad no disponible temporalmente.")

        # Agregar capacidades según permisos
        capabilities = []
        if ollama_service.can_read_snort_logs:
            capabilities.append("✓ Análisis de logs Snort")
        if ollama_service.can_read_suricata_logs:
            capabilities.append("✓ Análisis de logs Suricata")
        if ollama_service.can_read_incidents:
            capabilities.append("✓ Acceso a incidentes")
        if ollama_service.can_read_reports:
            capabilities.append("✓ Acceso a reportes")

        if capabilities:
            context_parts.append(f"CAPACIDADES ACTIVAS:\n" + "\n".join(capabilities))

        context_info = "\n".join(context_parts)

        # Crear prompt con contexto completo para análisis inteligente
        specific_data_json = json.dumps(specific_data, indent=2, default=str, ensure_ascii=False) if specific_data else "No hay datos específicos disponibles"

        # Información básica del sistema siempre disponible
        # Debug: verificar consultas de base de datos
        try:
            ids_alerts_total = IDSAlert.objects.all().count()
            snort_logs_total = SnortLog.objects.all().count()
            suricata_logs_total = SuricataEveAlert.objects.all().count()
            ids_alerts_24h = IDSAlert.objects.filter(timestamp__gte=last_24h).count()
            snort_logs_24h = SnortLog.objects.filter(timestamp__gte=last_24h).count()
            suricata_logs_24h = SuricataEveAlert.objects.filter(timestamp__gte=last_24h).count()

            # Obtener algunas alertas de ejemplo para verificar datos
            sample_ids_alerts = list(IDSAlert.objects.all()[:3].values('message', 'severity', 'timestamp'))
            sample_snort_logs = list(SnortLog.objects.all()[:3].values('message', 'severity', 'timestamp'))
            sample_suricata_logs = list(SuricataEveAlert.objects.all()[:3].values('message', 'severity', 'timestamp'))

        except Exception as db_error:
            ids_alerts_total = snort_logs_total = suricata_logs_total = 0
            ids_alerts_24h = snort_logs_24h = suricata_logs_24h = 0
            sample_ids_alerts = sample_snort_logs = sample_suricata_logs = []
            logger.error(f"Error consultando base de datos: {db_error}")

        basic_system_info = f"""
INFORMACIÓN BÁSICA DEL SISTEMA:
- Alertas IDS totales: {ids_alerts_total}
- Logs Snort totales: {snort_logs_total}
- Logs Suricata totales: {suricata_logs_total}
- Alertas últimas 24h: {ids_alerts_24h}
- Logs Snort últimas 24h: {snort_logs_24h}
- Logs Suricata últimas 24h: {suricata_logs_24h}

DATOS DE EJEMPLO (primeros 3 registros):
IDS Alerts: {json.dumps(sample_ids_alerts, indent=2, default=str)}
Snort Logs: {json.dumps(sample_snort_logs, indent=2, default=str)}
Suricata Logs: {json.dumps(sample_suricata_logs, indent=2, default=str)}
"""

        full_prompt = f"""VANT-SIEM - ANÁLISIS FORENSE DE SEGURIDAD

        DATOS DEL SISTEMA:
        {basic_system_info}

        CONTEXTO OPERACIONAL:
        {context_info}

        DATOS ESPECÍFICOS PARA ANÁLISIS:
        {specific_data_json}

        CONSULTA DEL USUARIO: {message}

        PROTOCOLO DE ANÁLISIS TÉCNICO:
        1. Responder ÚNICAMENTE en español profesional
        2. Basar análisis EXCLUSIVAMENTE en datos proporcionados arriba
        3. Si datos = 0: "No se encontraron registros de [tema] en el período consultado"
        4. Incluir métricas cuantitativas: número de eventos, IPs, severidades
        5. Proporcionar recomendaciones específicas basadas en evidencia técnica
        6. NO mencionar fuentes externas, sitios web o conocimiento general

        ANÁLISIS TÉCNICO DETALLADO:"""

        # Verificar si es una solicitud de generación de reporte automático
        if 'genera' in message_lower and ('reporte' in message_lower or 'informe' in message_lower):
            # Generar reporte usando IA directamente
            report_prompt = f"""
Genera un reporte ejecutivo completo basado en los siguientes datos del sistema VANT-SIEM:

DATOS DEL SISTEMA:
{chr(10).join(context_parts)}

DATOS DETALLADOS:
{json.dumps(specific_data, indent=2, default=str, ensure_ascii=False)}

INSTRUCCIONES PARA EL REPORTE:
- Estructura el reporte con: Resumen Ejecutivo, Análisis de Incidentes, Estado de Reportes, Recomendaciones
- Incluye estadísticas específicas y tendencias
- Identifica patrones de seguridad y riesgos
- Proporciona recomendaciones accionables
- Usa formato profesional y claro
- Responde en español

REPORTE EJECUTIVO:
"""

            ai_report = ollama_service._call_ollama(report_prompt, system_prompt)

            if ai_report and len(ai_report.strip()) > 50:
                # Crear el reporte en la base de datos automáticamente
                try:
                    from EVENT_M.models import Area
                    ai_area, created = Area.objects.get_or_create(
                        nombre='VANT-SIEM-AI-Analitic',
                        defaults={'descripcion': 'Área creada automáticamente para reportes de IA'}
                    )

                    # Crear el reporte
                    new_report = Reporte.objects.create(
                        nombre_informante=f'Reporte IA Automático - {timezone.now().strftime("%d/%m/%Y %H:%M")}',
                        descripcion=ai_report[:2000],  # Limitar longitud
                        estado_solucion='abierto',
                        area=ai_area,
                        fecha_hora=timezone.now()
                    )

                    # Log del evento
                    event_logger.log_event(
                        user=request.user,
                        event_type='AI_AUTO_REPORT',
                        description=f'Reporte IA automático generado: {new_report.nombre_informante}',
                        details={
                            'report_id': new_report.id,
                            'report_length': len(ai_report),
                            'data_sources': list(specific_data.keys())
                        },
                        target_model='Reporte',
                        target_id=new_report.id
                    )

                    return JsonResponse({
                        'success': True,
                        'response': f'✅ Reporte generado automáticamente y guardado en el sistema.\n\nID del Reporte: {new_report.id}\n\n{ai_report}',
                        'report_id': new_report.id,
                        'timestamp': timezone.now().isoformat(),
                        'auto_generated': True
                    })

                except Exception as e:
                    return JsonResponse({
                        'success': False,
                        'error': f'Error creando reporte automático: {str(e)}'
                    })

        # Sistema híbrido: respuestas directas para consultas básicas, IA para análisis complejo
        has_data = (ids_alerts_total > 0 or snort_logs_total > 0 or suricata_logs_total > 0)

        # Obtener totales de reportes e incidentes para todas las respuestas
        total_reportes = Reporte.objects.all().count()
        total_incidentes = Incidente.objects.all().count()

        # Consultas básicas que responden directamente sin IA
        if 'estado' in message_lower and 'sistema' in message_lower:
            logger.info("Providing direct system status response")
            response = f"📊 **Estado del Sistema VANT-SIEM**\n\n"
            response += f"**Datos registrados en el sistema:**\n"
            response += f"• Alertas IDS totales: {ids_alerts_total:,}\n"
            response += f"• Alertas últimas 24h: {ids_alerts_24h:,}\n"
            response += f"• Logs Snort totales: {snort_logs_total:,}\n"
            response += f"• Logs Suricata totales: {suricata_logs_total:,}\n"
            response += f"• Reportes: {total_reportes:,}\n"
            response += f"• Incidentes: {total_incidentes:,}\n\n"

            if has_data:
                response += f"✅ **Sistema operativo con datos de seguridad**\n"
                response += f"💡 Puedes consultar: 'analizar alertas recientes', 'ver reportes nuevos', etc."
            else:
                response += f"🔄 **Esperando datos de IDS/IPS**\n"
                response += f"💡 Configura la ingesta de logs para comenzar a recibir alertas."

            return JsonResponse({
                'success': True,
                'response': response,
                'timestamp': timezone.now().isoformat(),
                'direct_response': True
            })

        # Consultas sobre alertas que responden directamente
        elif ('alerta' in message_lower or 'alertas' in message_lower) and ('reciente' in message_lower or 'ultima' in message_lower or 'última' in message_lower):
            logger.info("Providing direct alerts analysis response")
            response = f"🔍 **Análisis de Alertas Recientes**\n\n"

            if has_data:
                response += f"**Alertas IDS encontradas:**\n"
                response += f"• Total de alertas: {ids_alerts_total:,}\n"
                response += f"• Alertas últimas 24h: {ids_alerts_24h:,}\n"
                response += f"• Alertas críticas: {critical_alerts}\n\n"

                if ids_alerts_24h > 0:
                    response += f"✅ **Hay actividad reciente de seguridad**\n"
                    response += f"📈 Recomendación: Revisar el dashboard de amenazas para detalles específicos."
                else:
                    response += f"⚠️ **No hay alertas en las últimas 24 horas**\n"
                    response += f"📊 El sistema registra {ids_alerts_total} alertas históricas."
            else:
                response += f"📭 **No hay alertas registradas en el sistema**\n\n"
                response += f"💡 **Para recibir alertas:**\n"
                response += f"• Configura parsers de Snort/Suricata\n"
                response += f"• Verifica rutas de logs\n"
                response += f"• Revisa configuración en 'Settings > IDS Services'"

            return JsonResponse({
                'success': True,
                'response': response,
                'timestamp': timezone.now().isoformat(),
                'direct_response': True
            })

        # Consultas sobre ingesta que responden directamente
        elif ('ingesta' in message_lower or 'snort' in message_lower or 'suricata' in message_lower) and ('que hay' in message_lower or 'estado' in message_lower or 'nuevo' in message_lower):
            logger.info("Providing direct ingestion status response")
            response = f"🔧 **Estado de Ingesta de Logs**\n\n"
            response += f"**Datos procesados por el sistema:**\n"
            response += f"• Snort: {snort_logs_total:,} logs totales ({snort_logs_24h:,} últimas 24h)\n"
            response += f"• Suricata: {suricata_logs_total:,} logs totales ({suricata_logs_24h:,} últimas 24h)\n"
            response += f"• Alertas IDS: {ids_alerts_total:,} totales ({ids_alerts_24h:,} últimas 24h)\n\n"

            if has_data:
                response += f"✅ **Ingesta funcionando correctamente**\n"
                response += f"📊 Datos disponibles para análisis de seguridad."
            else:
                response += f"⚠️ **Sin datos de ingesta**\n"
                response += f"🔧 Verifica:\n"
                response += f"• Que Snort/Suricata estén ejecutándose\n"
                response += f"• Rutas de archivos de log configuradas\n"
                response += f"• Permisos de lectura en archivos de log\n"
                response += f"• Configuración de parsers activa"

            return JsonResponse({
                'success': True,
                'response': response,
                'timestamp': timezone.now().isoformat(),
                'direct_response': True
            })

        # Para consultas más complejas, usar IA (si hay datos)
        if not has_data:
            logger.info("No data available, providing direct fallback response")
            return JsonResponse({
                'success': True,
                'response': f"📊 **Sistema VANT-SIEM**\n\n"
                           f"El sistema está operativo pero actualmente no tiene datos de seguridad registrados.\n\n"
                           f"**Estado actual:**\n"
                           f"• Alertas IDS: 0\n"
                           f"• Logs Snort: 0\n"
                           f"• Logs Suricata: 0\n\n"
                           f"💡 **Para comenzar:** Configura la ingesta de logs de Snort y Suricata en 'Settings > IDS Services'.\n\n"
                           f"El sistema está listo para procesar datos de seguridad cuando estén disponibles.",
                'timestamp': timezone.now().isoformat(),
                'fallback': True
            })

        # Agregar historial de conversación al prompt
        conversation_history = ""
        if history:
            conversation_history = "\n\nHISTORIAL DE CONVERSACIÓN RECIENTE:\n"
            # Mostrar últimas 3 interacciones para contexto
            recent_history = history[-6:]  # últimos 3 pares pregunta-respuesta
            for i, msg in enumerate(recent_history):
                role = "Usuario" if msg.get('role') == 'user' else "VANT-AI"
                content = msg.get('content', '')[:200]  # limitar longitud
                conversation_history += f"{role}: {content}\n"

        # Incluir historial en el prompt
        full_prompt_with_history = full_prompt + conversation_history

        # Definir system prompt técnico y específico
        chat_system_prompt = """SISTEMA VANT-AI - ANALISTA FORENSE DE CIBERSEGURIDAD

        PERFIL: Eres un analista técnico especializado en IDS/IPS (Snort/Suricata) para entornos corporativos.

        FUNCIONES TÉCNICAS:
        - Análisis de logs de seguridad reales
        - Identificación de patrones de amenazas
        - Evaluación de riesgos basada en evidencia
        - Recomendaciones de mitigación específicas

        PROTOCOLO DE RESPUESTA:
        1. SIEMPRE basar respuestas en datos proporcionados arriba
        2. Usar terminología técnica precisa (GID, SID, firmas, severidades)
        3. Responder en ESPAÑOL profesional y técnico
        4. Si no hay datos: "No se encontraron registros de [tema] en el período analizado"
        5. Enfocarse SOLO en análisis defensivo y monitoreo

        FORMATO DE RESPUESTAS:
        - Estadísticas cuantitativas cuando aplique
        - IPs, puertos y protocolos específicos
        - Recomendaciones accionables basadas en evidencia
        - Nivel de riesgo justificado técnicamente
        """

        # Llamar a Ollama para consultas normales con system prompt
        ai_response = ollama_service._call_ollama(full_prompt_with_history, system_prompt=chat_system_prompt)

        if ai_response and len(ai_response.strip()) > 5:
            # Log del evento exitoso
            event_logger.log_event(
                user=request.user,
                event_type='AI_CHAT',
                description=f'Consulta de chat IA: {message[:100]}...',
                details={
                    'message_length': len(message),
                    'response_length': len(ai_response),
                    'has_history': bool(history)
                }
            )

            return JsonResponse({
                'success': True,
                'response': ai_response,
                'timestamp': timezone.now().isoformat()
            })
        else:
            # Respuesta de respaldo cuando Ollama no está disponible
            fallback_response = _generate_fallback_response(message, specific_data, context_parts)

            # Si la respuesta de respaldo es genérica, forzar respuesta informativa
            if "Respeito si tienes alguna pregunta" in fallback_response or "Respeito si no hay información" in fallback_response:
                # Crear respuesta informativa forzada
                total_alerts = IDSAlert.objects.all().count()
                total_snort = SnortLog.objects.all().count()
                total_suricata = SuricataEveAlert.objects.all().count()
                total_reportes = Reporte.objects.all().count()
                total_incidentes = Incidente.objects.all().count()

                fallback_response = f"🤖 VANT-IA: Sistema operativo\n\n"
                fallback_response += f"📊 **Estado del sistema:**\n"
                fallback_response += f"• Alertas IDS: {total_alerts}\n"
                fallback_response += f"• Logs Snort: {total_snort}\n"
                fallback_response += f"• Logs Suricata: {total_suricata}\n"
                fallback_response += f"• Reportes: {total_reportes}\n"
                fallback_response += f"• Incidentes: {total_incidentes}\n\n"

                if total_alerts > 0 or total_snort > 0 or total_suricata > 0:
                    fallback_response += f"✅ **Sistema con datos de seguridad**\n\n"
                    fallback_response += f"💡 **Consultas disponibles:**\n"
                    fallback_response += f"• 'analizar amenazas'\n"
                    fallback_response += f"• 'ver estado del sistema'\n"
                    fallback_response += f"• 'reportes recientes'\n"
                else:
                    fallback_response += f"🔄 **Esperando datos de IDS/IPS**\n\n"
                    fallback_response += f"💡 El sistema está listo para recibir datos de Snort y Suricata."

            # Log del evento con fallback
            event_logger.log_event(
                user=request.user,
                event_type='AI_CHAT_FALLBACK',
                description=f'Consulta de chat IA (fallback): {message[:100]}...',
                details={
                    'message_length': len(message),
                    'used_fallback': True,
                    'has_specific_data': bool(specific_data)
                }
            )

            return JsonResponse({
                'success': True,
                'response': fallback_response,
                'timestamp': timezone.now().isoformat(),
                'fallback': True
            })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def local_search_ip(request):
    from .models import AbuseIPDBAnalysisRecord
    query = (request.GET.get('q') or '').strip()
    record = None
    results = []
    if query:
        qs = AbuseIPDBAnalysisRecord.objects.filter(ip_address__iexact=query).order_by('-created_at')
        record = qs.first()
        results = qs[:50]
    return render(request, 'local_search_ip.html', {
        'q': query,
        'record': record,
        'results': results,
    })

@login_required
def local_search_mac(request):
    from .models import MacVendorsAnalysisRecord
    query = (request.GET.get('q') or '').strip()
    record = None
    results = []
    if query:
        qs = MacVendorsAnalysisRecord.objects.filter(mac_address__iexact=query).order_by('-created_at')
        record = qs.first()
        results = qs[:50]
    return render(request, 'local_search_mac.html', {
        'q': query,
        'record': record,
        'results': results,
    })

@login_required
def local_search_indicator(request):
    from .models import VTAnalysisRecord
    query = (request.GET.get('q') or '').strip()
    record = None
    results = []
    if query:
        qs = VTAnalysisRecord.objects.filter(indicator__iexact=query).order_by('-created_at')
        record = qs.first()
        results = qs[:50]
    return render(request, 'local_search_indicator.html', {
        'q': query,
        'record': record,
        'results': results,
    })

@login_required
def report_vt(request):
    from .models import VTAnalysisRecord
    qs = VTAnalysisRecord.objects.all()
    total = qs.count()
    by_type = list(qs.values('indicator_type').annotate(total=Count('id')).order_by('-total'))
    by_status = list(qs.values('status_code').annotate(total=Count('id')).order_by('-total'))
    top_indicators = list(qs.values('indicator', 'indicator_type').annotate(total=Count('id')).order_by('-total')[:10])
    # últimos 7 días
    today = timezone.now().date()
    last7 = []
    for i in range(6,-1,-1):
        day = today - timedelta(days=i)
        count = qs.filter(created_at__date=day).count()
        last7.append({'date': day.strftime('%Y-%m-%d'), 'total': count})
    return render(request, 'report_vt.html', {
        'total': total,
        'by_type': by_type,
        'by_status': by_status,
        'top_indicators': top_indicators,
        'last7': last7,
    })

@login_required
def report_abuseipdb(request):
    from .models import AbuseIPDBAnalysisRecord
    qs = AbuseIPDBAnalysisRecord.objects.all()
    total = qs.count()
    by_status = list(qs.values('status_code').annotate(total=Count('id')).order_by('-total'))
    top_ips = list(qs.values('ip_address').annotate(total=Count('id')).order_by('-total')[:10])
    today = timezone.now().date()
    last7 = []
    for i in range(6,-1,-1):
        day = today - timedelta(days=i)
        count = qs.filter(created_at__date=day).count()
        last7.append({'date': day.strftime('%Y-%m-%d'), 'total': count})
    return render(request, 'report_abuseipdb.html', {
        'total': total,
        'by_status': by_status,
        'top_ips': top_ips,
        'last7': last7,
    })

@login_required
def report_macvendors(request):
    from .models import MacVendorsAnalysisRecord
    qs = MacVendorsAnalysisRecord.objects.all()
    total = qs.count()
    by_status = list(qs.values('status_code').annotate(total=Count('id')).order_by('-total'))
    top_vendors = list(qs.values('vendor').annotate(total=Count('id')).order_by('-total')[:10])
    top_macs = list(qs.values('mac_address').annotate(total=Count('id')).order_by('-total')[:10])
    today = timezone.now().date()
    last7 = []
    for i in range(6,-1,-1):
        day = today - timedelta(days=i)
        count = qs.filter(created_at__date=day).count()
        last7.append({'date': day.strftime('%Y-%m-%d'), 'total': count})
    return render(request, 'report_macvendors.html', {
        'total': total,
        'by_status': by_status,
        'top_vendors': top_vendors,
        'top_macs': top_macs,
        'last7': last7,
    })

import socket
import subprocess

@login_required
def tools_ping_view(request):
    return render(request, 'tools_ping.html')

@login_required
@require_POST
def api_tools_ping(request):
    host = (request.POST.get('host') or '').strip()
    count = int(request.POST.get('count') or 4)
    timeout = int(request.POST.get('timeout') or 2)
    if not host:
        return JsonResponse({'success': False, 'error': 'Host requerido'})
    try:
        import platform
        system = platform.system().lower()
        if 'windows' in system:
            ping_cmd = 'ping'
            cmd = [ping_cmd, '-n', str(min(max(count,1),10)), '-w', str(max(timeout*1000, 1000)), host]
        else:
            ping_cmd = 'ping'
            cmd = [ping_cmd, '-c', str(min(max(count,1),10)), '-W', str(max(timeout,1)), host]

        # Find the full path of the ping command
        ping_path = find_command_path(ping_cmd)
        if not ping_path:
            return JsonResponse({'success': False, 'error': f'Comando {ping_cmd} no encontrado en el sistema'})

        # Replace the command with full path
        cmd[0] = ping_path

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout*count+2, 5))
        # log
        event_logger.log_event(
            user=request.user,
            event_type='NET_PING',
            description=f'Ping a {host}',
            details={'host': host, 'count': count, 'timeout_s': timeout, 'returncode': result.returncode}
        )
        return JsonResponse({'success': result.returncode == 0, 'stdout': result.stdout, 'stderr': result.stderr, 'returncode': result.returncode})
    except Exception as e:
        event_logger.log_event(user=request.user, event_type='NET_PING', description=f'Ping error a {host}', details={'host': host, 'error': str(e)})
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def tools_dns_view(request):
    return render(request, 'tools_dns.html')

@login_required
@require_POST
def api_tools_dns(request):
    name = (request.POST.get('name') or '').strip()
    if not name:
        return JsonResponse({'success': False, 'error': 'Nombre de dominio requerido'})
    try:
        addrs = socket.getaddrinfo(name, None)
        v4 = []
        v6 = []
        for af, socktype, proto, canonname, sa in addrs:
            ip = sa[0]
            if ':' in ip:
                if ip not in v6:
                    v6.append(ip)
            else:
                if ip not in v4:
                    v4.append(ip)
        event_logger.log_event(user=request.user, event_type='NET_DNS', description=f'DNS {name}', details={'name': name, 'ipv4': v4, 'ipv6': v6})
        return JsonResponse({'success': True, 'ipv4': v4, 'ipv6': v6})
    except Exception as e:
        event_logger.log_event(user=request.user, event_type='NET_DNS', description=f'DNS error {name}', details={'name': name, 'error': str(e)})
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def tools_scan_view(request):
    return render(request, 'tools_scan.html')

@login_required
@require_POST
def api_tools_scan(request):
    host = (request.POST.get('host') or '').strip()
    start = int(request.POST.get('start') or 1)
    end = int(request.POST.get('end') or 1024)
    timeout = float(request.POST.get('timeout') or 0.5)
    if not host:
        return JsonResponse({'success': False, 'error': 'Host requerido'})
    start = max(1, min(start, 65535))
    end = max(start, min(end, 65535))
    end = min(end, start + 200)  # limitar rango para seguridad
    open_ports = []
    try:
        for port in range(start, end+1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((host, port)) == 0:
                        open_ports.append(port)
            except Exception:
                continue
        event_logger.log_event(user=request.user, event_type='NET_PORT_SCAN', description=f'Port scan {host}', details={'host': host, 'range': [start, end], 'open_ports': open_ports[:50]})
        return JsonResponse({'success': True, 'host': host, 'range': [start, end], 'open_ports': open_ports})
    except Exception as e:
        event_logger.log_event(user=request.user, event_type='NET_PORT_SCAN', description=f'Port scan error {host}', details={'host': host, 'error': str(e)})
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def tools_bruteforce_view(request):
    return render(request, 'tools_bruteforce.html')

@login_required
@require_POST
def api_tools_bruteforce(request):
    ip = (request.POST.get('ip') or '').strip()
    port = int(request.POST.get('port') or 22)
    single_user = (request.POST.get('single_user') or '').strip()
    single_pass = (request.POST.get('single_pass') or '').strip()
    users_list = (request.POST.get('users_list') or '').splitlines()
    passes_list = (request.POST.get('passes_list') or '').splitlines()
    pairs_list = (request.POST.get('pairs_list') or '').splitlines()
    target_cred = (request.POST.get('target_cred') or '').strip()
    max_attempts = int(request.POST.get('max_attempts') or 100)
    users = [u.strip() for u in users_list if u.strip()]
    passes = [p.strip() for p in passes_list if p.strip()]
    pairs = [p.strip() for p in pairs_list if ':' in p]
    if single_user: users.insert(0, single_user)
    if single_pass: passes.insert(0, single_pass)
    combos = []
    if pairs:
        combos.extend([tuple(x.split(':',1)) for x in pairs])
    for u in users:
        for p in passes:
            combos.append((u,p))
    total_combinations = len(combos)
    combos = combos[:max_attempts]

    # Intentos reales con paramiko (si disponible)
    attempts = 0
    found = False
    matched = ''
    tried = []
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for (u,p) in combos:
            attempts += 1
            tried.append(f"{u}:{p}")
            try:
                client.connect(ip, port=port, username=u, password=p, timeout=3, auth_timeout=3, allow_agent=False, look_for_keys=False)
                found = True
                matched = f"{u}:{p}"
                try:
                    client.close()
                except Exception:
                    pass
                break
            except Exception:
                continue
        try:
            client.close()
        except Exception:
            pass
    except Exception:
        # Fallback a simulación: coincide si target_cred fue provisto
        for (u,p) in combos:
            attempts += 1
            tried.append(f"{u}:{p}")
            if target_cred and f"{u}:{p}" == target_cred:
                found = True
                matched = f"{u}:{p}"
                break

    event_logger.log_event(user=request.user, event_type='NET_BRUTE_SSH', description='Brute SSH', details={
        'ip': ip, 'port': port, 'attempts': attempts, 'found': found, 'total_combinations': total_combinations, 'tried_sample': tried[:5]
    })
    return JsonResponse({'success': True, 'found': found, 'attempts': attempts, 'matched': matched, 'total_combinations': total_combinations})

import ipaddress

@login_required
def tools_traceroute_view(request):
    return render(request, 'tools_traceroute.html')

@login_required
@require_POST
def api_tools_traceroute(request):
    host = (request.POST.get('host') or '').strip()
    max_hops = int(request.POST.get('max_hops') or 20)
    timeout = int(request.POST.get('timeout') or 2)
    if not host:
        return JsonResponse({'success': False, 'error': 'Host requerido'})
    try:
        import platform
        system = platform.system().lower()
        if 'windows' in system:
            traceroute_cmd = 'tracert'
            cmd = [traceroute_cmd, '-d', '-h', str(min(max_hops,30)), host]
        else:
            traceroute_cmd = 'traceroute'
            cmd = [traceroute_cmd, '-n', '-m', str(min(max_hops,30)), '-w', str(max(timeout,1)), host]

        # Find the full path of the traceroute command
        traceroute_path = find_command_path(traceroute_cmd)
        if not traceroute_path:
            return JsonResponse({'success': False, 'error': f'Comando {traceroute_cmd} no encontrado en el sistema'})

        # Replace the command with full path
        cmd[0] = traceroute_path

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max(timeout*max_hops+5, 10))
        event_logger.log_event(user=request.user, event_type='NET_TRACEROUTE', description=f'Traceroute {host}', details={'host': host, 'max_hops': max_hops, 'returncode': result.returncode})
        return JsonResponse({'success': result.returncode == 0 or result.stdout != '', 'stdout': result.stdout, 'stderr': result.stderr, 'returncode': result.returncode})
    except Exception as e:
        event_logger.log_event(user=request.user, event_type='NET_TRACEROUTE', description=f'Traceroute error {host}', details={'host': host, 'error': str(e)})
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def tools_service_scan_view(request):
    return render(request, 'tools_service_scan.html')

@login_required
@require_POST
def api_tools_service_scan(request):
    host = (request.POST.get('host') or '').strip()
    start = int(request.POST.get('start') or 1)
    end = int(request.POST.get('end') or 1024)
    timeout = float(request.POST.get('timeout') or 0.5)
    if not host:
        return JsonResponse({'success': False, 'error': 'Host requerido'})
    start = max(1, min(start, 65535))
    end = max(start, min(end, 65535))
    end = min(end, start + 200)
    findings = []
    try:
        for port in range(start, end+1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((host, port)) == 0:
                        banner = ''
                        try:
                            s.settimeout(0.5)
                            data = s.recv(128)
                            if data:
                                banner = data.decode(errors='ignore')
                        except Exception:
                            pass
                        try:
                            service = socket.getservbyport(port)
                        except Exception:
                            service = ''
                        findings.append({'port': port, 'service': service, 'banner': banner})
            except Exception:
                continue
        event_logger.log_event(user=request.user, event_type='NET_SERVICE_SCAN', description=f'Service scan {host}', details={'host': host, 'range': [start, end], 'open': [f['port'] for f in findings[:50]]})
        return JsonResponse({'success': True, 'host': host, 'range': [start, end], 'open': findings})
    except Exception as e:
        event_logger.log_event(user=request.user, event_type='NET_SERVICE_SCAN', description=f'Service scan error {host}', details={'host': host, 'error': str(e)})
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def tools_discovery_view(request):
    return render(request, 'tools_discovery.html')

@login_required
@require_POST
def api_tools_discovery(request):
    cidr = (request.POST.get('cidr') or '').strip()
    if not cidr:
        return JsonResponse({'success': False, 'error': 'CIDR requerido (ej: 192.168.1.0/24)'})
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        return JsonResponse({'success': False, 'error': f'CIDR inválido: {e}'})
    hosts = [str(ip) for ip in net.hosts()]
    if len(hosts) > 256:
        hosts = hosts[:256]
    alive = []
    try:
        import platform
        system = platform.system().lower()

        # Find ping command path
        ping_cmd = 'ping'
        ping_path = find_command_path(ping_cmd)
        if not ping_path:
            return JsonResponse({'success': False, 'error': f'Comando {ping_cmd} no encontrado en el sistema'})

        for ip in hosts:
            try:
                if 'windows' in system:
                    cmd = [ping_path, '-n', '1', '-w', '800', ip]
                else:
                    cmd = [ping_path, '-c', '1', '-W', '1', ip]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                if res.returncode == 0:
                    alive.append(ip)
            except Exception:
                continue
        macs = {}
        try:
            # Find arp command path
            arp_cmd = 'arp'
            arp_path = find_command_path(arp_cmd)
            if arp_path:
                if 'windows' in system:
                    arp = subprocess.run([arp_path, '-a'], capture_output=True, text=True)
                    for line in arp.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].count('.')==3 and '-' in parts[1]:
                            macs[parts[0]] = parts[1]
                else:
                    arp = subprocess.run([arp_path, '-n'], capture_output=True, text=True)
                    for line in arp.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].count('.')==3 and (':' in parts[2] or '-' in parts[2]):
                            macs[parts[0]] = parts[2]
        except Exception:
            pass
        results = [{'ip': ip, 'mac': macs.get(ip, '')} for ip in alive]
        event_logger.log_event(user=request.user, event_type='NET_DISCOVERY', description=f'Descubrimiento {cidr}', details={'cidr': str(net), 'alive': results[:50]})
        return JsonResponse({'success': True, 'network': str(net), 'alive': results})
    except Exception as e:
        event_logger.log_event(user=request.user, event_type='NET_DISCOVERY', description=f'Descubrimiento error {cidr}', details={'cidr': cidr, 'error': str(e)})
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
def tools_ipcalc_view(request):
    return render(request, 'tools_ipcalc.html')

@login_required
@require_POST
def api_tools_ipcalc(request):
    cidr = (request.POST.get('cidr') or '').strip()
    if not cidr:
        return JsonResponse({'success': False, 'error': 'CIDR requerido'})
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        network = str(net.network_address)
        broadcast = str(net.broadcast_address)
        total = net.num_addresses
        first_host = str(list(net.hosts())[0]) if total > 2 else network
        last_host = str(list(net.hosts())[-1]) if total > 2 else broadcast
        event_logger.log_event(user=request.user, event_type='NET_IPCALC', description=f'IPCalc {cidr}', details={'cidr': str(net), 'network': network, 'broadcast': broadcast})
        return JsonResponse({'success': True, 'network': network, 'broadcast': broadcast, 'prefix': net.prefixlen, 'total': total, 'first_host': first_host, 'last_host': last_host})
    except Exception as e:
        event_logger.log_event(user=request.user, event_type='NET_IPCALC', description=f'IPCalc error {cidr}', details={'cidr': cidr, 'error': str(e)})
        return JsonResponse({'success': False, 'error': f'CIDR inválido: {e}'})

# ===== VISTAS DE MONITOREO DE SERVICIOS =====

@login_required
def monitoring_services(request):
    """Vista principal de monitoreo de servicios"""
    from EVENT_M.models import Servicio, MonitoreoServicio, ConfiguracionMonitoreo
    
    # Obtener servicios con monitoreo activo - consulta simplificada
    servicios_monitoreados = Servicio.objects.filter(monitorear=True)
    
    # Filtrar solo los que tienen host configurado
    servicios_con_host = []
    for servicio in servicios_monitoreados:
        if servicio.host and servicio.host.strip():
            servicios_con_host.append(servicio)
    
    # Obtener última verificación de cada servicio
    servicios_con_estado = []
    for servicio in servicios_con_host:
        try:
            ultimo_monitoreo = MonitoreoServicio.objects.filter(servicio=servicio).first()
            servicios_con_estado.append({
                'servicio': servicio,
                'ultimo_estado': ultimo_monitoreo.estado if ultimo_monitoreo else False,
                'ultima_latencia': ultimo_monitoreo.latencia if ultimo_monitoreo else None,
                'ultima_verificacion': ultimo_monitoreo.timestamp if ultimo_monitoreo else None,
                'error': ultimo_monitoreo.error if ultimo_monitoreo else None
            })
        except Exception as e:
            # Si el modelo MonitoreoServicio no existe, crear entrada sin historial
            servicios_con_estado.append({
                'servicio': servicio,
                'ultimo_estado': False,
                'ultima_latencia': None,
                'ultima_verificacion': None,
                'error': 'Sin verificación previa'
            })
    
    # Obtener configuración de monitoreo
    config, created = ConfiguracionMonitoreo.objects.get_or_create(pk=1)
    
    # Estadísticas
    total_servicios = Servicio.objects.count()
    servicios_arriba = sum(1 for s in servicios_con_estado if s['ultimo_estado'])
    servicios_abajo = sum(1 for s in servicios_con_estado if not s['ultimo_estado'])
    servicios_sin_monitoreo = total_servicios - len(servicios_con_estado)
    
    context = {
        'servicios_con_estado': servicios_con_estado,
        'config': config,
        'stats': {
            'total': total_servicios,
            'arriba': servicios_arriba,
            'abajo': servicios_abajo,
            'sin_monitoreo': servicios_sin_monitoreo
        }
    }
    
    return render(request, 'monitoring_services.html', context)

@login_required
def monitoring_config(request):
    """Vista de configuración del servicio de monitoreo"""
    from EVENT_M.models import ConfiguracionMonitoreo
    
    config, created = ConfiguracionMonitoreo.objects.get_or_create(pk=1)
    
    if request.method == 'POST':
        config.intervalo_segundos = int(request.POST.get('intervalo_segundos', 60))
        config.activo = request.POST.get('activo') == 'on'
        config.save()
        
        if config.activo:
            messages.success(request, f'Servicio de monitoreo iniciado con intervalo de {config.intervalo_segundos} segundos')
        else:
            messages.info(request, 'Servicio de monitoreo detenido')
        
        return redirect('monitoring-config')
    
    return render(request, 'monitoring_config.html', {'config': config})

@login_required
@require_POST
def monitoring_check_api(request):
    """API para verificar estado de servicios con ping"""
    from EVENT_M.models import Servicio, MonitoreoServicio
    import subprocess
    import platform
    
    # Obtener servicios con monitoreo activo
    servicios_monitoreados = Servicio.objects.filter(monitorear=True)
    
    # Filtrar solo los que tienen host configurado
    servicios = []
    for servicio in servicios_monitoreados:
        if servicio.host and servicio.host.strip():
            servicios.append(servicio)
    resultados = []
    
    for servicio in servicios:
        try:
            # Comando ping según el sistema operativo
            if platform.system().lower() == "windows":
                cmd = ['ping', '-n', '1', '-w', '2000', str(servicio.host)]
            else:
                cmd = ['ping', '-c', '1', '-W', '2', str(servicio.host)]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Extraer latencia del output
                latencia = None
                output_lines = result.stdout.split('\n')
                for line in output_lines:
                    if 'time=' in line or 'tiempo=' in line:
                        try:
                            if 'time=' in line:
                                latencia = float(line.split('time=')[1].split('ms')[0])
                            elif 'tiempo=' in line:
                                latencia = float(line.split('tiempo=')[1].split('ms')[0])
                        except:
                            pass
                        break
                
                # Guardar resultado exitoso
                MonitoreoServicio.objects.create(
                    servicio=servicio,
                    estado=True,
                    latencia=latencia
                )
                
                resultados.append({
                    'servicio': servicio.nombre,
                    'host': str(servicio.host),
                    'estado': True,
                    'latencia': latencia,
                    'error': None
                })
            else:
                # Guardar resultado fallido
                MonitoreoServicio.objects.create(
                    servicio=servicio,
                    estado=False,
                    error=result.stderr or 'Ping falló'
                )
                
                resultados.append({
                    'servicio': servicio.nombre,
                    'host': str(servicio.host),
                    'estado': False,
                    'latencia': None,
                    'error': result.stderr or 'Ping falló'
                })
                
        except subprocess.TimeoutExpired:
            MonitoreoServicio.objects.create(
                servicio=servicio,
                estado=False,
                error='Timeout'
            )
            resultados.append({
                'servicio': servicio.nombre,
                'host': str(servicio.host),
                'estado': False,
                'latencia': None,
                'error': 'Timeout'
            })
        except Exception as e:
            MonitoreoServicio.objects.create(
                servicio=servicio,
                estado=False,
                error=str(e)
            )
            resultados.append({
                'servicio': servicio.nombre,
                'host': str(servicio.host),
                'estado': False,
                'latencia': None,
                'error': str(e)
            })
    
    # Log del evento
    event_logger.log_event(
        user=request.user,
        event_type='MONITORING_CHECK',
        description=f'Verificación de monitoreo de {len(servicios)} servicios',
        details={'servicios_verificados': len(servicios), 'resultados': resultados}
    )
    
    return JsonResponse({'success': True, 'resultados': resultados})

@login_required
def monitoring_history_api(request, servicio_id):
    """API para obtener historial de monitoreo de un servicio"""
    from EVENT_M.models import Servicio, MonitoreoServicio
    from django.utils import timezone
    from datetime import timedelta
    
    servicio = get_object_or_404(Servicio, pk=servicio_id)
    
    # Obtener datos de las últimas 24 horas
    desde = timezone.now() - timedelta(hours=24)
    historial = MonitoreoServicio.objects.filter(
        servicio=servicio,
        timestamp__gte=desde
    ).order_by('timestamp')
    
    # Preparar datos para gráfico
    labels = []
    latencia_data = []
    estado_data = []
    
    for registro in historial:
        labels.append(registro.timestamp.strftime('%H:%M'))
        latencia_data.append(registro.latencia if registro.latencia else 0)
        estado_data.append(1 if registro.estado else 0)
    
    return JsonResponse({
        'success': True,
        'labels': labels,
        'latencia': latencia_data,
        'estado': estado_data,
        'servicio': servicio.nombre
    })

# ===== VISTAS PARA IDS/IPS =====

@login_required
def threats_dashboard(request):
    return redirect('dashboard')

@login_required
def snort_dashboard(request):
    """Dashboard de amenazas filtrado para Snort (v2 y v3)."""
    from .models import IDSConfiguration, ThreatLog
    from django.utils import timezone
    from datetime import timedelta
    snort_configs = IDSConfiguration.objects.filter(sistema__in=['snort_v2', 'snort_v3'], activo=True)
    threats = ThreatLog.objects.filter(configuracion__in=snort_configs)

    # filtros de tiempo
    start = request.GET.get('start', '').strip()
    end = request.GET.get('end', '').strip()
    try:
        if start:
            from django.utils.dateparse import parse_datetime
            sdt = parse_datetime(start) or timezone.make_aware(timezone.datetime.fromisoformat(start))
            threats = threats.filter(timestamp__gte=sdt)
        if end:
            from django.utils.dateparse import parse_datetime
            edt = parse_datetime(end) or timezone.make_aware(timezone.datetime.fromisoformat(end))
            threats = threats.filter(timestamp__lte=edt)
    except Exception:
        pass

    # filtros
    search = request.GET.get('search', '').strip()
    prioridad = request.GET.get('prioridad', '').strip()
    estado = request.GET.get('estado', '').strip()
    configuracion = request.GET.get('configuracion', '').strip()

    from django.db.models import Q
    if search:
        threats = threats.filter(
            Q(mensaje__icontains=search) |
            Q(ip_origen__icontains=search) |
            Q(ip_destino__icontains=search) |
            Q(regla_id__icontains=search)
        )
    if prioridad:
        threats = threats.filter(prioridad=prioridad)
    if estado:
        threats = threats.filter(estado=estado)
    if configuracion:
        threats = threats.filter(configuracion_id=configuracion)

    # paginación
    paginator = Paginator(threats.order_by('-timestamp'), 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # agregados para tablas
    top_reglas = (threats.values('regla_id')
                  .exclude(regla_id='')
                  .annotate(total=Count('id'))
                  .order_by('-total')[:10])
    top_categorias = (threats.values('clasificacion')
                      .exclude(clasificacion='')
                      .annotate(total=Count('id'))
                      .order_by('-total')[:10])
    top_ips_origen = (threats.values('ip_origen')
                      .exclude(ip_origen=None)
                      .annotate(total=Count('id'))
                      .order_by('-total')[:10])
    top_ips_destino = (threats.values('ip_destino')
                       .exclude(ip_destino=None)
                       .annotate(total=Count('id'))
                       .order_by('-total')[:10])

    context = {
        'vendor': 'Snort',
        'configuraciones': snort_configs,
        'stats': {
            'total_amenazas': threats.count(),
            'amenazas_hoy': threats.filter(timestamp__date=timezone.now().date()).count(),
            'amenazas_ultima_hora': threats.filter(timestamp__gte=timezone.now() - timedelta(hours=1)).count(),
        },
        'page_obj': page_obj,
        'filters': {
            'search': search,
            'prioridad': prioridad,
            'estado': estado,
            'configuracion': configuracion,
            'start': start,
            'end': end,
        },
        'top_reglas': top_reglas,
        'top_categorias': top_categorias,
        'top_ips_origen': top_ips_origen,
        'top_ips_destino': top_ips_destino,
    }
    return render(request, 'snort_dashboard.html', context)

@login_required
def suricata_dashboard(request):
    """Dashboard de amenazas filtrado para Suricata."""
    from .models import IDSConfiguration, ThreatLog
    from django.utils import timezone
    from datetime import timedelta
    suri_configs = IDSConfiguration.objects.filter(sistema='suricata', activo=True)
    threats = ThreatLog.objects.filter(configuracion__in=suri_configs)

    # filtros de tiempo
    start = request.GET.get('start', '').strip()
    end = request.GET.get('end', '').strip()
    try:
        if start:
            from django.utils.dateparse import parse_datetime
            sdt = parse_datetime(start) or timezone.make_aware(timezone.datetime.fromisoformat(start))
            threats = threats.filter(timestamp__gte=sdt)
        if end:
            from django.utils.dateparse import parse_datetime
            edt = parse_datetime(end) or timezone.make_aware(timezone.datetime.fromisoformat(end))
            threats = threats.filter(timestamp__lte=edt)
    except Exception:
        pass

    # filtros
    search = request.GET.get('search', '').strip()
    prioridad = request.GET.get('prioridad', '').strip()
    estado = request.GET.get('estado', '').strip()
    configuracion = request.GET.get('configuracion', '').strip()

    from django.db.models import Q
    if search:
        threats = threats.filter(
            Q(mensaje__icontains=search) |
            Q(ip_origen__icontains=search) |
            Q(ip_destino__icontains=search) |
            Q(regla_id__icontains=search)
        )
    if prioridad:
        threats = threats.filter(prioridad=prioridad)
    if estado:
        threats = threats.filter(estado=estado)
    if configuracion:
        threats = threats.filter(configuracion_id=configuracion)

    # paginación
    paginator = Paginator(threats.order_by('-timestamp'), 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    top_reglas = (threats.values('regla_id')
                  .exclude(regla_id='')
                  .annotate(total=Count('id'))
                  .order_by('-total')[:10])
    top_categorias = (threats.values('clasificacion')
                      .exclude(clasificacion='')
                      .annotate(total=Count('id'))
                      .order_by('-total')[:10])
    top_ips_origen = (threats.values('ip_origen')
                      .exclude(ip_origen=None)
                      .annotate(total=Count('id'))
                      .order_by('-total')[:10])
    top_ips_destino = (threats.values('ip_destino')
                       .exclude(ip_destino=None)
                       .annotate(total=Count('id'))
                       .order_by('-total')[:10])

    context = {
        'vendor': 'Suricata',
        'configuraciones': suri_configs,
        'stats': {
            'total_amenazas': threats.count(),
            'amenazas_hoy': threats.filter(timestamp__date=timezone.now().date()).count(),
            'amenazas_ultima_hora': threats.filter(timestamp__gte=timezone.now() - timedelta(hours=1)).count(),
        },
        'page_obj': page_obj,
        'filters': {
            'search': search,
            'prioridad': prioridad,
            'estado': estado,
            'configuracion': configuracion,
            'start': start,
            'end': end,
        },
        'top_reglas': top_reglas,
        'top_categorias': top_categorias,
        'top_ips_origen': top_ips_origen,
        'top_ips_destino': top_ips_destino,
    }
    return render(request, 'suricata_dashboard.html', context)

@login_required
def ids_configuration_list(request):
    return redirect('dashboard')

@login_required
def ids_services_settings(request):
    """Redirigir a la gestión de servicios IDS en ids_ingest"""
    from django.shortcuts import redirect
    return redirect('service-management')

@login_required
def ids_logs_tester(request):
    return redirect('dashboard')

@login_required
def ids_configuration_create(request):
    return redirect('dashboard')
# def ids_configuration_create(request):
#     """Crear nueva configuración IDS/IPS"""
#     from .models import IDSConfiguration
#
#     if request.method == 'POST':
#         try:
#             config = IDSConfiguration.objects.create(
#                 nombre=request.POST.get('nombre'),
#                 sistema=request.POST.get('sistema'),
#                 version=request.POST.get('version', ''),
#                 sistema_operativo=request.POST.get('sistema_operativo'),
#                 tipo_log=request.POST.get('tipo_log'),
#                 ruta_logs=request.POST.get('ruta_logs'),
#                 patron_archivos=request.POST.get('patron_archivos', '*.log'),
#                 host_syslog=request.POST.get('host_syslog') or None,
#                 puerto_syslog=int(request.POST.get('puerto_syslog', 514)),
#                 protocolo_syslog=request.POST.get('protocolo_syslog', 'UDP'),
#                 intervalo_escaneo=int(request.POST.get('intervalo_escaneo', 60)),
#                 formato_timestamp=request.POST.get('formato_timestamp', '%m/%d-%H:%M:%S'),
#                 separador_campos=request.POST.get('separador_campos', ' '),
#                 creado_por=request.user
#             )
#
#             messages.success(request, f'Configuración "{config.nombre}" creada exitosamente')
#             return redirect('ids-configuration-list')
#
#         except Exception as e:
#             messages.error(request, f'Error al crear configuración: {str(e)}')
#
#     return render(request, 'ids_configuration_form.html')

@login_required
def ids_configuration_edit(request, config_id):
    return redirect('dashboard')

@login_required
@require_POST
def ids_service_start(request, config_id):
    return JsonResponse({'success': False})

@login_required
@require_POST
def ids_service_stop(request, config_id):
    return JsonResponse({'success': False})

@login_required
def threats_list(request):
    """Lista de amenazas detectadas"""
    from .models import ThreatLog
    from django.core.paginator import Paginator
    from django.db.models import Q
    
    # Filtros
    search = request.GET.get('search', '')
    prioridad = request.GET.get('prioridad', '')
    estado = request.GET.get('estado', '')
    configuracion = request.GET.get('configuracion', '')
    
    # Query base
    threats = ThreatLog.objects.select_related('configuracion', 'asignado_a').all()
    
    # Aplicar filtros
    if search:
        threats = threats.filter(
            Q(mensaje__icontains=search) |
            Q(ip_origen__icontains=search) |
            Q(ip_destino__icontains=search) |
            Q(regla_id__icontains=search)
        )
    
    if prioridad:
        threats = threats.filter(prioridad=prioridad)
    
    if estado:
        threats = threats.filter(estado=estado)
    
    if configuracion:
        threats = threats.filter(configuracion_id=configuracion)
    
    # Paginación
    paginator = Paginator(threats, 50)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Obtener configuraciones para el filtro
    from .models import IDSConfiguration
    configuraciones = IDSConfiguration.objects.filter(activo=True)
    
    context = {
        'page_obj': page_obj,
        'configuraciones': configuraciones,
        'filters': {
            'search': search,
            'prioridad': prioridad,
            'estado': estado,
            'configuracion': configuracion,
        }
    }
    
    return render(request, 'threats_list.html', context)

@login_required
def threat_detail(request, threat_id):
    """Detalle de una amenaza específica"""
    from .models import ThreatLog
    from django.shortcuts import get_object_or_404
    
    threat = get_object_or_404(ThreatLog, pk=threat_id)
    
    if request.method == 'POST':
        try:
            threat.estado = request.POST.get('estado')
            threat.asignado_a_id = request.POST.get('asignado_a') or None
            threat.notas = request.POST.get('notas', '')
            threat.save()
            
            messages.success(request, 'Amenaza actualizada exitosamente')
            return redirect('threat-detail', threat_id=threat_id)
            
        except Exception as e:
            messages.error(request, f'Error al actualizar amenaza: {str(e)}')
    
    # Obtener usuarios para asignación
    from django.contrib.auth.models import User
    usuarios = User.objects.filter(is_active=True)
    
    context = {
        'threat': threat,
        'usuarios': usuarios,
    }
    
    return render(request, 'threat_detail.html', context)

@login_required
@require_POST
def test_ids_configuration(request, config_id):
    """Probar configuración IDS/IPS"""
    from .models import IDSConfiguration
    from django.shortcuts import get_object_or_404
    import os
    import glob
    
    config = get_object_or_404(IDSConfiguration, pk=config_id)
    
    try:
        if config.tipo_log == 'archivo' or config.tipo_log=='eve_json':
            # Verificar si la ruta existe
            if not os.path.exists(config.ruta_logs):
                return JsonResponse({
                    'success': False,
                    'error': f'La ruta {config.ruta_logs} no existe'
                })
            
            # Buscar archivos que coincidan con el patrón
            patron_completo = os.path.join(config.ruta_logs, config.patron_archivos)
            archivos = glob.glob(patron_completo)
            
            if not archivos:
                return JsonResponse({
                    'success': False,
                    'error': f'No se encontraron archivos con el patrón {config.patron_archivos} en {config.ruta_logs}'
                })
            
            # Verificar si se puede leer el primer archivo
            try:
                with open(archivos[0], 'r', encoding='utf-8', errors='ignore') as f:
                    f.read(100)  # Leer solo los primeros 100 caracteres
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'error': f'No se puede leer el archivo {archivos[0]}: {str(e)}'
                })
            
            return JsonResponse({
                'success': True,
                'message': f'Configuración válida. Se encontraron {len(archivos)} archivos.',
                'archivos_encontrados': len(archivos),
                'primer_archivo': os.path.basename(archivos[0])
            })
        
        elif config.tipo_log == 'syslog':
            # Para syslog, solo verificar que los campos estén completos
            if not config.host_syslog:
                return JsonResponse({
                    'success': False,
                    'error': 'Debe especificar la IP del servidor syslog'
                })
            
            return JsonResponse({
                'success': True,
                'message': f'Configuración de syslog válida para {config.host_syslog}:{config.puerto_syslog}'
            })
        
        else:
            return JsonResponse({
                'success': False,
                'error': f'Tipo de log {config.tipo_log} no soportado aún'
            })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': f'Error al probar configuración: {str(e)}'
        })
# ===== VISTAS PARA CONFIGURACIÓN DE NOTIFICACIONES =====

@login_required
@require_POST
def save_notification_settings(request):
    """Guardar configuración de notificaciones"""
    if not request.user.is_superuser:
        messages.error(request, "Solo los superusuarios pueden modificar la configuración de notificaciones")
        return redirect('notification-settings')

    section = request.POST.get('section')

    # Obtener o crear configuración global
    settings_obj, created = NotificationSettings.objects.get_or_create(
        defaults={'enable_async_processing': True}
    )

    try:
        if section == 'global':
            settings_obj.enable_async_processing = 'enable_async_processing' in request.POST
            settings_obj.auto_cleanup = 'auto_cleanup' in request.POST
            settings_obj.max_retries = int(request.POST.get('max_retries', 3))
            settings_obj.cleanup_days = int(request.POST.get('cleanup_days', 30))
            settings_obj.cleanup_frequency = request.POST.get('cleanup_frequency', 'daily')

        elif section == 'email':
            settings_obj.email_batch_size = int(request.POST.get('email_batch_size', 50))
            settings_obj.email_rate_limit = int(request.POST.get('email_rate_limit', 100))

        elif section == 'sms':
            settings_obj.sms_provider = request.POST.get('sms_provider', '')
            settings_obj.sms_api_key = request.POST.get('sms_api_key', '')
            settings_obj.sms_rate_limit = int(request.POST.get('sms_rate_limit', 20))

        elif section == 'slack':
            settings_obj.slack_webhook_url = request.POST.get('slack_webhook_url', '')
            settings_obj.slack_default_channel = request.POST.get('slack_default_channel', '#alerts')

        elif section == 'teams':
            settings_obj.teams_webhook_url = request.POST.get('teams_webhook_url', '')

        elif section == 'push':
            settings_obj.push_enabled = 'push_enabled' in request.POST
            settings_obj.push_vapid_key = request.POST.get('push_vapid_key', '')

        settings_obj.save()
        messages.success(request, f"Configuración de {section} guardada exitosamente")

    except Exception as e:
        messages.error(request, f"Error al guardar configuración: {str(e)}")

    return redirect('notification-settings')


@login_required
def notification_settings(request):
    """Vista principal de configuración de notificaciones"""
    if not request.user.is_superuser:
        messages.error(request, "Solo los superusuarios pueden acceder a la configuración de notificaciones")
        return redirect('dashboard')

    # Obtener configuración global
    settings_obj, created = NotificationSettings.objects.get_or_create(
        defaults={'enable_async_processing': True}
    )

    # Obtener datos para la vista
    context = {
        'settings': settings_obj,
        'email_configs': EmailConfiguration.objects.all(),
        'channels': NotificationChannel.objects.all(),
        'templates': NotificationTemplate.objects.all(),
        'stats': get_notification_stats(),
    }

    return render(request, 'notification_settings.html', context)


@login_required
@require_POST
def add_notification_channel(request):
    """Agregar nuevo canal de notificación"""
    if not request.user.is_superuser:
        messages.error(request, "Solo los superusuarios pueden gestionar canales")
        return redirect('notification-settings')

    try:
        channel = NotificationChannel.objects.create(
            name=request.POST.get('name'),
            channel_type=request.POST.get('channel_type'),
            is_active='is_active' in request.POST,
            config={},  # Configuración específica se puede agregar después
            created_by=request.user
        )
        messages.success(request, f"Canal '{channel.name}' creado exitosamente")
    except Exception as e:
        messages.error(request, f"Error al crear canal: {str(e)}")

    return redirect('notification-settings')


@login_required
@require_POST
def add_notification_template(request):
    """Agregar nueva plantilla de notificación"""
    if not request.user.is_superuser:
        messages.error(request, "Solo los superusuarios pueden gestionar plantillas")
        return redirect('notification-settings')

    try:
        template = NotificationTemplate.objects.create(
            name=request.POST.get('name'),
            template_type=request.POST.get('template_type'),
            event_type=request.POST.get('event_type'),
            subject_template=request.POST.get('subject_template', ''),
            body_template=request.POST.get('body_template'),
            is_active='is_active' in request.POST,
            created_by=request.user
        )
        messages.success(request, f"Plantilla '{template.name}' creada exitosamente")
    except Exception as e:
        messages.error(request, f"Error al crear plantilla: {str(e)}")

    return redirect('notification-settings')


@login_required
@require_POST
def delete_notification_channel(request, channel_id):
    """Eliminar canal de notificación"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Permisos insuficientes'})

    try:
        channel = NotificationChannel.objects.get(id=channel_id)
        channel_name = channel.name
        channel.delete()
        return JsonResponse({'success': True, 'message': f'Canal {channel_name} eliminado'})
    except NotificationChannel.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Canal no encontrado'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_POST
def delete_notification_template(request, template_id):
    """Eliminar plantilla de notificación"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Permisos insuficientes'})

    try:
        template = NotificationTemplate.objects.get(id=template_id)
        template_name = template.name
        template.delete()
        return JsonResponse({'success': True, 'message': f'Plantilla {template_name} eliminada'})
    except NotificationTemplate.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Plantilla no encontrada'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
def get_notification_stats(request):
    """Obtener estadísticas de notificaciones"""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permisos insuficientes'})

    stats = get_notification_stats()
    return JsonResponse(stats)


def get_notification_stats():
    """Función helper para obtener estadísticas"""
    from django.db.models import Count, Q
    from django.utils import timezone

    # Estadísticas generales
    total_notifications = Notification.objects.count()

    # Estadísticas de hoy
    today = timezone.now().date()
    sent_today = NotificationLog.objects.filter(
        sent_at__date=today,
        status='SENT'
    ).count()

    # Estadísticas de cola
    queue_stats = NotificationQueue.objects.aggregate(
        pending=Count('id', filter=Q(status='PENDING')),
        processing=Count('id', filter=Q(status='PROCESSING')),
        sent=Count('id', filter=Q(status='SENT')),
        failed=Count('id', filter=Q(status='FAILED')),
    )

    return {
        'total_notifications': total_notifications,
        'sent_today': sent_today,
        'pending': queue_stats['pending'] or 0,
        'processing': queue_stats['processing'] or 0,
        'sent': queue_stats['sent'] or 0,
        'failed': queue_stats['failed'] or 0,
    }


@login_required
@require_POST
def test_notification_channel(request, channel_id):
    """Probar un canal de notificación"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Permisos insuficientes'})

    try:
        channel = NotificationChannel.objects.get(id=channel_id)

        # Crear notificación de prueba
        notification = Notification.objects.create(
            user=request.user,
            title=f"Prueba de Canal: {channel.name}",
            message=f"Esta es una notificación de prueba para el canal {channel.get_channel_type_display()}",
            event_type='SYSTEM_ALERT'
        )

        # Enviar a través del servicio mejorado
        enhanced_notification_service.send_notification(
            notification,
            channels=[channel],
            priority=1
        )

        return JsonResponse({
            'success': True,
            'message': f'Notificación de prueba enviada a través de {channel.name}'
        })

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_POST
def toggle_notification_channel(request, channel_id):
    """Activar/desactivar canal de notificación"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Permisos insuficientes'})

    try:
        channel = NotificationChannel.objects.get(id=channel_id)
        channel.is_active = not channel.is_active
        channel.save()

        status = "activado" if channel.is_active else "desactivado"
        return JsonResponse({
            'success': True,
            'message': f'Canal {channel.name} {status}',
            'is_active': channel.is_active
        })

    except NotificationChannel.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Canal no encontrado'})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
@require_POST
def cleanup_notifications(request):
    """Limpiar notificaciones antiguas manualmente"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'Permisos insuficientes'})

    try:
        enhanced_notification_service.cleanup_old_notifications()
        return JsonResponse({
            'success': True,
            'message': 'Limpieza de notificaciones completada'
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
def notification_queue_status(request):
    """Obtener estado de la cola de notificaciones"""
    if not request.user.is_superuser:
        return JsonResponse({'error': 'Permisos insuficientes'})

    queue_stats = enhanced_notification_service.get_queue_stats()
    return JsonResponse(queue_stats)

# ==================== VISTAS PARA CONFIGURACIÓN DE OLLAMA ====================

@login_required
def ollama_config(request):
    """Vista de configuración de Ollama"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta configuración')
        return redirect('dashboard')

    # Obtener configuración actual o crear una por defecto
    try:
        config = OllamaConfig.get_active_config()
        if not config:
            # Intentar crear configuración por defecto
            config = OllamaConfig.objects.create(created_by=request.user)
    except Exception as e:
        # Si hay error de base de datos (columnas faltantes), crear objeto temporal
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Error obteniendo configuración Ollama: {e}. Usando configuración por defecto.")

        # Crear objeto temporal con valores por defecto para todos los campos
        class TempConfig:
            def __init__(self):
                # Campos básicos
                self.ollama_url = "http://localhost:11434"
                self.ollama_model = "mistral:7b"  # Modelo más robusto
                self.max_tokens = 2000
                self.temperature = 0.3
                self.timeout_seconds = 30
                self.is_active = True
                # Campos de permisos
                self.can_read_snort_logs = True
                self.can_read_suricata_logs = True
                self.can_read_incidents = True
                self.can_read_reports = True
                self.can_read_users = False
                self.can_read_system_logs = False
                # Campos de automatización
                self.auto_generate_reports = False
                self.auto_send_emails = False
                self.auto_create_incidents = False
                # Campos de umbrales
                self.alert_threshold_critical = 10
                self.alert_threshold_high = 50
                self.auto_report_interval_hours = 24

        config = TempConfig()

    context = {
        'config': config,
    }
    return render(request, 'ollama_config.html', context)

@login_required
@require_POST
def ollama_config_save(request):
    """Guardar configuración de Ollama"""
    if not request.user.is_superuser:
        return JsonResponse({'success': False, 'error': 'No tienes permisos'})

    try:
        # Obtener o crear configuración
        config, created = OllamaConfig.objects.get_or_create(
            defaults={'created_by': request.user}
        )

        # Actualizar campos básicos (siempre disponibles)
        config.ollama_url = request.POST.get('ollama_url', config.ollama_url)
        config.ollama_model = request.POST.get('ollama_model', config.ollama_model)
        config.max_tokens = int(request.POST.get('max_tokens', config.max_tokens))
        config.temperature = float(request.POST.get('temperature', config.temperature))
        config.timeout_seconds = int(request.POST.get('timeout_seconds', config.timeout_seconds))
        config.is_active = request.POST.get('is_active') == 'on'

        # Campos básicos (siempre existen)
        config.ollama_url = request.POST.get('ollama_url', config.ollama_url)
        config.ollama_model = request.POST.get('ollama_model', config.ollama_model)
        config.max_tokens = int(request.POST.get('max_tokens', config.max_tokens))
        config.temperature = float(request.POST.get('temperature', config.temperature))
        config.timeout_seconds = int(request.POST.get('timeout_seconds', config.timeout_seconds))
        config.is_active = request.POST.get('is_active') == 'on'

        # Intentar asignar campos adicionales si existen en el modelo
        permission_fields = [
            'can_read_snort_logs', 'can_read_suricata_logs', 'can_read_incidents',
            'can_read_reports', 'can_read_users', 'can_read_system_logs',
            'auto_generate_reports', 'auto_send_emails', 'auto_create_incidents'
        ]

        threshold_fields = [
            'alert_threshold_critical', 'alert_threshold_high', 'auto_report_interval_hours'
        ]

        # Asignar campos de permisos si existen
        for field in permission_fields:
            if hasattr(config, field):
                setattr(config, field, request.POST.get(field) == 'on')

        # Asignar campos de umbrales si existen
        for field in threshold_fields:
            if hasattr(config, field):
                default_values = {
                    'alert_threshold_critical': 10,
                    'alert_threshold_high': 50,
                    'auto_report_interval_hours': 24
                }
                setattr(config, field, int(request.POST.get(field, default_values.get(field, 0))))

        # Guardar configuración con manejo de errores
        try:
            # Intentar guardar todos los campos
            config.save()
        except Exception as e:
            # Si falla por columnas faltantes, intentar guardar solo campos básicos
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Error guardando configuración completa, intentando campos básicos: {e}")

            try:
                # Solo guardar campos que sabemos que existen
                config.save(update_fields=['ollama_url', 'ollama_model', 'max_tokens', 'temperature', 'timeout_seconds', 'is_active'])

                # Intentar actualizar campos adicionales con SQL raw si existen
                from django.db import connection
                cursor = connection.cursor()

                # Campos de permisos
                permission_fields = [
                    'can_read_snort_logs', 'can_read_suricata_logs', 'can_read_incidents',
                    'can_read_reports', 'can_read_users', 'can_read_system_logs',
                    'auto_generate_reports', 'auto_send_emails', 'auto_create_incidents'
                ]

                # Campos de umbrales
                threshold_fields = [
                    'alert_threshold_critical', 'alert_threshold_high', 'auto_report_interval_hours'
                ]

                # Construir query de actualización
                update_fields = []
                update_values = []

                for field in permission_fields:
                    if hasattr(config, field):
                        update_fields.append(f"{field} = %s")
                        update_values.append(getattr(config, field))

                for field in threshold_fields:
                    if hasattr(config, field):
                        update_fields.append(f"{field} = %s")
                        update_values.append(getattr(config, field))

                if update_fields:
                    query = f"UPDATE VANT_SIEM_ollamaconfig SET {', '.join(update_fields)}, updated_at = NOW() WHERE id = %s"
                    update_values.append(config.id)
                    try:
                        cursor.execute(query, update_values)
                        logger.info(f"Campos adicionales guardados exitosamente para config ID {config.id}")
                    except Exception as sql_e:
                        logger.warning(f"No se pudieron guardar campos adicionales con SQL: {sql_e}")

            except Exception as e2:
                logger.error(f"Error crítico guardando configuración básica: {e2}")
                return JsonResponse({'success': False, 'error': f'Error guardando configuración: {str(e2)}'})

        # Log del evento
        event_logger.log_event(
            user=request.user,
            event_type='OLLAMA_CONFIG_UPDATED',
            description=f'Configuración de Ollama actualizada: {config.ollama_model}',
            details={
                'ollama_url': config.ollama_url,
                'ollama_model': config.ollama_model,
                'is_active': config.is_active
            }
        )

        return JsonResponse({
            'success': True,
            'message': 'Configuración guardada exitosamente'
        })

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

# ==================== VISTAS PARA ANÁLISIS CON IA (OLLAMA) ====================

@login_required
def analysis_ollama(request):
    """Vista principal de análisis inteligente con Ollama"""
    return render(request, 'analysis_ollama.html')

@login_required
@require_GET
def ollama_test_connection(request):
    """Probar conexión con Ollama"""
    from .ollama_service import ollama_service
    result = ollama_service.test_connection()
    return JsonResponse(result)

@login_required
@require_POST
def ollama_analyze_trends(request):
    """Analizar tendencias de seguridad usando IA"""
    from .ollama_service import ollama_service
    try:
        hours = int(request.POST.get('hours', 24))
        result = ollama_service.analyze_security_trends(hours)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def ollama_analyze_ip(request):
    """Analizar comportamiento de una IP usando IA"""
    from .ollama_service import ollama_service
    try:
        # Intentar obtener datos del POST (form data)
        ip = request.POST.get('ip', '').strip()
        hours = int(request.POST.get('hours', 24))

        # Si no hay IP en POST, intentar JSON
        if not ip and request.content_type == 'application/json':
            try:
                import json
                data = json.loads(request.body)
                ip = data.get('ip', '').strip()
                hours = int(data.get('hours', 24))
            except (json.JSONDecodeError, KeyError):
                pass

        if not ip:
            return JsonResponse({'success': False, 'error': 'IP requerida'})

        result = ollama_service.analyze_ip_behavior(ip, hours)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def ollama_correlate_events(request):
    """Correlacionar eventos usando IA"""
    from .ollama_service import ollama_service
    try:
        time_window = int(request.POST.get('time_window', 60))
        result = ollama_service.correlate_events(time_window)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def ollama_generate_report(request):
    """Generar reporte ejecutivo usando IA"""
    from .ollama_service import ollama_service
    try:
        report_type = request.POST.get('type', 'threat')
        hours = int(request.POST.get('hours', 24))
        result = ollama_service.generate_threat_report(hours)
        return JsonResponse(result)
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def ollama_send_report_email(request):
    """Enviar reporte por email usando IA"""
    from .ollama_service import ollama_service
    from .email_service import send_system_alert
    try:
        report_type = request.POST.get('type', 'threat')
        hours = int(request.POST.get('hours', 24))

        # Generar el reporte
        report_result = ollama_service.generate_threat_report(hours)

        if not report_result.get('success'):
            return JsonResponse({'success': False, 'error': 'No se pudo generar el reporte'})

        # Crear contenido del email
        subject = f"VANT-SIEM - Reporte Ejecutivo IA: {report_type.title()}"

        # Formatear el reporte para email
        report_data = report_result.get('report', {})
        body = f"""
        <html>
        <body>
            <h2>Reporte Ejecutivo de Seguridad - Análisis IA</h2>
            <p><strong>Tipo de Reporte:</strong> {report_type.title()}</p>
            <p><strong>Período Analizado:</strong> {hours} horas</p>
            <p><strong>Generado:</strong> {report_result.get('metadata', {}).get('generated_at', 'N/A')}</p>

            <h3>Resumen Ejecutivo</h3>
            <p>{report_data.get('executive_summary', 'No disponible')}</p>

            <h3>Alertas Críticas</h3>
            <ul>
        """

        critical_alerts = report_data.get('critical_alerts', [])
        if isinstance(critical_alerts, list):
            for alert in critical_alerts[:5]:  # Limitar a 5 alertas
                body += f"<li>{alert}</li>"
        else:
            body += f"<li>{critical_alerts}</li>"

        body += """
            </ul>

            <h3>Recomendaciones</h3>
            <ul>
        """

        recommendations = report_data.get('recommendations', [])
        if isinstance(recommendations, list):
            for rec in recommendations[:5]:  # Limitar a 5 recomendaciones
                body += f"<li>{rec}</li>"
        else:
            body += f"<li>{recommendations}</li>"

        body += f"""
            </ul>

            <h3>Métricas Clave</h3>
            <ul>
                <li>Alertas no reconocidas: {report_result.get('metadata', {}).get('unacknowledged_alerts', 0)}</li>
                <li>Flujos sospechosos: {report_result.get('metadata', {}).get('suspicious_flows', 0)}</li>
            </ul>

            <hr>
            <p><em>Reporte generado automáticamente por VANT-SIEM con análisis de IA</em></p>
        </body>
        </html>
        """

        # Enviar email al usuario actual
        send_system_alert(
            user=request.user,
            alert_type='AI_REPORT',
            subject=subject,
            body=body,
            priority='HIGH'
        )

        # Log del evento
        event_logger.log_event(
            user=request.user,
            event_type='AI_REPORT_SENT',
            description=f'Reporte IA enviado por email: {report_type}',
            details={
                'report_type': report_type,
                'hours': hours,
                'recipient': request.user.email
            }
        )

        return JsonResponse({'success': True, 'message': 'Reporte enviado por email'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@require_POST
def ollama_cross_reference(request):
    """Cruzar información inteligente en la base de datos usando IA"""
    from .ollama_service import ollama_service
    from opensearch_ui.models import SnortLog, SuricataEveAlert
    from EVENT_M.models import Incidente, Reporte
    from django.contrib.auth.models import User

    try:
        query = request.POST.get('query', '').strip()
        model_type = request.POST.get('model_type', 'all')

        if not query:
            return JsonResponse({'success': False, 'error': 'Consulta requerida'})

        # Recopilar datos según el tipo de modelo
        data_context = {}

        if model_type in ['all', 'snort']:
            # Datos de Snort
            snort_recent = SnortLog.objects.all().order_by('-timestamp')[:100]
            data_context['snort_logs'] = [
                {
                    'timestamp': log.timestamp.isoformat(),
                    'src_ip': log.src_ip,
                    'dst_ip': log.dst_ip,
                    'protocol': log.protocol,
                    'severity': log.severity,
                    'message': log.message[:200]  # Limitar longitud
                } for log in snort_recent
            ]

        if model_type in ['all', 'suricata']:
            # Datos de Suricata
            suricata_recent = SuricataEveAlert.objects.all().order_by('-timestamp')[:100]
            data_context['suricata_alerts'] = [
                {
                    'timestamp': alert.timestamp.isoformat(),
                    'src_ip': alert.src_ip,
                    'dest_ip': alert.dest_ip,
                    'severity': alert.severity,
                    'signature': alert.signature[:200],
                    'category': alert.category
                } for alert in suricata_recent
            ]

        if model_type in ['all', 'events']:
            # Datos de incidentes y reportes (con verificación de permisos)
            from .ollama_service import ollama_service
            if ollama_service.can_read_incidents:
                incidentes_recent = Incidente.objects.all().order_by('-fecha_hora')[:50]
                data_context['incidentes'] = [
                    {
                        'titulo': inc.nombre_incidente,
                        'estado': inc.estado_solucion,
                        'categoria': 'Incidente de seguridad',
                        'fecha': inc.fecha_hora.isoformat()
                    } for inc in incidentes_recent
                ]
            else:
                data_context['incidentes'] = []
                data_context['incidentes_access_denied'] = True

            if ollama_service.can_read_reports:
                reportes_recent = Reporte.objects.all().order_by('-fecha_hora')[:50]
                data_context['reportes'] = [
                    {
                        'titulo': rep.nombre_informante,
                        'estado': rep.estado_solucion,
                        'area': rep.area.nombre if rep.area else 'N/A',
                        'fecha': rep.fecha_hora.isoformat()
                    } for rep in reportes_recent
                ]
            else:
                data_context['reportes'] = []
                data_context['reportes_access_denied'] = True

        # Prompt optimizado para análisis cruzado
        system_prompt = """Eres un analista de ciberseguridad experto. Analiza los datos proporcionados y responde de manera precisa y técnica."""

        analysis_prompt = f"""
CONSULTA: {query}

DATOS DISPONIBLES:
{json.dumps(data_context, indent=2, default=str)}

INSTRUCCIONES:
• Analiza patrones y anomalías en los datos
• Proporciona insights específicos y accionables
• Identifica correlaciones entre diferentes fuentes de datos
• Incluye recomendaciones de seguridad cuando aplique
• Sé conciso pero completo
"""

        # Usar Ollama para analizar
        ai_response = ollama_service._call_ollama(analysis_prompt, system_prompt)

        if ai_response:
            # Log del evento
            event_logger.log_event(
                user=request.user,
                event_type='AI_CROSS_REFERENCE',
                description=f'Consulta IA: {query[:100]}...',
                details={
                    'query': query,
                    'model_type': model_type,
                    'response_length': len(ai_response)
                }
            )

            return JsonResponse({
                'success': True,
                'results': {
                    'query': query,
                    'model_type': model_type,
                    'analysis': ai_response,
                    'data_summary': {
                        'snort_logs_count': len(data_context.get('snort_logs', [])),
                        'suricata_alerts_count': len(data_context.get('suricata_alerts', [])),
                        'incidentes_count': len(data_context.get('incidentes', [])),
                        'reportes_count': len(data_context.get('reportes', []))
                    }
                }
            })
        else:
            return JsonResponse({'success': False, 'error': 'No se pudo procesar la consulta con IA'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)})




# ===== VISTAS PARA CONFIGURACION LDAP =====

@login_required
def ldap_config_list(request):
    """Lista todas las configuraciones LDAP"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    configs = LDAPConfig.objects.all()
    return render(request, 'ldap_config_list.html', {'configs': configs})


@login_required
def ldap_config_create(request):
    """Crea una nueva configuración LDAP"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    if request.method == 'POST':
        form_data = {
            'nombre': request.POST.get('nombre'),
            'servidor': request.POST.get('servidor'),
            'puerto': request.POST.get('puerto', 389),
            'use_ssl': request.POST.get('use_ssl') == 'on',
            'use_starttls': request.POST.get('use_starttls') == 'on',
            'cert_path': request.POST.get('cert_path') or None,
            'bind_dn': request.POST.get('bind_dn') or None,
            'bind_password': request.POST.get('bind_password') or None,
            'user_search_base': request.POST.get('user_search_base'),
            'user_search_filter': request.POST.get('user_search_filter') or '(uid={username})',
            'group_search_base': request.POST.get('group_search_base') or None,
            'group_search_filter': request.POST.get('group_search_filter') or '(member={user_dn})',
            'username_attr': request.POST.get('username_attr') or 'uid',
            'first_name_attr': request.POST.get('first_name_attr') or 'givenName',
            'last_name_attr': request.POST.get('last_name_attr') or 'sn',
            'email_attr': request.POST.get('email_attr') or 'mail',
            'is_active': request.POST.get('is_active') == 'on',
            'is_default': request.POST.get('is_default') == 'on',
            'auto_create_user': request.POST.get('auto_create_user') == 'on',
        }
        
        config = LDAPConfig.objects.create(**form_data)
        messages.success(request, f'Configuración LDAP "{config.nombre}" creada exitosamente.')
        return redirect('ldap-config-list')
    
    return render(request, 'ldap_config_form.html', {'action': 'create'})


@login_required
def ldap_config_edit(request, config_id):
    """Edita una configuración LDAP existente"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    try:
        config = LDAPConfig.objects.get(id=config_id)
    except LDAPConfig.DoesNotExist:
        messages.error(request, 'Configuración no encontrada')
        return redirect('ldap-config-list')
    
    if request.method == 'POST':
        config.nombre = request.POST.get('nombre')
        config.servidor = request.POST.get('servidor')
        config.puerto = request.POST.get('puerto', 389)
        config.use_ssl = request.POST.get('use_ssl') == 'on'
        config.use_starttls = request.POST.get('use_starttls') == 'on'
        config.cert_path = request.POST.get('cert_path') or None
        config.bind_dn = request.POST.get('bind_dn') or None
        config.bind_password = request.POST.get('bind_password') or None
        config.user_search_base = request.POST.get('user_search_base')
        config.user_search_filter = request.POST.get('user_search_filter') or '(uid={username})'
        config.group_search_base = request.POST.get('group_search_base') or None
        config.group_search_filter = request.POST.get('group_search_filter') or '(member={user_dn})'
        config.username_attr = request.POST.get('username_attr') or 'uid'
        config.first_name_attr = request.POST.get('first_name_attr') or 'givenName'
        config.last_name_attr = request.POST.get('last_name_attr') or 'sn'
        config.email_attr = request.POST.get('email_attr') or 'mail'
        config.is_active = request.POST.get('is_active') == 'on'
        config.is_default = request.POST.get('is_default') == 'on'
        config.auto_create_user = request.POST.get('auto_create_user') == 'on'
        config.save()
        
        messages.success(request, f'Configuración LDAP "{config.nombre}" actualizada exitosamente.')
        return redirect('ldap-config-list')
    
    return render(request, 'ldap_config_form.html', {'action': 'edit', 'config': config})


@login_required
def ldap_config_delete(request, config_id):
    """Elimina una configuración LDAP"""
    if not request.user.is_superuser:
        messages.error(request, 'No tienes permisos para acceder a esta sección')
        return redirect('dashboard')
    
    try:
        config = LDAPConfig.objects.get(id=config_id)
        nombre = config.nombre
        config.delete()
        messages.success(request, f'Configuración LDAP "{nombre}" eliminada exitosamente.')
    except LDAPConfig.DoesNotExist:
        messages.error(request, 'Configuración no encontrada')
    
    return redirect('ldap-config-list')
