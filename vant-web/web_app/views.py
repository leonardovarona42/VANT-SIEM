import json
import logging

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_protect
from django.conf import settings

from . import http_client

logger = logging.getLogger("vant_web.views")


def _require_auth(request):
    if request.session.get("jwt_token"):
        return True
    if hasattr(request, "user") and request.user.is_authenticated:
        return True
    return False


def _redirect_login(request):
    return redirect(settings.LOGIN_URL)


# ── Auth Views ────────────────────────────────────────────────────────

def login_view(request):
    if request.session.get("jwt_token"):
        return redirect("web:dashboard")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        if not username or not password:
            messages.error(request, "Ingrese usuario y contraseña.")
            return render(request, "web_app/login.html")

        result = http_client.auth_login(username, password)
        if result and result.get("access"):
            request.session["jwt_token"] = result["access"]
            request.session["refresh_token"] = result.get("refresh", "")
            user_info = result.get("user", {})
            request.session["username"] = user_info.get("username", username)
            request.session["is_superuser"] = user_info.get("is_superuser", user_info.get("role") == "admin")
            request.session["user_id"] = user_info.get("id")
            request.session.save()
            return redirect("web:dashboard")
        elif result:
            messages.error(
                request,
                result.get("error", "Credenciales inválidas"),
            )
        else:
            messages.error(
                request,
                "Servicio de autenticación no disponible. Intente más tarde.",
            )

    return render(request, "web_app/login.html")


def logout_view(request):
    token = request.session.get("jwt_token")
    if token:
        http_client.auth_logout(request)
    request.session.flush()
    messages.info(request, "Sesión cerrada correctamente.")
    return redirect(settings.LOGIN_URL)


# ── Dashboard ─────────────────────────────────────────────────────────

def dashboard_view(request):
    if not _require_auth(request):
        return _redirect_login(request)

    ctx = {}

    try:
        agents = http_client.get_agents(request, page_size=1)
        ctx["total_agents"] = agents.get("count", 0)
    except Exception:
        ctx["total_agents"] = 0

    try:
        inv_stats = http_client.get_inventory_stats(request)
        ctx["online_agents"] = inv_stats.get("online_agents", 0)
        total_agents = inv_stats.get("total_agents", 0)
        ctx["offline_agents"] = max(0, total_agents - ctx["online_agents"])
    except Exception:
        ctx["online_agents"] = 0
        ctx["offline_agents"] = 0

    try:
        events = http_client.get_events(request, page=1, page_size=1)
        ctx["total_events"] = events.get("count", 0)
    except Exception:
        ctx["total_events"] = 0

    try:
        incidents = http_client.get_incidents(request)
        ctx["total_incidents"] = incidents.get("count", 0)
    except Exception:
        ctx["total_incidents"] = 0

    try:
        aegis_stats = http_client.get_aegis_stats(request)
        ctx["open_incidents"] = aegis_stats.get("today", 0)
    except Exception:
        ctx["open_incidents"] = 0

    try:
        recent_events = http_client.get_events(request, page=1, page_size=10)
        ctx["recent_events"] = recent_events.get("results", [])
    except Exception:
        ctx["recent_events"] = []

    try:
        recent_incidents = http_client.get_incidents(request)
        ctx["recent_incidents"] = recent_incidents.get("results", [])[:10]
    except Exception:
        ctx["recent_incidents"] = []

    return render(request, "web_app/dashboard.html", ctx)


# ── Logs Views ────────────────────────────────────────────────────────

def events_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    params = {
        "page": request.GET.get("page", 1),
        "page_size": request.GET.get("page_size", 50),
    }
    for key in ("source_type", "severity", "host_ip", "category", "q", "hours", "ordering"):
        val = request.GET.get(key)
        if val:
            params[key] = val

    try:
        data = http_client.get_events(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio de logs.")

    return render(request, "web_app/events_list.html", {
        "events": data.get("results", []),
        "total": data.get("count", 0),
        "page": int(params.get("page", 1)),
        "page_size": int(params.get("page_size", 50)),
        "filters": {
            "source_type": request.GET.get("source_type", ""),
            "severity": request.GET.get("severity", ""),
            "host_ip": request.GET.get("host_ip", ""),
            "category": request.GET.get("category", ""),
            "search": request.GET.get("q", ""),
            "hours": request.GET.get("hours", "24"),
        },
    })


def event_detail(request, event_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        event = http_client.get_event(event_id, request)
    except Exception:
        event = None

    if not event:
        messages.error(request, "Evento no encontrado o servicio no disponible.")
        return redirect("web:events-list")

    return render(request, "web_app/event_detail.html", {"event": event})


def logs_discovery(request):
    if not _require_auth(request):
        return _redirect_login(request)

    ctx = {}
    try:
        sources = http_client.get_log_sources(request)
        ctx["sources"] = sources.get("results", [])
        ctx["total_sources"] = sources.get("count", 0)
    except Exception:
        ctx["sources"] = []
        ctx["total_sources"] = 0

    try:
        stats = http_client.get_logs_stats(request)
        ctx["total_events"] = stats.get("total_events", 0)
    except Exception:
        ctx["total_events"] = 0

    return render(request, "web_app/logs_discovery.html", ctx)


def suricata_dashboard(request):
    if not _require_auth(request):
        return _redirect_login(request)

    hours = int(request.GET.get("hours", 24))
    ctx = {"hours": hours}

    try:
        stats = http_client.get_logs_stats(request, source_type="suricata", hours=hours)
        ctx.update(stats)
    except Exception:
        pass

    return render(request, "web_app/suricata_dashboard.html", ctx)


# ── DLP / Aegis Views ────────────────────────────────────────────────

def incidents_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    params = {}
    for key in ("severity", "status", "classification", "channel", "q", "hours"):
        val = request.GET.get(key)
        if val:
            params[key] = val
    params["page"] = request.GET.get("page", 1)
    params["page_size"] = request.GET.get("page_size", 50)

    try:
        data = http_client.get_incidents(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio AEGIS.")

    return render(request, "web_app/incidents_list.html", {
        "incidents": data.get("results", []),
        "total": data.get("count", 0),
        "page": int(params.get("page", 1)),
        "page_size": int(params.get("page_size", 50)),
        "severity": request.GET.get("severity", ""),
        "status_filter": request.GET.get("status", ""),
        "classification": request.GET.get("classification", ""),
        "channel": request.GET.get("channel", ""),
        "search": request.GET.get("q", ""),
    })


def incident_detail(request, incident_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        incident = http_client.get_incident(incident_id, request)
    except Exception:
        incident = None

    if not incident:
        messages.error(request, "Incidente no encontrado o servicio no disponible.")
        return redirect("web:incidents-list")

    return render(request, "web_app/incident_detail.html", {"incident": incident})


@csrf_protect
@require_POST
def incident_acknowledge(request, incident_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        ok = http_client.acknowledge_incident(incident_id, request)
        if ok:
            messages.success(request, "Incidente marcado como reconocido.")
        else:
            messages.error(request, "Error al reconocer el incidente.")
    except Exception:
        messages.error(request, "Servicio no disponible.")

    return redirect("web:incident-detail", incident_id=incident_id)


@csrf_protect
@require_POST
def incident_resolve(request, incident_id):
    if not _require_auth(request):
        return _redirect_login(request)

    data = {
        "status": request.POST.get("status", "resolved"),
        "notes": request.POST.get("notes", ""),
    }

    try:
        ok = http_client.resolve_incident(incident_id, data, request)
        if ok:
            messages.success(request, "Incidente resuelto.")
        else:
            messages.error(request, "Error al resolver el incidente.")
    except Exception:
        messages.error(request, "Servicio no disponible.")

    return redirect("web:incident-detail", incident_id=incident_id)


def policies_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        data = http_client.get_policies(request)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio AEGIS.")

    return render(request, "web_app/policies_list.html", {
        "policies": data.get("results", []),
        "total": data.get("count", 0),
    })


@csrf_protect
def policy_create(request):
    if not _require_auth(request):
        return _redirect_login(request)

    if request.method == "POST":
        data = {
            "name": request.POST.get("name", ""),
            "description": request.POST.get("description", ""),
            "code": request.POST.get("code", ""),
            "is_active": request.POST.get("is_active") == "on",
        }
        result = http_client.create_policy(data, request)
        if result:
            messages.success(request, "Política creada exitosamente.")
            return redirect("web:policies-list")
        else:
            messages.error(request, "Error al crear la política. Verifique los datos.")

    return render(request, "web_app/policy_form.html", {"title": "Crear Política", "policy": None})


@csrf_protect
def policy_edit(request, code):
    if not _require_auth(request):
        return _redirect_login(request)

    if request.method == "POST":
        data = {
            "name": request.POST.get("name", ""),
            "description": request.POST.get("description", ""),
            "is_active": request.POST.get("is_active") == "on",
        }
        result = http_client.update_policy(code, data, request)
        if result:
            messages.success(request, "Política actualizada exitosamente.")
            return redirect("web:policies-list")
        else:
            messages.error(request, "Error al actualizar la política.")

    try:
        policy = http_client.get_policy(code, request)
    except Exception:
        policy = None

    return render(request, "web_app/policy_form.html", {
        "title": f"Editar: {code}",
        "policy": policy,
    })


@csrf_protect
def policy_delete(request, code):
    if not _require_auth(request):
        return _redirect_login(request)

    if request.method == "POST":
        ok = http_client.delete_policy(code, request)
        if ok:
            messages.success(request, f"Política {code} eliminada.")
        else:
            messages.error(request, "Error al eliminar la política.")
        return redirect("web:policies-list")

    return redirect("web:policies-list")


# ── Inventory Views ───────────────────────────────────────────────────

def inventory_dashboard(request):
    if not _require_auth(request):
        return _redirect_login(request)

    ctx = {}
    try:
        stats = http_client.get_inventory_stats(request)
        ctx["total"] = stats.get("total", 0)
        ctx["online"] = stats.get("online", 0)
        ctx["offline"] = stats.get("offline", 0)
        ctx["pending"] = stats.get("pending", 0)
        ctx["health_pct"] = stats.get("health_pct", 0)
        ctx["os_dist"] = stats.get("os_distribution", [])
        ctx["recent_agents"] = stats.get("recent_agents", [])
    except Exception:
        ctx["total"] = 0
        ctx["online"] = 0
        ctx["offline"] = 0
        ctx["pending"] = 0
        ctx["health_pct"] = 0
        ctx["os_dist"] = []
        ctx["recent_agents"] = []

    return render(request, "web_app/inventory_dashboard.html", ctx)


def agents_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    params = {"page": request.GET.get("page", 1)}
    for key in ("status", "os_type", "search"):
        val = request.GET.get(key)
        if val:
            params[key] = val

    try:
        data = http_client.get_agents(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio de inventario.")

    return render(request, "web_app/agents_list.html", {
        "agents": data.get("results", []),
        "total": data.get("count", 0),
        "page": int(params.get("page", 1)),
        "status_filter": request.GET.get("status", ""),
        "os_filter": request.GET.get("os_type", ""),
        "search": request.GET.get("search", ""),
    })


def agent_detail(request, agent_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        agent = http_client.get_agent(agent_id, request)
    except Exception:
        agent = None

    if not agent:
        messages.error(request, "Agente no encontrado o servicio no disponible.")
        return redirect("web:agents-list")

    hardware = None
    try:
        hardware = http_client.get_agent_hardware(agent_id, request)
    except Exception:
        pass

    software = []
    try:
        sw_data = http_client.get_agent_software(agent_id, request)
        software = sw_data.get("results", [])
    except Exception:
        pass

    return render(request, "web_app/agent_detail.html", {
        "agent": agent,
        "hardware": hardware,
        "software": software,
    })


@csrf_protect
def agent_config_view(request, agent_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        agent = http_client.get_agent(agent_id, request)
    except Exception:
        agent = None

    if not agent:
        messages.error(request, "Agente no encontrado.")
        return redirect("web:agents-list")

    if request.method == "POST":
        try:
            config_data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            config_data = {"config": request.POST.dict()}

        import requests as req_lib
        s = http_client._get_session()
        headers = http_client._auth_headers(request)
        try:
            resp = s.post(
                f"{settings.INVENTORY_SERVICE_URL}/api/agents/{agent_id}/config/",
                json=config_data,
                headers=headers,
            )
            if resp.ok:
                messages.success(request, "Configuración enviada al agente.")
            else:
                messages.error(request, "Error al enviar configuración.")
        except Exception:
            messages.error(request, "Servicio no disponible.")

        return redirect("web:agent-config", agent_id=agent_id)

    return render(request, "web_app/agent_config.html", {"agent": agent})


def software_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    params = {"page": request.GET.get("page", 1)}
    for key in ("search", "agent_id", "software_type"):
        val = request.GET.get(key)
        if val:
            params[key] = val

    try:
        data = http_client.get_software_inventory(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio de inventario.")

    return render(request, "web_app/software_list.html", {
        "software": data.get("results", []),
        "total": data.get("count", 0),
        "page": int(params.get("page", 1)),
        "search": request.GET.get("search", ""),
        "type_filter": request.GET.get("software_type", ""),
    })


# ── JSON API endpoints for dashboard ─────────────────────────────────

def dashboard_metrics(request):
    if not _require_auth(request):
        return JsonResponse({"success": False, "error": "unauthorized"}, status=401)

    ctx = {"success": True, "metricas": {
        "totales": {"reportes": 0, "incidentes": 0, "involucrados": 0, "areas": 0},
        "ultimas_24h": {"reportes": 0, "incidentes": 0},
        "reportes_por_estado": [],
        "incidentes_por_estado": [],
        "reportes_por_dia": [],
        "medidas": {"cumplidas": 0, "pendientes": 0},
    }}

    try:
        inv = http_client.get_inventory_stats(request)
        ctx["metricas"]["totales"]["involucrados"] = inv.get("total", 0)
    except Exception:
        pass

    try:
        aegis = http_client.get_aegis_stats(request)
        ctx["metricas"]["totales"]["incidentes"] = aegis.get("total", 0)
        ctx["metricas"]["ultimas_24h"]["incidentes"] = aegis.get("today", 0)
        ctx["metricas"]["incidentes_por_estado"] = aegis.get("by_status", [])
    except Exception:
        pass

    return JsonResponse(ctx)


def notifications_api(request):
    return JsonResponse({"notifications": [], "unread_count": 0})


def service_health_api(request):
    return JsonResponse({
        "inventory": http_client.inventory_health(),
        "logs": http_client.logs_health(),
        "aegis": http_client.aegis_health(),
    })
