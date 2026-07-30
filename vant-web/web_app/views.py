import json
import logging
from datetime import datetime, timedelta

from django.shortcuts import render, redirect
from django.urls import reverse
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


def _get_current_username(request):
    return request.session.get("username", "web_user")


def _publish_enriched_event(incident_result, linked_reports, username):
    import requests as http_requests
    import os
    try:
        http_requests.post(
            "http://127.0.0.1:8600/api/events/receive/",
            json={
                "event_type": "incidente_creado",
                "source_service": "soc",
                "entity_type": "incidente",
                "entity_id": str(incident_result.get("id", "")),
                "actor_user_id": "",
                "actor_username": username,
                "payload": {
                    "codigo": incident_result.get("codigo_incidente", ""),
                    "nombre": incident_result.get("nombre_incidente", ""),
                    "estado": incident_result.get("estado_solucion", "nuevo"),
                    "descripcion": (incident_result.get("descripcion", "") or "")[:200],
                    "creado_por": username,
                    "reportes": linked_reports,
                },
                "severity": "medium",
            },
            headers={"X-Service-Secret": os.getenv("SERVICE_SECRET", "changeme-service-secret")},
            timeout=5,
        )
    except Exception:
        pass


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
        aegis_stats = http_client.get_soc_stats(request)
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

def logs_storage_dashboard(request):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        data = http_client.get_logs_storage_dashboard(request)
    except Exception:
        data = {}

    return render(request, "web_app/logs_storage_dashboard.html", {
        "data": data,
    })


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
        return redirect("web:logs-discovery")

    return render(request, "web_app/event_detail.html", {"event": event})


def logs_discovery(request):
    if not _require_auth(request):
        return _redirect_login(request)

    from_str = request.GET.get("from", "")
    to_str = request.GET.get("to", "")
    host_ip = request.GET.get("host_ip", "")
    host_name = request.GET.get("host_name", "")
    severity = request.GET.get("severity", "")
    source_type = request.GET.get("source_type", "")
    event_category = request.GET.get("event_category", "")
    search = request.GET.get("q", "")
    page = int(request.GET.get("page", 1))
    page_size = int(request.GET.get("page_size", 50))

    if from_str:
        dt_from = from_str
    else:
        dt_from = ""
    if to_str:
        dt_to = to_str
    else:
        dt_to = ""

    time_params = {}
    if dt_from:
        time_params["from"] = dt_from
    if dt_to:
        time_params["to"] = dt_to

    if not dt_from and not dt_to:
        now = datetime.now()
        default_from = now - timedelta(minutes=15)
        from_str = default_from.strftime("%Y-%m-%dT%H:%M")
        to_str = now.strftime("%Y-%m-%dT%H:%M")
        time_params["from"] = from_str
        time_params["to"] = to_str

    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

    if is_ajax:
        try:
            params = {"page": page, "page_size": page_size}
            params.update(time_params)
            if host_ip:
                params["host_ip"] = host_ip
            if host_name:
                params["host_name"] = host_name
            if severity:
                params["severity"] = severity
            if source_type:
                params["source_type"] = source_type
            if event_category:
                params["event_category"] = event_category
            if search:
                params["q"] = search
            events_data = http_client.get_events(request, **params)
        except Exception:
            events_data = {"results": [], "count": 0}

        total = events_data.get("count", 0)
        total_pages = max(1, (total + page_size - 1) // page_size)

        return JsonResponse({
            "events": events_data.get("results", []),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        })

    ctx = {"from_str": from_str, "to_str": to_str, "host_ip": host_ip,
           "host_name": host_name, "severity": severity, "source_type": source_type,
           "event_category": event_category, "search": search,
           "page": page, "page_size": page_size}

    try:
        st_data = http_client.get_log_source_types(request, **time_params)
        ctx["source_types_list"] = st_data.get("results", [])
    except Exception:
        ctx["source_types_list"] = []

    try:
        histogram = http_client.get_logs_histogram(
            request,
            bucket_minutes=_histogram_bucket_from_range(dt_from, dt_to),
            **time_params,
            **({"host_ip": host_ip} if host_ip else {}),
            **({"severity": severity} if severity else {}),
            **({"source_type": source_type} if source_type else {}),
            **({"q": search} if search else {}),
        )
        timeline = histogram.get("timeline", [])
        ctx["timeline_json"] = json.dumps([
            {"t": item["time"][:19], "c": item["count"]} for item in timeline
        ])
    except Exception:
        ctx["timeline_json"] = "[]"

    try:
        field_params = dict(time_params)
        if source_type:
            field_params["source_type"] = source_type
        ctx["field_values"] = http_client.get_log_field_values(request, **field_params)
    except Exception:
        ctx["field_values"] = {}

    try:
        params = {"page": page, "page_size": page_size}
        params.update(time_params)
        if host_ip:
            params["host_ip"] = host_ip
        if host_name:
            params["host_name"] = host_name
        if severity:
            params["severity"] = severity
        if source_type:
            params["source_type"] = source_type
        if event_category:
            params["event_category"] = event_category
        if search:
            params["q"] = search
        events_data = http_client.get_events(request, **params)
    except Exception:
        events_data = {"results": [], "count": 0}
    ctx["events"] = events_data.get("results", [])
    ctx["total"] = events_data.get("count", 0)

    total_pages = max(1, (ctx["total"] + page_size - 1) // page_size)
    ctx["total_pages"] = total_pages
    ctx["has_prev"] = page > 1
    ctx["has_next"] = page < total_pages

    return render(request, "web_app/logs_discovery.html", ctx)


def _histogram_bucket_from_range(dt_from_str, dt_to_str):
    try:
        if dt_from_str and dt_to_str:
            f = datetime.fromisoformat(dt_from_str.replace('Z', '+00:00'))
            t = datetime.fromisoformat(dt_to_str.replace('Z', '+00:00'))
            diff_hours = max(0.1, (t - f).total_seconds() / 3600)
        else:
            diff_hours = 0.25
    except Exception:
        diff_hours = 0.25
    if diff_hours <= 1:
        return 2
    if diff_hours <= 6:
        return 10
    if diff_hours <= 24:
        return 30
    if diff_hours <= 72:
        return 60
    return 120


def suricata_dashboard(request):
    if not _require_auth(request):
        return _redirect_login(request)

    hours = int(request.GET.get("hours", 6))
    ctx = {"hours": hours}

    try:
        stats = http_client.get_suricata_stats(request, hours=hours)
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


@csrf_protect
def agent_restart(request, agent_id):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:agent-detail", agent_id=agent_id)
    result = http_client.send_agent_command(agent_id, "restart_agent", request=request)
    if result:
        messages.success(request, "Comando de reinicio enviado al agente.")
    else:
        messages.error(request, "Error al enviar comando de reinicio.")
    return redirect("web:agent-detail", agent_id=agent_id)


@csrf_protect
def agent_delete(request, agent_id):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:agents-list")
    agent = http_client.get_agent(agent_id, request)
    hostname = (agent.get("hostname") or agent_id) if agent else agent_id
    result = http_client.delete_agent(agent_id, request)
    if result:
        messages.success(request, f"Agente {hostname} eliminado correctamente.")
    else:
        messages.error(request, "Error al eliminar el agente.")
    return redirect("web:agents-list")


def agent_processes(request, agent_id):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        agent = http_client.get_agent(agent_id, request)
    except Exception:
        agent = None
    if not agent:
        messages.error(request, "Agente no encontrado.")
        return redirect("web:agents-list")
    proc_data = http_client.get_agent_processes(agent_id, request)
    return render(request, "web_app/agent_processes.html", {
        "agent": agent,
        "processes": proc_data.get("processes", []),
        "connections": proc_data.get("connections", []),
        "captured_at": proc_data.get("captured_at"),
        "has_data": proc_data.get("status") == "ok",
    })


@csrf_protect
def agent_collect_processes(request, agent_id):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:agent-processes", agent_id=agent_id)
    result = http_client.send_agent_command(agent_id, "collect_processes", request=request)
    if result:
        messages.success(request, "Comando de recolección de procesos enviado. Los datos se actualizarán cuando el agente responda.")
    else:
        messages.error(request, "Error al enviar comando.")
    return redirect("web:agent-processes", agent_id=agent_id)


def agent_services(request, agent_id):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        agent = http_client.get_agent(agent_id, request)
    except Exception:
        agent = None
    if not agent:
        messages.error(request, "Agente no encontrado.")
        return redirect("web:agents-list")

    svc_data = http_client.get_agent_services(agent_id, request)
    services = svc_data.get("services", [])

    if request.method == "POST":
        monitored = request.POST.getlist("monitored_services")
        result = http_client.toggle_service_monitoring(agent_id, monitored, request)
        if result:
            messages.success(request, f"{result.get('monitored_count', 0)} servicios configurados para monitoreo.")
        else:
            messages.error(request, "Error al guardar configuración.")
        return redirect("web:agent-services", agent_id=agent_id)

    return render(request, "web_app/agent_services.html", {
        "agent": agent,
        "services": services,
    })


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


# ── SOC: CRUD - Categorias ──────────────────────────────────────────

def _entity_create_page(request, title, subtitle, icon, back_url, form_action, fields):
    return render(request, "web_app/soc_entity_create.html", {
        "title": title, "subtitle": subtitle, "icon": icon,
        "back_url": back_url, "form_action": form_action, "fields": fields,
    })


def categoria_create_page(request):
    if not _require_auth(request): return _redirect_login(request)
    return _entity_create_page(request,
        "Nueva Categoria", "Registrar categoria de clasificacion", "fas fa-folder-tree",
        reverse("web:soc-categorias-list"), reverse("web:soc-categoria-create"),
        [{"name": "nombre", "label": "Nombre", "type": "text", "required": True, "placeholder": "Nombre de la categoria"},
         {"name": "descripcion", "label": "Descripcion", "type": "textarea", "placeholder": "Descripcion opcional"}],
    )


def subcategoria_create_page(request):
    if not _require_auth(request): return _redirect_login(request)
    cats = http_client.get_categorias(request).get("results", [])
    return _entity_create_page(request,
        "Nueva Subcategoria", "Registrar subcategoria de clasificacion", "fas fa-tags",
        reverse("web:soc-subcategorias-list"), reverse("web:soc-subcategoria-create"),
        [{"name": "nombre", "label": "Nombre", "type": "text", "required": True, "placeholder": "Nombre de la subcategoria"},
         {"name": "categoria", "label": "Categoria", "type": "select", "required": True,
          "options": [{"value": "", "label": "-- Seleccionar --"}] + [{"value": c["id"], "label": c["nombre"]} for c in cats]},
         {"name": "nivel_peligrosidad", "label": "Nivel de Peligrosidad", "type": "number", "min": 1, "max": 10, "value": "5", "placeholder": "1-10"},
         {"name": "descripcion", "label": "Descripcion", "type": "textarea", "placeholder": "Descripcion opcional"}],
    )


def medida_create_page(request):
    if not _require_auth(request): return _redirect_login(request)
    return _entity_create_page(request,
        "Nueva Medida", "Registrar medida de seguridad", "fas fa-tools",
        reverse("web:soc-medidas-list"), reverse("web:soc-medida-create"),
        [{"name": "nombre", "label": "Nombre", "type": "text", "required": True, "placeholder": "Nombre de la medida"},
         {"name": "tipo", "label": "Tipo", "type": "select",
          "options": [{"value": "preventiva", "label": "Preventiva"},
                      {"value": "reactiva", "label": "Reactiva"},
                      {"value": "recuperacion", "label": "Recuperación"}]},
         {"name": "descripcion", "label": "Descripcion", "type": "textarea", "placeholder": "Descripcion de la medida"}],
    )


def responsable_create_page(request):
    if not _require_auth(request): return _redirect_login(request)
    return _entity_create_page(request,
        "Nuevo Responsable", "Agregar miembro al equipo de respuesta", "fas fa-user-tie",
        reverse("web:soc-responsables-list"), reverse("web:soc-responsable-create"),
        [{"name": "nombres", "label": "Nombres", "type": "text", "required": True, "placeholder": "Nombres completos"},
         {"name": "apellidos", "label": "Apellidos", "type": "text", "placeholder": "Apellidos"},
         {"name": "email", "label": "Email", "type": "email", "placeholder": "correo@ejemplo.com"},
         {"name": "telefono_particular", "label": "Telefono Particular", "type": "text", "placeholder": "+52 ..."},
         {"name": "telefono_corp", "label": "Telefono Corporativo", "type": "text", "placeholder": "+52 ..."},
         {"name": "tipo", "label": "Tipo", "type": "select",
          "options": [{"value": "rsi", "label": "RSI"}, {"value": "cuadro_centro", "label": "Cuadro Centro"},
                      {"value": "admin", "label": "Administrador"}, {"value": "otro", "label": "Otro"}]},
         {"name": "descripcion", "label": "Descripcion", "type": "textarea", "placeholder": "Rol o descripcion del responsable"}],
    )


def area_create_page(request):
    if not _require_auth(request): return _redirect_login(request)
    resps = http_client.get_responsables(request).get("results", [])
    resp_opts = [{"value": "", "label": "-- Ninguno --"}] + [{"value": r["id"], "label": (r.get("nombres", "") + " " + r.get("apellidos", "")).strip() or str(r["id"])} for r in resps]
    return _entity_create_page(request,
        "Nueva Area", "Registrar area organizacional", "fas fa-building",
        reverse("web:soc-areas-list"), reverse("web:soc-area-create"),
        [{"name": "nombre", "label": "Nombre", "type": "text", "required": True, "placeholder": "Nombre del area"},
         {"name": "acronimo", "label": "Acrónimo", "type": "text", "required": True, "placeholder": "Ej: TI, SI, RH"},
         {"name": "cuadro_centro", "label": "Responsable Cuadro Centro", "type": "select", "options": resp_opts},
         {"name": "rsi", "label": "Responsable RSI", "type": "select", "options": resp_opts},
         {"name": "admin", "label": "Responsable Admin", "type": "select", "options": resp_opts}],
    )


def involucrado_create_page(request):
    if not _require_auth(request): return _redirect_login(request)
    return _entity_create_page(request,
        "Nuevo Involucrado", "Registrar persona involucrada en incidentes", "fas fa-user-secret",
        reverse("web:soc-involucrados-list"), reverse("web:soc-involucrado-create"),
        [{"name": "nombres", "label": "Nombres", "type": "text", "required": True, "placeholder": "Nombres completos"},
         {"name": "apellidos", "label": "Apellidos", "type": "text", "placeholder": "Apellidos"},
         {"name": "usuario", "label": "Usuario", "type": "text", "placeholder": "Usuario de sistema"},
         {"name": "ip", "label": "Direccion IP", "type": "text", "placeholder": "192.168.1.100"},
         {"name": "mac", "label": "Direccion MAC", "type": "text", "placeholder": "AA:BB:CC:DD:EE:FF"},
         {"name": "tipo", "label": "Tipo", "type": "select",
          "options": [{"value": "interno", "label": "Interno"}, {"value": "externo", "label": "Externo"},
                      {"value": "desconocido", "label": "Desconocido"}]}],
    )

@csrf_protect
@require_POST
def soc_categoria_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {"nombre": request.POST.get("nombre", "").strip(), "descripcion": request.POST.get("descripcion", "").strip()}
    if not data["nombre"]:
        messages.error(request, "El nombre es obligatorio.")
        return redirect("web:soc-categorias-list")
    try:
        result = http_client.create_categoria(data, request)
        if result:
            messages.success(request, "Categoría creada.")
        else:
            messages.error(request, "Error al crear la categoría.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-categorias-list")


@csrf_protect
@require_POST
def soc_categoria_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {"nombre": request.POST.get("nombre", "").strip(), "descripcion": request.POST.get("descripcion", "").strip()}
    try:
        result = http_client.update_categoria(pk, data, request)
        if result:
            messages.success(request, "Categoría actualizada.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-categorias-list")


@csrf_protect
@require_POST
def soc_categoria_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_categoria(pk, request):
            messages.success(request, "Categoría eliminada.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-categorias-list")


# ── SOC: CRUD - Subcategorias ───────────────────────────────────────

@csrf_protect
@require_POST
def soc_subcategoria_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombre": request.POST.get("nombre", "").strip(),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "nivel_peligrosidad": request.POST.get("nivel_peligrosidad", "5"),
        "categoria": request.POST.get("categoria", ""),
    }
    if not data["nombre"] or not data["categoria"]:
        messages.error(request, "Nombre y categoría son obligatorios.")
        return redirect("web:soc-subcategorias-list")
    try:
        result = http_client.create_subcategoria(data, request)
        if result:
            messages.success(request, "Subcategoría creada.")
        else:
            messages.error(request, "Error al crear la subcategoría.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-subcategorias-list")


@csrf_protect
@require_POST
def soc_subcategoria_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombre": request.POST.get("nombre", "").strip(),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "nivel_peligrosidad": request.POST.get("nivel_peligrosidad", "5"),
        "categoria": request.POST.get("categoria", ""),
    }
    try:
        result = http_client.update_subcategoria(pk, data, request)
        if result:
            messages.success(request, "Subcategoría actualizada.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-subcategorias-list")


@csrf_protect
@require_POST
def soc_subcategoria_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_subcategoria(pk, request):
            messages.success(request, "Subcategoría eliminada.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-subcategorias-list")


# ── SOC: CRUD - Medidas ────────────────────────────────────────────

@csrf_protect
@require_POST
def soc_medida_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {"nombre": request.POST.get("nombre", "").strip(), "descripcion": request.POST.get("descripcion", "").strip(), "tipo": request.POST.get("tipo", "preventiva")}
    if not data["nombre"]:
        messages.error(request, "El nombre es obligatorio.")
        return redirect("web:soc-medidas-list")
    try:
        result = http_client.create_medida(data, request)
        if result:
            messages.success(request, "Medida creada.")
        else:
            messages.error(request, "Error al crear la medida.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-medidas-list")


@csrf_protect
@require_POST
def soc_medida_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {"nombre": request.POST.get("nombre", "").strip(), "descripcion": request.POST.get("descripcion", "").strip(), "tipo": request.POST.get("tipo", "preventiva")}
    try:
        result = http_client.update_medida(pk, data, request)
        if result:
            messages.success(request, "Medida actualizada.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-medidas-list")


@csrf_protect
@require_POST
def soc_medida_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_medida(pk, request):
            messages.success(request, "Medida eliminada.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-medidas-list")


# ── SOC: CRUD - Responsables ────────────────────────────────────────

@csrf_protect
@require_POST
def soc_responsable_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombres": request.POST.get("nombres", "").strip(),
        "apellidos": request.POST.get("apellidos", "").strip(),
        "email": request.POST.get("email", "").strip(),
        "telefono_particular": request.POST.get("telefono_particular", "").strip(),
        "telefono_corp": request.POST.get("telefono_corp", "").strip(),
        "tipo": request.POST.get("tipo", "rsi"),
        "descripcion": request.POST.get("descripcion", "").strip(),
    }
    if not data["nombres"] or not data["apellidos"]:
        messages.error(request, "Nombres y apellidos son obligatorios.")
        return redirect("web:soc-responsables-list")
    try:
        result = http_client.create_responsable(data, request)
        if result:
            messages.success(request, "Responsable creado.")
        else:
            messages.error(request, "Error al crear el responsable.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-responsables-list")


@csrf_protect
@require_POST
def soc_responsable_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombres": request.POST.get("nombres", "").strip(),
        "apellidos": request.POST.get("apellidos", "").strip(),
        "email": request.POST.get("email", "").strip(),
        "telefono_particular": request.POST.get("telefono_particular", "").strip(),
        "telefono_corp": request.POST.get("telefono_corp", "").strip(),
        "tipo": request.POST.get("tipo", "rsi"),
        "descripcion": request.POST.get("descripcion", "").strip(),
    }
    try:
        result = http_client.update_responsable(pk, data, request)
        if result:
            messages.success(request, "Responsable actualizado.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-responsables-list")


@csrf_protect
@require_POST
def soc_responsable_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_responsable(pk, request):
            messages.success(request, "Responsable eliminado.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-responsables-list")


# ── SOC: CRUD - Areas ──────────────────────────────────────────────

@csrf_protect
@require_POST
def soc_area_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombre": request.POST.get("nombre", "").strip(),
        "acronimo": request.POST.get("acronimo", "").strip(),
    }
    for fk in ("cuadro_centro", "rsi", "admin"):
        val = request.POST.get(fk, "")
        if val:
            data[fk] = val
    if not data["nombre"] or not data["acronimo"]:
        messages.error(request, "Nombre y acrónimo son obligatorios.")
        return redirect("web:soc-areas-list")
    try:
        result = http_client.create_area(data, request)
        if result:
            messages.success(request, "Área creada.")
        else:
            messages.error(request, "Error al crear el área.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-areas-list")


@csrf_protect
@require_POST
def soc_area_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombre": request.POST.get("nombre", "").strip(),
        "acronimo": request.POST.get("acronimo", "").strip(),
    }
    for fk in ("cuadro_centro", "rsi", "admin"):
        val = request.POST.get(fk, "")
        data[fk] = val if val else None
    try:
        result = http_client.update_area(pk, data, request)
        if result:
            messages.success(request, "Área actualizada.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-areas-list")


@csrf_protect
@require_POST
def soc_area_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_area(pk, request):
            messages.success(request, "Área eliminada.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-areas-list")


# ── SOC: CRUD - Involucrados ────────────────────────────────────────

def involucrados_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    params = {"page_size": 50}
    for key in ("q", "page"):
        val = request.GET.get(key)
        if val:
            params[key] = val
    try:
        data = http_client.get_involucrados(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")
    return render(request, "web_app/soc_involucrados_list.html", {
        "involucrados": data.get("results", []),
        "total": data.get("count", 0),
        "search": request.GET.get("q", ""),
    })


def involucrado_detail(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        involucrado = http_client.get_involucrado(pk, request)
    except Exception:
        involucrado = None
    if not involucrado:
        messages.error(request, "Involucrado no encontrado.")
        return redirect("web:soc-involucrados-list")
    return render(request, "web_app/soc_involucrado_detail.html", {"involucrado": involucrado})


@csrf_protect
@require_POST
def soc_involucrado_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombres": request.POST.get("nombres", "").strip(),
        "apellidos": request.POST.get("apellidos", "").strip(),
        "usuario": request.POST.get("usuario", "").strip(),
        "ip": request.POST.get("ip", "").strip() or None,
        "mac": request.POST.get("mac", "").strip(),
        "tipo": request.POST.get("tipo", "interno"),
    }
    if not data["nombres"]:
        messages.error(request, "El nombre es obligatorio.")
        return redirect("web:soc-involucrados-list")
    try:
        result = http_client.create_involucrado(data, request)
        if result:
            messages.success(request, "Involucrado creado.")
        else:
            messages.error(request, "Error al crear el involucrado.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-involucrados-list")


@csrf_protect
@require_POST
def soc_involucrado_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombres": request.POST.get("nombres", "").strip(),
        "apellidos": request.POST.get("apellidos", "").strip(),
        "usuario": request.POST.get("usuario", "").strip(),
        "ip": request.POST.get("ip", "").strip() or None,
        "mac": request.POST.get("mac", "").strip(),
        "tipo": request.POST.get("tipo", "interno"),
    }
    try:
        result = http_client.update_involucrado(pk, data, request)
        if result:
            messages.success(request, "Involucrado actualizado.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-involucrado-detail", pk=pk)


@csrf_protect
@require_POST
def soc_involucrado_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_involucrado(pk, request):
            messages.success(request, "Involucrado eliminado.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-involucrados-list")


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
        soc_stats = http_client.get_soc_stats(request)
        ctx["metricas"]["totales"]["incidentes"] = soc_stats.get("incidentes", {}).get("total", 0)
        ctx["metricas"]["ultimas_24h"]["incidentes"] = soc_stats.get("incidentes", {}).get("today", 0)
        ctx["metricas"]["incidentes_por_estado"] = soc_stats.get("incidentes", {}).get("by_estado", [])
    except Exception:
        pass

    return JsonResponse(ctx)


def notifications_api(request):
    return JsonResponse({"notifications": [], "unread_count": 0})


def service_health_api(request):
    return JsonResponse({
        "inventory": http_client.inventory_health(),
        "logs": http_client.logs_health(),
        "soc": http_client.soc_health(),
    })


# ── SOC: Bitacora de Incidentes ─────────────────────────────────────

def soc_incidents_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    params = {}
    for key in ("estado", "nivel_peligrosidad", "categoria", "q", "page", "page_size"):
        val = request.GET.get(key)
        if val:
            params[key] = val

    try:
        data = http_client.get_soc_incidents(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")

    metrics = {}
    try:
        metrics = http_client.get_incidentes_metrics(request)
    except Exception:
        pass

    return render(request, "web_app/soc_incidents_list.html", {
        "incidents": data.get("results", []),
        "total": data.get("count", 0),
        "search": request.GET.get("q", ""),
        "estado_filter": request.GET.get("estado", ""),
        "totales": metrics.get("totales", {}),
        "promedio_atencion_horas": f"{metrics.get('atencion', {}).get('promedio', 0):.1f}",
        "min_atencion_horas": f"{metrics.get('atencion', {}).get('minimo', 0):.1f}",
        "max_atencion_horas": f"{metrics.get('atencion', {}).get('maximo', 0):.1f}",
        "gauge_atencion_horas": f"{metrics.get('atencion', {}).get('gauge', 0):.1f}",
        "promedio_solucion_horas": f"{metrics.get('solucion', {}).get('promedio', 0):.1f}",
        "min_solucion_horas": f"{metrics.get('solucion', {}).get('minimo', 0):.1f}",
        "max_solucion_horas": f"{metrics.get('solucion', {}).get('maximo', 0):.1f}",
        "tasa_resolucion": f"{metrics.get('tasa_resolucion', 0):.1f}",
        "mensual_atencion_json": json.dumps(metrics.get("atencion", {}).get("mensual", [])),
        "mensual_solucion_json": json.dumps(metrics.get("solucion", {}).get("mensual", [])),
    })


def soc_incident_detail(request, incident_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        incident = http_client.get_soc_incident(incident_id, request)
    except Exception:
        incident = None

    if not incident:
        messages.error(request, "Incidente no encontrado.")
        return redirect("web:soc-incidents-list")

    return render(request, "web_app/soc_incident_detail.html", {"incident": incident})


@csrf_protect
@require_POST
def soc_incident_transition(request, incident_id, action):
    if not _require_auth(request):
        return _redirect_login(request)

    data = {}
    for key in ("responsable_id", "notas", "nivel_peligrosidad"):
        val = request.POST.get(key)
        if val:
            data[key] = val

    try:
        ok = http_client.transition_soc_incident(incident_id, action, data, request)
        if ok:
            messages.success(request, f"Incidente actualizado: {action}.")
        else:
            messages.error(request, f"Error al ejecutar: {action}.")
    except Exception:
        messages.error(request, "Servicio no disponible.")

    return redirect("web:soc-incident-detail", incident_id=incident_id)


def reportes_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    params = {}
    for key in ("estado", "canal", "q", "page", "page_size"):
        val = request.GET.get(key)
        if val:
            params[key] = val

    try:
        data = http_client.get_reportes(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")

    metrics = {}
    try:
        metrics = http_client.get_reportes_metrics(request)
    except Exception:
        pass

    return render(request, "web_app/soc_reportes_list.html", {
        "reportes": data.get("results", []),
        "total": data.get("count", 0),
        "search": request.GET.get("q", ""),
        "totales": metrics.get("totales", {}),
        "promedio_atencion_horas": f"{metrics.get('atencion', {}).get('promedio', 0):.1f}",
        "min_atencion_horas": f"{metrics.get('atencion', {}).get('minimo', 0):.1f}",
        "max_atencion_horas": f"{metrics.get('atencion', {}).get('maximo', 0):.1f}",
        "gauge_atencion_horas": f"{metrics.get('atencion', {}).get('gauge', 0):.1f}",
        "promedio_solucion_horas": f"{metrics.get('solucion', {}).get('promedio', 0):.1f}",
        "min_solucion_horas": f"{metrics.get('solucion', {}).get('minimo', 0):.1f}",
        "max_solucion_horas": f"{metrics.get('solucion', {}).get('maximo', 0):.1f}",
        "tasa_resolucion": f"{metrics.get('tasa_resolucion', 0):.1f}",
        "mensual_atencion_json": json.dumps(metrics.get("atencion", {}).get("mensual", [])),
        "mensual_solucion_json": json.dumps(metrics.get("solucion", {}).get("mensual", [])),
    })


def reporte_detail(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        reporte = http_client.get_reporte(pk, request)
    except Exception:
        reporte = None
    if not reporte:
        messages.error(request, "Reporte no encontrado.")
        return redirect("web:soc-reportes-list")
    return render(request, "web_app/soc_reporte_detail.html", {"reporte": reporte})


def reporte_create_page(request):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        areas_data = http_client.get_areas(request)
    except Exception:
        areas_data = {"results": []}
    return render(request, "web_app/soc_reporte_create.html", {
        "areas": areas_data.get("results", []),
    })


@csrf_protect
@require_POST
def reporte_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombre_informante": request.POST.get("nombre_informante", "").strip(),
        "email_informante": request.POST.get("email_informante", "").strip(),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "area": request.POST.get("area", ""),
        "estado_solucion": request.POST.get("estado_solucion", "nuevo"),
    }
    if not data["nombre_informante"] or not data["descripcion"]:
        messages.error(request, "Nombre del informante y descripción son obligatorios.")
        return redirect("web:soc-reportes-create")
    try:
        result = http_client.create_reporte(data, request)
        if result:
            messages.success(request, "Reporte creado correctamente.")
            return redirect("web:soc-reportes-list")
        else:
            messages.error(request, "Error al crear el reporte.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-reportes-create")


@csrf_protect
def reporte_edit_page(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        reporte = http_client.get_reporte(pk, request)
    except Exception:
        reporte = None
    if not reporte:
        messages.error(request, "Reporte no encontrado.")
        return redirect("web:soc-reportes-list")
    try:
        areas_data = http_client.get_areas(request)
    except Exception:
        areas_data = {"results": []}
    return render(request, "web_app/soc_reporte_edit.html", {
        "reporte": reporte,
        "areas": areas_data.get("results", []),
    })


@csrf_protect
@require_POST
def reporte_edit(request, pk):
    data = {
        "nombre_informante": request.POST.get("nombre_informante", "").strip(),
        "email_informante": request.POST.get("email_informante", "").strip(),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "area": request.POST.get("area", ""),
        "estado_solucion": request.POST.get("estado_solucion", "nuevo"),
    }
    try:
        result = http_client.update_reporte(pk, data, request)
        if result:
            messages.success(request, "Reporte actualizado.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-reportes-list")


@csrf_protect
@require_POST
def reporte_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_reporte(pk, request):
            messages.success(request, "Reporte eliminado.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-reportes-list")


def incidente_create_page(request):
    if not _require_auth(request):
        return _redirect_login(request)
    ctx = {}
    try:
        ctx["reportes"] = http_client.get_reportes(request).get("results", [])
    except Exception:
        ctx["reportes"] = []
    try:
        ctx["servicios"] = http_client.get_servicios(request).get("results", [])
    except Exception:
        ctx["servicios"] = []
    try:
        ctx["areas"] = http_client.get_areas(request).get("results", [])
    except Exception:
        ctx["areas"] = []
    try:
        ctx["subcategorias"] = http_client.get_subcategorias(request).get("results", [])
    except Exception:
        ctx["subcategorias"] = []
    try:
        ctx["involucrados_list"] = http_client.get_involucrados(request).get("results", [])
    except Exception:
        ctx["involucrados_list"] = []
    try:
        ctx["medidas_list"] = http_client.get_medidas(request).get("results", [])
    except Exception:
        ctx["medidas_list"] = []
    ctx["preselected_involucrados"] = []
    ctx["preselected_medidas"] = []

    preselected_reporte = request.GET.get("reporte", "")
    ctx["selected_reportes"] = [preselected_reporte] if preselected_reporte else []
    ctx["selected_servicios"] = []
    ctx["selected_areas"] = []
    ctx["selected_subcategorias"] = []
    return render(request, "web_app/soc_incidente_create.html", ctx)


@csrf_protect
@require_POST
def incidente_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombre_incidente": request.POST.get("nombre_incidente", "").strip(),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "notificado_osri": request.POST.get("notificado_osri", "no"),
        "estado_solucion": request.POST.get("estado_solucion", "nuevo"),
    }
    if not data["nombre_incidente"] or not data["descripcion"]:
        messages.error(request, "Nombre y descripción son obligatorios.")
        return redirect("web:soc-incidentes-create")

    reporte_ids = request.POST.getlist("reportes")
    servicio_ids = request.POST.getlist("servicios")
    area_ids = request.POST.getlist("areas")
    subcat_ids = request.POST.getlist("subcategorias")
    involucrado_ids = request.POST.getlist("involucrados")
    inv_medida_ids = request.POST.getlist("inv_medida")
    medida_ids = request.POST.getlist("medidas_incidente")

    try:
        result = http_client.create_incidente(data, request, actor_username=_get_current_username(request))
        if result:
            iid = result.get("id")
            base = f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{iid}"
            linked_reports = []
            for rid in reporte_ids:
                http_client._service_call("post", f"{base}/reportes/{rid}/", request=request)
                http_client._service_call("patch", f"{settings.SOC_SERVICE_URL}/soc/api/reportes/{rid}/",
                                          request=request, json={"estado_solucion": "atendido"})
                linked_reports.append({"id": int(rid)})
            for sid in servicio_ids:
                http_client._service_call("post", f"{base}/servicios/{sid}/", request=request)
            for aid in area_ids:
                http_client._service_call("post", f"{base}/areas/{aid}/", request=request)
            for scid in subcat_ids:
                http_client._service_call("post", f"{base}/subcategorias/{scid}/", request=request)
            for idx, iid_val in enumerate(involucrado_ids):
                inv_data = {"incidente": result["id"], "involucrado": int(iid_val)}
                if idx < len(inv_medida_ids) and inv_medida_ids[idx]:
                    inv_data["medida_impuesta"] = int(inv_medida_ids[idx])
                http_client.create_involucrado_incidente(inv_data, request)
            for mid in medida_ids:
                http_client.create_medida_incidente(
                    {"incidente": result["id"], "medida": int(mid), "responsable": 1},
                    request,
                )
            evidencia = request.FILES.get("evidencia")
            if evidencia:
                http_client._service_call(
                    "patch", base + "/",
                    request=request,
                    data={},
                    files={"evidencia": (evidencia.name, evidencia.read(), evidencia.content_type)},
                )
            _publish_enriched_event(result, linked_reports, _get_current_username(request))
            messages.success(request, "Incidente creado correctamente.")
            return redirect("web:soc-incident-detail", incident_id=result["codigo_incidente"])
        else:
            messages.error(request, "Error al crear el incidente.")
    except Exception:
        messages.error(request, "Error al crear el incidente.")
    return redirect("web:soc-incidentes-create")


def incidente_edit_page(request, incident_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        incident = http_client.get_soc_incident(incident_id, request)
    except Exception:
        incident = None

    if not incident:
        messages.error(request, "Incidente no encontrado.")
        return redirect("web:soc-incidents-list")

    ctx = {"incident": incident}

    for key, getter in [
        ("reportes", lambda: http_client.get_reportes(request).get("results", [])),
        ("servicios", lambda: http_client.get_servicios(request).get("results", [])),
        ("areas", lambda: http_client.get_areas(request).get("results", [])),
        ("subcategorias", lambda: http_client.get_subcategorias(request).get("results", [])),
        ("involucrados_list", lambda: http_client.get_involucrados(request).get("results", [])),
        ("medidas_list", lambda: http_client.get_medidas(request).get("results", [])),
    ]:
        try:
            ctx[key] = getter()
        except Exception:
            ctx[key] = []

    ctx["selected_reportes"] = [str(r["id"]) for r in incident.get("reportes", [])]
    ctx["selected_servicios"] = [str(s) for s in incident.get("servicios", [])]
    ctx["selected_areas"] = [str(a["id"]) for a in incident.get("areas_data", [])]
    ctx["selected_subcategorias"] = [str(sc["id"]) for sc in incident.get("subcategorias_data", [])]
    ctx["selected_involucrados"] = [
        {"involucrado": inv["involucrado"], "involucrado_nombre": inv.get("involucrado_nombre", ""),
         "medida_impuesta": inv.get("medida_impuesta", ""), "medida_nombre": inv.get("medida_nombre", ""),
         "descripcion": inv.get("descripcion", ""),
         "fecha_inicio": inv.get("fecha_inicio", ""), "fecha_fin": inv.get("fecha_fin", "")}
        for inv in incident.get("involucrados_data", [])
    ]
    ctx["selected_medidas_incidente"] = [
        {"medida": m["medida"], "medida_nombre": m.get("medida_nombre", ""),
         "responsable": m.get("responsable", ""),
         "estado_cumplimiento": m.get("estado_cumplimiento", "pendiente"),
         "observaciones": m.get("observaciones", "")}
        for m in incident.get("medidas", [])
    ]

    return render(request, "web_app/soc_incidente_edit.html", ctx)


@csrf_protect
@require_POST
def incidente_edit_submit(request, incident_id):
    if not _require_auth(request):
        return _redirect_login(request)

    data = {
        "nombre_incidente": request.POST.get("nombre_incidente", "").strip(),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "notificado_osri": request.POST.get("notificado_osri", "no"),
        "estado_solucion": request.POST.get("estado_solucion", "nuevo"),
    }
    if not data["nombre_incidente"] or not data["descripcion"]:
        messages.error(request, "Nombre y descripción son obligatorios.")
        return redirect("web:soc-incidente-edit", incident_id=incident_id)

    try:
        result = http_client.update_soc_incident(incident_id, data, request)
        if result:
            evidencia = request.FILES.get("evidencia")
            if evidencia:
                http_client._service_call(
                    "patch",
                    f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{result['id']}/",
                    request=request,
                    data={},
                    files={"evidencia": (evidencia.name, evidencia.read(), evidencia.content_type)},
                )
            _sync_m2m_relations(incident_id, request)
            messages.success(request, "Incidente actualizado correctamente.")
            return redirect("web:soc-incident-detail", incident_id=incident_id)
        else:
            messages.error(request, "Error al actualizar el incidente.")
    except Exception:
        messages.error(request, "Servicio no disponible.")

    return redirect("web:soc-incidente-edit", incident_id=incident_id)


def _sync_m2m_relations(incident_id, request):
    reporte_ids = set(request.POST.getlist("reportes"))
    servicio_ids = set(request.POST.getlist("servicios"))
    area_ids = set(request.POST.getlist("areas"))
    subcat_ids = set(request.POST.getlist("subcategorias"))
    involucrado_ids = request.POST.getlist("involucrados")
    inv_medida_ids = request.POST.getlist("inv_medida")
    medida_ids = request.POST.getlist("medidas_incidente")

    base = f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{incident_id}"

    try:
        current = http_client.get_soc_incident(incident_id, request) or {}
    except Exception:
        current = {}

    cur_reportes = {str(r["id"]) for r in current.get("reportes", [])}
    cur_servicios = {str(s) for s in current.get("servicios", [])}
    cur_areas = {str(a["id"]) for a in current.get("areas_data", [])}
    cur_subcats = {str(sc["id"]) for sc in current.get("subcategorias_data", [])}

    for rid in cur_reportes - reporte_ids:
        http_client._service_call("delete", f"{base}/reportes/{rid}/", request=request)
    for rid in reporte_ids - cur_reportes:
        http_client._service_call("post", f"{base}/reportes/{rid}/", request=request)

    for sid in cur_servicios - servicio_ids:
        http_client._service_call("delete", f"{base}/servicios/{sid}/", request=request)
    for sid in servicio_ids - cur_servicios:
        http_client._service_call("post", f"{base}/servicios/{sid}/", request=request)

    for aid in cur_areas - area_ids:
        http_client._service_call("delete", f"{base}/areas/{aid}/", request=request)
    for aid in area_ids - cur_areas:
        http_client._service_call("post", f"{base}/areas/{aid}/", request=request)

    for scid in cur_subcats - subcat_ids:
        http_client._service_call("delete", f"{base}/subcategorias/{scid}/", request=request)
    for scid in subcat_ids - cur_subcats:
        http_client._service_call("post", f"{base}/subcategorias/{scid}/", request=request)

    cur_inv_ids = {str(inv["involucrado"]) for inv in current.get("involucrados_data", [])}
    for inv in current.get("involucrados_data", []):
        if str(inv["involucrado"]) not in set(involucrado_ids):
            http_client._service_call(
                "delete",
                f"{settings.SOC_SERVICE_URL}/soc/api/involucrado-incidente/{inv['id']}/",
                request=request,
            )
    for idx, iid in enumerate(involucrado_ids):
        if iid not in cur_inv_ids:
            inv_data = {"incidente": incident_id, "involucrado": int(iid)}
            if idx < len(inv_medida_ids) and inv_medida_ids[idx]:
                inv_data["medida_impuesta"] = int(inv_medida_ids[idx])
            http_client.create_involucrado_incidente(inv_data, request)

    cur_med_ids = {str(m["medida"]) for m in current.get("medidas", [])}
    for m in current.get("medidas", []):
        if str(m["medida"]) not in set(medida_ids):
            http_client._service_call(
                "delete",
                f"{settings.SOC_SERVICE_URL}/soc/api/medidas-incidente/{m['id']}/",
                request=request,
            )
    for mid in medida_ids:
        if mid not in cur_med_ids:
            http_client.create_medida_incidente(
                {
                    "incidente": incident_id,
                    "medida": int(mid),
                    "responsable": 1,
                },
                request,
            )



@csrf_protect
@require_POST
def incidente_delete(request, incident_id):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_incidente(incident_id, request):
            messages.success(request, "Incidente eliminado.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-incidents-list")


# ── SOC: Categorias / Subcategorias ─────────────────────────────────

def categorias_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    params = {"page_size": 50}
    if request.GET.get("q"):
        params["q"] = request.GET["q"]
    try:
        data = http_client.get_categorias(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")
    return render(request, "web_app/soc_categorias_list.html", {
        "categorias": data.get("results", []),
        "total": data.get("count", 0),
        "search": request.GET.get("q", ""),
    })


def subcategorias_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    params = {"page_size": 50}
    if request.GET.get("categoria"):
        params["categoria"] = request.GET["categoria"]
    if request.GET.get("q"):
        params["q"] = request.GET["q"]
    try:
        data = http_client.get_subcategorias(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")
    try:
        cats_data = http_client.get_categorias(request, page_size=200)
    except Exception:
        cats_data = {"results": []}
    return render(request, "web_app/soc_subcategorias_list.html", {
        "subcategorias": data.get("results", []),
        "total": data.get("count", 0),
        "categorias": cats_data.get("results", []),
        "categoria_filter": request.GET.get("categoria", ""),
        "search": request.GET.get("q", ""),
    })


# ── SOC: Responsables / Areas ───────────────────────────────────────

def responsables_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    params = {"page_size": 50}
    if request.GET.get("q"):
        params["q"] = request.GET["q"]
    try:
        data = http_client.get_responsables(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")
    return render(request, "web_app/soc_responsables_list.html", {
        "responsables": data.get("results", []),
        "total": data.get("count", 0),
        "search": request.GET.get("q", ""),
    })


def areas_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    params = {"page_size": 50}
    if request.GET.get("q"):
        params["q"] = request.GET["q"]
    try:
        data = http_client.get_areas(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")
    try:
        resp_data = http_client.get_responsables(request, page_size=200)
    except Exception:
        resp_data = {"results": [], "count": 0}
    return render(request, "web_app/soc_areas_list.html", {
        "areas": data.get("results", []),
        "total": data.get("count", 0),
        "responsables": resp_data.get("results", []),
        "search": request.GET.get("q", ""),
    })


# ── SOC: Medidas ────────────────────────────────────────────────────

def medidas_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    params = {"page_size": 50}
    if request.GET.get("q"):
        params["q"] = request.GET["q"]
    if request.GET.get("tipo"):
        params["tipo"] = request.GET["tipo"]
    try:
        data = http_client.get_medidas(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")
    return render(request, "web_app/soc_medidas_list.html", {
        "medidas": data.get("results", []),
        "total": data.get("count", 0),
        "search": request.GET.get("q", ""),
        "tipo": request.GET.get("tipo", ""),
    })


# ── SOC: Infraestructura / CMDB ─────────────────────────────────────

from django.http import JsonResponse

def servicios_metrics_ajax(request):
    if not _require_auth(request):
        return JsonResponse({"error": "unauthorized"}, status=401)
    try:
        metrics = http_client.get_servicios_metrics(request)
    except Exception:
        metrics = {}
    return JsonResponse(metrics)


def servicios_list(request):
    if not _require_auth(request):
        return _redirect_login(request)

    params = {}
    for key in ("estado", "tipo", "q", "page", "page_size"):
        val = request.GET.get(key)
        if val:
            params[key] = val
    if "page_size" not in params:
        params["page_size"] = request.GET.get("page_size", "50")

    try:
        data = http_client.get_servicios(request, **params)
    except Exception:
        data = {"results": [], "count": 0}
        messages.error(request, "Error al conectar con el servicio SOC.")

    try:
        metrics = http_client.get_servicios_metrics(request)
    except Exception:
        metrics = {}

    total = data.get("count", 0)
    page_size = int(params.get("page_size", 50))
    current_page = int(request.GET.get("page", 1))
    total_pages = max(1, -(-total // page_size))
    has_prev = current_page > 1
    has_next = current_page < total_pages

    page_range = []
    if total_pages <= 7:
        page_range = list(range(1, total_pages + 1))
    else:
        page_range = [1]
        if current_page > 3:
            page_range.append("...")
        for p in range(max(2, current_page - 1), min(total_pages, current_page + 2) + 1):
            page_range.append(p)
        if current_page < total_pages - 2:
            page_range.append("...")
        page_range.append(total_pages)

    tipo_choices = [
        ("host", "Host"), ("switch", "Switch"), ("router", "Router"),
        ("firewall", "Firewall"), ("access_point", "Access Point"),
        ("ups", "UPS"), ("storage", "Storage"), ("vlan", "VLAN"),
        ("segmento", "Segmento"), ("subred", "Subred"), ("red", "Red"),
        ("cluster", "Cluster"), ("plataforma", "Plataforma"),
        ("servicio_externo", "Servicio Externo"), ("zona", "Zona"),
        ("datacenter", "Datacenter"),
    ]

    return render(request, "web_app/soc_servicios_list.html", {
        "servicios": data.get("results", []),
        "total": total,
        "search": request.GET.get("q", ""),
        "metrics": metrics,
        "page": current_page,
        "total_pages": total_pages,
        "has_prev": has_prev,
        "has_next": has_next,
        "page_size": page_size,
        "page_range": page_range,
        "tipos": tipo_choices,
    })


def servicio_detail(request, servicio_id):
    if not _require_auth(request):
        return _redirect_login(request)

    try:
        servicio = http_client.get_servicio(servicio_id, request)
    except Exception:
        servicio = None

    if not servicio:
        messages.error(request, "Servicio no encontrado.")
        return redirect("web:soc-servicios-list")

    try:
        ips_data = http_client.get_servicio_ips(servicio_id, request)
        ips = ips_data.get("results", []) if isinstance(ips_data, dict) else ips_data
    except Exception:
        ips = []

    return render(request, "web_app/soc_servicio_detail.html", {
        "servicio": servicio,
        "ips": ips,
    })


def servicio_create_page(request):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        resp_data = http_client.get_responsables(request)
    except Exception:
        resp_data = {"results": []}
    return render(request, "web_app/soc_servicio_create.html", {
        "responsables": resp_data.get("results", []),
    })


@csrf_protect
@require_POST
def servicio_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {
        "nombre": request.POST.get("nombre", "").strip(),
        "tipo": request.POST.get("tipo", "host"),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "modelo": request.POST.get("modelo", "").strip(),
        "fabricante": request.POST.get("fabricante", "").strip(),
        "host": request.POST.get("host", "").strip() or None,
        "red_tipo": request.POST.get("red_tipo", "interna"),
        "vlan_id": request.POST.get("vlan_id", "").strip() or None,
        "ubicacion_fisica": request.POST.get("ubicacion_fisica", "").strip(),
        "responsable": request.POST.get("responsable", "").strip() or None,
        "servicio_padre": request.POST.get("servicio_padre", "").strip() or None,
        "activo": request.POST.get("activo") == "on",
        "monitorear": request.POST.get("monitorear") == "on",
    }
    if data["tipo"] in ("zona", "datacenter"):
        data["coordenadas_logicas_x"] = request.POST.get("coordenadas_logicas_x", "0").strip() or 0
        data["coordenadas_logicas_y"] = request.POST.get("coordenadas_logicas_y", "0").strip() or 0
        data["zona_ancho"] = request.POST.get("zona_ancho", "500").strip() or 500
        data["zona_alto"] = request.POST.get("zona_alto", "400").strip() or 400
        data["zona_color_fondo"] = request.POST.get("zona_color_fondo", "rgba(59,130,246,0.10)").strip()
        data["zona_color_borde"] = request.POST.get("zona_color_borde", "#3b82f6").strip()
    if not data["nombre"]:
        messages.error(request, "El nombre es obligatorio.")
        return redirect("web:soc-servicios-create")
    try:
        result = http_client.create_servicio(data, request)
        if result:
            messages.success(request, "Servicio creado correctamente.")
            return redirect("web:soc-servicios-list")
        else:
            messages.error(request, "Error al crear el servicio.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-servicios-create")


# ── SOC: Topologia / Redes ─────────────────────────────────────────

_NODE_COLORS = {
    "host": "#3b82f6", "switch": "#10b981", "router": "#f59e0b",
    "firewall": "#ef4444", "access_point": "#8b5cf6", "ups": "#6b7280",
    "storage": "#06b6d4", "vlan": "#ec4899", "segmento": "#f97316",
    "subred": "#14b8a6", "red": "#0ea5e9", "cluster": "#a855f7",
    "plataforma": "#6366f1", "servicio_externo": "#64748b",
    "zona": "#3b82f6", "datacenter": "#f59e0b",
}

_ZONE_TIPOS = {"zona", "datacenter"}


def _build_topology_context(request):
    try:
        servicios_data = http_client.get_servicios(request, page_size=500)
    except Exception:
        servicios_data = {"results": []}
    try:
        conexiones_data = http_client.get_conexiones_topologicas(request, page_size=500)
    except Exception:
        conexiones_data = {"results": []}

    servicios = servicios_data.get("results", [])
    conexiones = conexiones_data.get("results", [])

    by_id = {}
    for s in servicios:
        sid = s.get("id") or s.get("pk")
        if sid is not None:
            by_id[sid] = s

    zones = [s for s in servicios if s.get("tipo") in _ZONE_TIPOS]
    non_zones = [s for s in servicios if s.get("tipo") not in _ZONE_TIPOS]

    nodes = []

    for z in zones:
        zid = z.get("id") or z.get("pk")
        x = z.get("coordenadas_logicas_x") or 0
        y = z.get("coordenadas_logicas_y") or 0
        w = z.get("zona_ancho") or 500
        h = z.get("zona_alto") or 400
        bg = z.get("zona_color_fondo") or "rgba(59,130,246,0.10)"
        bd = z.get("zona_color_borde") or "#3b82f6"
        children_count = len([s for s in non_zones if (s.get("servicio_padre") == zid)])
        label_suffix = f"\n({children_count} elementos)" if children_count else ""
        nodes.append({
            "id": zid,
            "label": z.get("nombre", "") + label_suffix,
            "tipo": z.get("tipo", ""),
            "is_zone": True,
            "shape": "box",
            "size": None,
            "width": w,
            "height": h,
            "color": {"background": bg, "border": bd, "highlight": {"background": bg, "border": bd}},
            "borderWidth": 2,
            "borderDashes": [8, 4],
            "x": x, "y": y,
            "fixed": {"x": True, "y": True},
            "physics": False,
            "zOrder": "background",
            "font": {"size": 16, "color": bd, "face": "Inter, sans-serif", "multi": "md", "align": "center"},
            "margin": {"top": 20, "right": 10, "bottom": 10, "left": 10},
        })

    zone_children_map = {}
    for z in zones:
        zid = z.get("id") or z.get("pk")
        zone_children_map[zid] = []

    for s in non_zones:
        sid = s.get("id") or s.get("pk")
        x = s.get("coordenadas_logicas_x") or 0
        y = s.get("coordenadas_logicas_y") or 0
        parent_id = s.get("servicio_padre")
        if parent_id and parent_id in zone_children_map:
            zone_children_map[parent_id].append(sid)
        nodes.append({
            "id": sid,
            "label": s.get("nombre", ""),
            "tipo": s.get("tipo", ""),
            "is_zone": False,
            "host": s.get("host", ""),
            "color": _NODE_COLORS.get(s.get("tipo", ""), "#6b7280"),
            "x": x, "y": y,
            "monitorear": s.get("monitorear", False),
            "ubicacion": s.get("ubicacion_fisica", ""),
            "fabricante": s.get("fabricante", ""),
            "modelo": s.get("modelo", ""),
            "vlan_id": s.get("vlan_id"),
            "servicio_padre": parent_id,
        })

    edges = []
    for z in zones:
        zid = z.get("id") or z.get("pk")
        for child_id in zone_children_map.get(zid, []):
            edges.append({
                "from": zid,
                "to": child_id,
                "label": "",
                "title": "Pertenencia",
                "color": {"color": "#94a3b8", "highlight": "#60a5fa"},
                "dashes": [4, 4],
                "width": 1,
                "smooth": {"type": "continuous"},
                "physics": False,
            })

    for c in conexiones:
        if c.get("activa", True):
            from_id = c.get("origen_id")
            if from_id is None:
                o = c.get("origen")
                from_id = o if isinstance(o, (int, str)) else (o.get("id") if isinstance(o, dict) else None)
            to_id = c.get("destino_id")
            if to_id is None:
                d = c.get("destino")
                to_id = d if isinstance(d, (int, str)) else (d.get("id") if isinstance(d, dict) else None)
            if from_id is None or to_id is None:
                continue
            src = by_id.get(from_id)
            dst = by_id.get(to_id)
            if src and src.get("tipo") in _ZONE_TIPOS:
                continue
            if dst and dst.get("tipo") in _ZONE_TIPOS:
                continue
            edges.append({
                "from": from_id,
                "to": to_id,
                "label": c.get("medio", "") or c.get("tipo", ""),
                "title": c.get("descripcion", ""),
            })

    redes = [s for s in servicios if s.get("tipo") in ("subred", "red", "segmento", "vlan")]
    total_zones = len(zones)

    return {
        "nodes_json": json.dumps(nodes),
        "edges_json": json.dumps(edges),
        "redes": redes,
        "total_servicios": len(servicios),
        "total_conexiones": len(conexiones),
        "total_zonas": total_zones,
        "monitoreados": sum(1 for s in servicios if s.get("monitorear")),
    }


def esquema_fisico(request):
    if not _require_auth(request):
        return _redirect_login(request)
    ctx = _build_topology_context(request)
    ctx["esquema_tipo"] = "fisica"
    ctx["esquema_titulo"] = "Esquema Fisico"
    return render(request, "web_app/soc_esquema.html", ctx)


def esquema_logico(request):
    if not _require_auth(request):
        return _redirect_login(request)
    ctx = _build_topology_context(request)
    ctx["esquema_tipo"] = "logica"
    ctx["esquema_titulo"] = "Esquema Logico"
    return render(request, "web_app/soc_esquema.html", ctx)


def redes_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        data = http_client.get_servicios(request, page_size=500)
    except Exception:
        data = {"results": []}
    servicios = data.get("results", [])
    redes = [s for s in servicios if s.get("tipo") in ("subred", "red", "segmento", "vlan")]

    redes_tree = []
    for r in redes:
        rid = r.get("id") or r.get("pk")
        children = [s for s in servicios if (s.get("servicio_padre") == rid) and s.get("tipo") not in ("subred", "red", "segmento", "vlan", "zona", "datacenter")]
        redes_tree.append({"red": r, "children": children})

    return render(request, "web_app/soc_redes_list.html", {
        "redes_tree": redes_tree,
        "total_redes": len(redes),
        "total_dispositivos": len([s for s in servicios if s.get("tipo") in ("host", "switch", "router", "firewall", "access_point", "ups", "storage")]),
    })


@csrf_protect
def servicio_edit(request, servicio_id):
    if not _require_auth(request):
        return _redirect_login(request)

    if request.method == "GET":
        try:
            servicio = http_client.get_servicio(servicio_id, request)
        except Exception:
            servicio = None
        if not servicio:
            messages.error(request, "Servicio no encontrado.")
            return redirect("web:soc-servicios-list")
        try:
            responsables_data = http_client.get_responsables(request, page_size=200)
            responsables = responsables_data.get("results", [])
        except Exception:
            responsables = []
        return render(request, "web_app/soc_servicio_edit.html", {
            "servicio": servicio,
            "responsables": responsables,
        })

    data = {
        "nombre": request.POST.get("nombre", "").strip(),
        "tipo": request.POST.get("tipo", "host"),
        "descripcion": request.POST.get("descripcion", "").strip(),
        "modelo": request.POST.get("modelo", "").strip(),
        "fabricante": request.POST.get("fabricante", "").strip(),
        "host": request.POST.get("host", "").strip() or None,
        "red_tipo": request.POST.get("red_tipo", "interna"),
        "vlan_id": request.POST.get("vlan_id", "").strip() or None,
        "ubicacion_fisica": request.POST.get("ubicacion_fisica", "").strip(),
        "responsable": request.POST.get("responsable", "").strip() or None,
        "servicio_padre": request.POST.get("servicio_padre", "").strip() or None,
        "activo": request.POST.get("activo") == "on",
        "monitorear": request.POST.get("monitorear") == "on",
    }
    if data["tipo"] in ("zona", "datacenter"):
        data["coordenadas_logicas_x"] = request.POST.get("coordenadas_logicas_x", "0").strip() or 0
        data["coordenadas_logicas_y"] = request.POST.get("coordenadas_logicas_y", "0").strip() or 0
        data["zona_ancho"] = request.POST.get("zona_ancho", "500").strip() or 500
        data["zona_alto"] = request.POST.get("zona_alto", "400").strip() or 400
        data["zona_color_fondo"] = request.POST.get("zona_color_fondo", "rgba(59,130,246,0.10)").strip()
        data["zona_color_borde"] = request.POST.get("zona_color_borde", "#3b82f6").strip()
    try:
        result = http_client.update_servicio(servicio_id, data, request)
        if result:
            messages.success(request, "Servicio actualizado.")
        else:
            messages.error(request, "Error al actualizar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-servicios-list")


@csrf_protect
@require_POST
def servicio_delete(request, servicio_id):
    if not _require_auth(request):
        return _redirect_login(request)
    try:
        if http_client.delete_servicio(servicio_id, request):
            messages.success(request, "Servicio eliminado.")
        else:
            messages.error(request, "Error al eliminar.")
    except Exception:
        messages.error(request, "Servicio no disponible.")
    return redirect("web:soc-servicios-list")


# ── AJAX API endpoints for inline creation ──────────────────────────

@csrf_protect
@require_POST
def api_involucrado_create(request):
    if not _require_auth(request):
        return JsonResponse({"success": False, "error": "No autenticado"}, status=401)
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"success": False, "error": "JSON invalido"}, status=400)
    required = ["nombres", "apellidos", "ip", "mac"]
    for field in required:
        if not data.get(field, "").strip():
            return JsonResponse({"success": False, "error": f"Campo '{field}' es obligatorio"}, status=400)
    payload = {
        "nombres": data["nombres"].strip(),
        "apellidos": data["apellidos"].strip(),
        "ip": data["ip"].strip(),
        "mac": data["mac"].strip(),
        "usuario": data.get("usuario", "").strip(),
        "tipo": data.get("tipo", "interno"),
    }
    result = http_client.create_involucrado(payload, request)
    if result:
        return JsonResponse({"success": True, "id": result["id"]})
    return JsonResponse({"success": False, "error": "Error al crear involucrado"}, status=500)


@csrf_protect
@require_POST
def api_medida_create(request):
    if not _require_auth(request):
        return JsonResponse({"success": False, "error": "No autenticado"}, status=401)
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, ValueError):
        return JsonResponse({"success": False, "error": "JSON invalido"}, status=400)
    nombre = data.get("nombre", "").strip()
    desc = data.get("descripcion", "").strip()
    if not nombre:
        return JsonResponse({"success": False, "error": "Nombre es obligatorio"}, status=400)
    result = http_client.create_medida({"nombre": nombre, "descripcion": desc}, request)
    if result:
        return JsonResponse({"success": True, "id": result["id"]})
    return JsonResponse({"success": False, "error": "Error al crear medida"}, status=500)


# ============================================================================
#  BUS: Eventos en Tiempo Real
# ============================================================================

def bus_eventos(request):
    if not _require_auth(request):
        return _redirect_login(request)
    params = {}
    for key in ("severity", "source", "event_type", "q", "hostname", "service_name"):
        if request.GET.get(key):
            params[key] = request.GET[key]
    params["page"] = request.GET.get("page", "1")
    params["page_size"] = request.GET.get("page_size", "50")
    events_data = http_client.bus_list_events(request, **params)
    stats = http_client.bus_dashboard_stats(request)

    import json
    for ev in events_data.get("results", []):
        if isinstance(ev.get("payload"), dict):
            ev["payload_json"] = json.dumps(ev["payload"], ensure_ascii=False)

    return render(request, "web_app/bus_eventos.html", {
        "events": events_data.get("results", []),
        "total": events_data.get("count", 0),
        "page": int(params.get("page", 1)),
        "page_size": int(params.get("page_size", 50)),
        "stats": stats,
        "severity_filter": request.GET.get("severity", ""),
        "source_filter": request.GET.get("source", ""),
        "event_type_filter": request.GET.get("event_type", ""),
        "search_query": request.GET.get("q", ""),
        "hostname_filter": request.GET.get("hostname", ""),
        "service_filter": request.GET.get("service_name", ""),
    })


def bus_eventos_ajax(request):
    if not _require_auth(request):
        return JsonResponse({"error": "unauthorized"}, status=401)
    params = {}
    for key in ("severity", "source", "event_type", "q", "page", "page_size"):
        if request.GET.get(key):
            params[key] = request.GET[key]
    if "page_size" not in params:
        params["page_size"] = "50"
    events_data = http_client.bus_list_events(request, **params)
    stats = http_client.bus_dashboard_stats(request)
    return JsonResponse({"events": events_data, "stats": stats})


def bus_evento_detalle_ajax(request, event_id):
    if not _require_auth(request):
        return JsonResponse({"error": "unauthorized"}, status=401)
    event = http_client.bus_event_detail(event_id, request)
    if event:
        return JsonResponse(event)
    return JsonResponse({"error": "not found"}, status=404)


# ============================================================================
#  CONFIGURACION: Users
# ============================================================================

def configuracion_usuarios(request):
    if not _require_auth(request):
        return _redirect_login(request)
    users_data = http_client.auth_list_users(request)
    users = users_data.get("users", []) if isinstance(users_data, dict) else users_data
    return render(request, "web_app/configuracion_usuarios.html", {"users": users})


def configuracion_usuario_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    return render(request, "web_app/configuracion_usuario_form.html", {"mode": "create"})


def configuracion_usuario_create_submit(request):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-usuarios")
    data = {
        "username": request.POST.get("username", ""),
        "email": request.POST.get("email", ""),
        "first_name": request.POST.get("first_name", ""),
        "last_name": request.POST.get("last_name", ""),
        "phone": request.POST.get("phone", ""),
        "role": request.POST.get("role", "analyst"),
        "password": request.POST.get("password", ""),
    }
    if not data["username"] or not data["email"] or not data["password"]:
        messages.error(request, "Username, email y password son obligatorios")
        return redirect("web:configuracion-usuario-create")
    result = http_client.auth_create_user(data, request)
    if result:
        messages.success(request, f"Usuario '{data['username']}' creado correctamente")
        return redirect("web:configuracion-usuarios")
    messages.error(request, "Error al crear usuario")
    return redirect("web:configuracion-usuario-create")


def configuracion_usuario_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    user_data = http_client.auth_get_user(pk, request)
    user = user_data.get("user", user_data) if isinstance(user_data, dict) else user_data
    if not user:
        messages.error(request, "Usuario no encontrado")
        return redirect("web:configuracion-usuarios")
    return render(request, "web_app/configuracion_usuario_form.html", {"mode": "edit", "user": user, "pk": pk})


def configuracion_usuario_edit_submit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-usuarios")
    data = {
        "email": request.POST.get("email", ""),
        "first_name": request.POST.get("first_name", ""),
        "last_name": request.POST.get("last_name", ""),
        "phone": request.POST.get("phone", ""),
        "role": request.POST.get("role", "analyst"),
    }
    result = http_client.auth_update_user(pk, data, request)
    if result:
        messages.success(request, "Usuario actualizado correctamente")
    else:
        messages.error(request, "Error al actualizar usuario")
    return redirect("web:configuracion-usuarios")


def configuracion_usuario_delete_submit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-usuarios")
    ok = http_client.auth_delete_user(pk, request)
    if ok:
        messages.success(request, "Usuario eliminado correctamente")
    else:
        messages.error(request, "Error al eliminar usuario")
    return redirect("web:configuracion-usuarios")


def configuracion_usuario_reset_password(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-usuarios")
    new_password = request.POST.get("new_password", "")
    if not new_password or len(new_password) < 6:
        messages.error(request, "La contrasena debe tener al menos 6 caracteres")
        return redirect("web:configuracion-usuarios")
    ok = http_client.auth_reset_password(pk, new_password, request)
    if ok:
        messages.success(request, "Contrasena reseteada correctamente")
    else:
        messages.error(request, "Error al resetear contrasena")
    return redirect("web:configuracion-usuarios")


# ============================================================================
#  CONFIGURACION: Notification Groups
# ============================================================================

def configuracion_grupos(request):
    if not _require_auth(request):
        return _redirect_login(request)
    groups_data = http_client.bus_list_groups(request)
    groups = groups_data.get("results", []) if isinstance(groups_data, dict) else groups_data
    return render(request, "web_app/configuracion_grupos.html", {"groups": groups})


def configuracion_grupo_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return render(request, "web_app/configuracion_grupo_form.html", {"mode": "create"})
    data = {
        "name": request.POST.get("name", ""),
        "description": request.POST.get("description", ""),
    }
    if not data["name"]:
        messages.error(request, "Nombre es obligatorio")
        return redirect("web:configuracion-grupo-create")
    result = http_client.bus_create_group(data, request)
    if result:
        messages.success(request, f"Grupo '{data['name']}' creado correctamente")
        return redirect("web:configuracion-grupos")
    messages.error(request, "Error al crear grupo")
    return redirect("web:configuracion-grupo-create")


def configuracion_grupo_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        group = http_client.bus_get_group(pk, request)
        return render(request, "web_app/configuracion_grupo_form.html", {"mode": "edit", "group": group, "pk": pk})
    data = {
        "name": request.POST.get("name", ""),
        "description": request.POST.get("description", ""),
    }
    result = http_client.bus_update_group(pk, data, request)
    if result:
        messages.success(request, "Grupo actualizado correctamente")
    else:
        messages.error(request, "Error al actualizar grupo")
    return redirect("web:configuracion-grupos")


def configuracion_grupo_delete_submit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-grupos")
    ok = http_client.bus_delete_group(pk, request)
    if ok:
        messages.success(request, "Grupo eliminado correctamente")
    else:
        messages.error(request, "Error al eliminar grupo")
    return redirect("web:configuracion-grupos")


EVENT_TYPE_CHOICES = [
    ("reporte_creado", "Reporte Creado"),
    ("reporte_editado", "Reporte Editado"),
    ("reporte_eliminado", "Reporte Eliminado"),
    ("reporte_rechazado", "Reporte Rechazado"),
    ("incidente_creado", "Incidente Creado"),
    ("incidente_editado", "Incidente Editado"),
    ("incidente_estado_cambiado", "Incidente Estado Cambiado"),
    ("incidente_eliminado", "Incidente Eliminado"),
    ("login_exitoso", "Login Exitoso"),
    ("login_fallido", "Login Fallido"),
    ("login_bloqueado", "Login Bloqueado"),
    ("usuario_creado", "Usuario Creado"),
    ("usuario_desabilitado", "Usuario Deshabilitado"),
    ("servicio_down", "Servicio Down"),
    ("servicio_up", "Servicio Up"),
    ("servicio_restart", "Servicio Restart"),
    ("servicio_stop", "Servicio Stop"),
    ("agente_conectado", "Agente Conectado"),
    ("agente_desconectado", "Agente Desconectado"),
    ("amenaza_dlp", "Amenaza DLP"),
]


def configuracion_grupo_detail(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)

    if request.method == "POST":
        action = request.POST.get("action", "")
        if action == "add_member":
            user_id = request.POST.get("user_id", "").strip()
            username = request.POST.get("username", "").strip()
            email = request.POST.get("email", "").strip()
            if user_id and username:
                result = http_client.bus_add_group_member(pk, {"user_id": user_id, "username": username, "email": email}, request)
                if result:
                    messages.success(request, f"Miembro '{username}' agregado al grupo")
                else:
                    messages.error(request, "Error al agregar miembro")
            else:
                messages.error(request, "Seleccione un usuario")
        elif action == "remove_member":
            user_id = request.POST.get("user_id", "")
            if user_id:
                ok = http_client.bus_remove_group_member(pk, user_id, request)
                if ok:
                    messages.success(request, "Miembro removido del grupo")
                else:
                    messages.error(request, "Error al remover miembro")
        elif action == "add_subscription":
            event_type = request.POST.get("event_type", "")
            channel = request.POST.get("channel", "dashboard")
            if event_type:
                result = http_client.bus_create_subscription(
                    {"group": pk, "event_type": event_type, "channel": channel, "is_active": True}, request
                )
                if result:
                    messages.success(request, "Suscripcion agregada correctamente")
                else:
                    messages.error(request, "Error al agregar suscripcion (puede que ya exista)")
            else:
                messages.error(request, "Seleccione un tipo de evento")
        elif action == "remove_subscription":
            sub_id = request.POST.get("sub_id", "")
            if sub_id:
                ok = http_client.bus_delete_subscription(sub_id, request)
                if ok:
                    messages.success(request, "Suscripcion eliminada")
                else:
                    messages.error(request, "Error al eliminar suscripcion")
        return redirect("web:configuracion-grupo-detail", pk=pk)

    group = http_client.bus_get_group(pk, request)
    if not group:
        messages.error(request, "Grupo no encontrado")
        return redirect("web:configuracion-grupos")

    members = http_client.bus_list_group_members(pk, request)
    members_list = members.get("results", []) if isinstance(members, dict) else members

    subscriptions = http_client.bus_list_subscriptions(pk, request)
    subs_list = subscriptions if isinstance(subscriptions, list) else []

    users_data = http_client.auth_list_users(request)
    all_users = users_data.get("users", []) if isinstance(users_data, dict) else []
    member_ids = {m.get("user_id") for m in members_list}
    available_users = [u for u in all_users if str(u.get("id")) not in member_ids]

    return render(request, "web_app/configuracion_grupo_detail.html", {
        "group": group,
        "members": members_list,
        "subscriptions": subs_list,
        "available_users": available_users,
        "event_types": EVENT_TYPE_CHOICES,
    })


# ============================================================================
#  CONFIGURACION: Email Config
# ============================================================================

def configuracion_correo(request):
    if not _require_auth(request):
        return _redirect_login(request)
    configs_data = http_client.bus_list_email_configs(request)
    configs = configs_data.get("results", []) if isinstance(configs_data, dict) else configs_data
    return render(request, "web_app/configuracion_correo.html", {"configs": configs})


def configuracion_correo_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return render(request, "web_app/configuracion_correo_form.html", {"mode": "create"})
    data = {
        "smtp_host": request.POST.get("smtp_host", ""),
        "smtp_port": int(request.POST.get("smtp_port", "587") or "587"),
        "smtp_user": request.POST.get("smtp_user", ""),
        "smtp_password": request.POST.get("smtp_password", ""),
        "use_tls": request.POST.get("use_tls") == "on",
        "from_address": request.POST.get("from_address", "vant-alerts@example.com"),
        "is_active": request.POST.get("is_active") == "on",
    }
    if not data["smtp_host"]:
        messages.error(request, "SMTP Host es obligatorio")
        return redirect("web:configuracion-correo-create")
    result = http_client.bus_create_email_config(data, request)
    if result:
        messages.success(request, "Configuracion de correo creada correctamente")
        return redirect("web:configuracion-correo")
    messages.error(request, "Error al crear configuracion")
    return redirect("web:configuracion-correo-create")


def configuracion_correo_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        configs_data = http_client.bus_list_email_configs(request)
        configs = configs_data.get("results", []) if isinstance(configs_data, dict) else configs_data
        config = configs[0] if configs else None
        return render(request, "web_app/configuracion_correo_form.html", {"mode": "edit", "config": config, "pk": pk})
    data = {
        "smtp_host": request.POST.get("smtp_host", ""),
        "smtp_port": int(request.POST.get("smtp_port", "587") or "587"),
        "smtp_user": request.POST.get("smtp_user", ""),
        "smtp_password": request.POST.get("smtp_password", ""),
        "use_tls": request.POST.get("use_tls") == "on",
        "from_address": request.POST.get("from_address", "vant-alerts@example.com"),
        "is_active": request.POST.get("is_active") == "on",
    }
    result = http_client.bus_update_email_config(pk, data, request)
    if result:
        messages.success(request, "Configuracion actualizada correctamente")
    else:
        messages.error(request, "Error al actualizar configuracion")
    return redirect("web:configuracion-correo")


def configuracion_correo_delete_submit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-correo")
    ok = http_client.bus_delete_email_config(pk, request)
    if ok:
        messages.success(request, "Configuracion eliminada correctamente")
    else:
        messages.error(request, "Error al eliminar configuracion")
    return redirect("web:configuracion-correo")


def configuracion_correo_test_submit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-correo")
    ok = http_client.bus_test_email_config(pk, request)
    if ok:
        messages.success(request, "Email de prueba enviado correctamente")
    else:
        messages.error(request, "Error al enviar email de prueba")
    return redirect("web:configuracion-correo")


# ============================================================================
#  CONFIGURACION: Ecosystem Status
# ============================================================================

def configuracion_ecosistema(request):
    if not _require_auth(request):
        return _redirect_login(request)
    services_data = http_client.bus_list_services(request)
    services = services_data.get("results", []) if isinstance(services_data, dict) else services_data
    stats = http_client.bus_dashboard_stats(request)

    healthy_count = 0
    unhealthy_count = 0
    unknown_count = 0
    for svc in services:
        status = svc.get("last_health_status", "unknown")
        if status == "healthy":
            healthy_count += 1
        elif status in ("unhealthy", "degraded"):
            unhealthy_count += 1
        else:
            unknown_count += 1

    return render(request, "web_app/configuracion_ecosistema.html", {
        "services": services,
        "healthy_count": healthy_count,
        "unhealthy_count": unhealthy_count,
        "unknown_count": unknown_count,
        "stats": stats,
    })


def configuracion_ecosistema_action(request, pk, action):
    if not _require_auth(request):
        return _redirect_login(request)
    if request.method != "POST":
        return redirect("web:configuracion-ecosistema")
    ok = http_client.bus_service_action(pk, action, request)
    if ok:
        messages.success(request, f"Servicio {action} ejecutado correctamente")
    else:
        messages.error(request, f"Error al ejecutar {action} en el servicio")
    return redirect("web:configuracion-ecosistema")


# ============================================================================
#  GESTION DE BASE DE DATOS
# ============================================================================

def db_dashboard(request):
    if not _require_auth(request):
        return _redirect_login(request)
    health = http_client.get_db_health(request)
    policies_data = http_client.get_retention_policies(request, page_size=50)
    backups_data = http_client.get_backups(request, page_size=10)
    return render(request, "web_app/configuracion_db_management.html", {
        "health": health or {},
        "policies": policies_data.get("results", []),
        "backups": backups_data.get("results", []),
    })


def db_retention_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = http_client.get_retention_policies(request, page_size=100)
    return render(request, "web_app/configuracion_retention_policies.html", {
        "policies": data.get("results", []),
    })


@csrf_protect
@require_POST
def db_retention_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {k: request.POST.get(k, "") for k in ("entity_type", "retention_days", "action", "description")}
    data["is_active"] = request.POST.get("is_active", "false") == "true"
    try:
        data["retention_days"] = int(data["retention_days"])
    except (ValueError, TypeError):
        data["retention_days"] = 90
    if http_client.create_retention_policy(data, request):
        messages.success(request, "Politica de retencion creada.")
    else:
        messages.error(request, "Error al crear la politica.")
    return redirect("web:configuracion-db-retention")


@csrf_protect
@require_POST
def db_retention_edit(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    data = {k: request.POST.get(k, "") for k in ("entity_type", "retention_days", "action", "description")}
    data["is_active"] = request.POST.get("is_active", "false") == "true"
    try:
        data["retention_days"] = int(data["retention_days"])
    except (ValueError, TypeError):
        data["retention_days"] = 90
    if http_client.update_retention_policy(pk, data, request):
        messages.success(request, "Politica actualizada.")
    else:
        messages.error(request, "Error al actualizar.")
    return redirect("web:configuracion-db-retention")


@csrf_protect
@require_POST
def db_retention_delete(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if http_client.delete_retention_policy(pk, request):
        messages.success(request, "Politica eliminada.")
    else:
        messages.error(request, "Error al eliminar.")
    return redirect("web:configuracion-db-retention")


def db_backups_list(request):
    if not _require_auth(request):
        return _redirect_login(request)
    data = http_client.get_backups(request, page_size=100)
    return render(request, "web_app/configuracion_db_backups.html", {
        "backups": data.get("results", []),
    })


@csrf_protect
@require_POST
def db_backup_create(request):
    if not _require_auth(request):
        return _redirect_login(request)
    result = http_client.create_backup({
        "backup_type": request.POST.get("backup_type", "full"),
        "notes": request.POST.get("notes", ""),
    }, request)
    if result:
        messages.success(request, "Respaldo iniciado.")
    else:
        messages.error(request, "Error al iniciar respaldo.")
    return redirect("web:configuracion-db-backups")


@csrf_protect
@require_POST
def db_backup_restore(request, pk):
    if not _require_auth(request):
        return _redirect_login(request)
    if http_client.restore_backup(pk, request):
        messages.success(request, "Restauracion completada.")
    else:
        messages.error(request, "Error en la restauracion.")
    return redirect("web:configuracion-db-backups")


@require_POST
def db_optimize_action(request):
    if not _require_auth(request):
        return _redirect_login(request)
    action = request.POST.get("action", "vacuum")
    table = request.POST.get("table", "")
    if http_client.post_db_optimize(action, table, request):
        messages.success(request, f"Optimizacion '{action}' completada.")
    else:
        messages.error(request, f"Error en optimizacion '{action}'.")
    return redirect("web:configuracion-db-dashboard")


def intelligence_dashboard(request):
    if not _require_auth(request):
        return _redirect_login(request)
    stats = http_client.intel_dashboard_stats(request)
    ip_reports = http_client.intel_ip_reports(request, page_size=20)
    api_keys = http_client.intel_api_keys(request)
    return render(request, "web_app/intelligence_dashboard.html", {
        "stats": stats,
        "ip_reports": ip_reports.get("results", []),
        "api_keys": api_keys,
    })


def intelligence_analytics(request):
    if not _require_auth(request):
        return _redirect_login(request)
    hours = int(request.GET.get("hours", 24))
    analytics_data = http_client.intel_analytics_dashboard(request, hours=hours)
    return render(request, "web_app/intelligence_analytics.html", {
        "hours": hours,
        "analytics_data": json.dumps(analytics_data),
    })


def intelligence_geo(request):
    if not _require_auth(request):
        return _redirect_login(request)
    hours = int(request.GET.get("hours", 24))
    geo_data = http_client.intel_analytics_geo(request, hours=hours)
    return render(request, "web_app/intelligence_geo.html", {
        "hours": hours,
        "geo_data": json.dumps(geo_data),
    })


def intelligence_geo_live(request):
    if not _require_auth(request):
        return _redirect_login(request)
    return render(request, "web_app/intelligence_geo.html", {
        "hours": 1,
        "geo_data": "{}",
    })


def intelligence_geo_report(request):
    if not _require_auth(request):
        return _redirect_login(request)
    return render(request, "web_app/intelligence_geo_report.html")


def intelligence_geo_report_api(request):
    if not _require_auth(request):
        return JsonResponse({"error": "Unauthorized"}, status=401)
    period = request.GET.get("period", "week")
    data = http_client.intel_analytics_geo_report(request, period=period)
    return JsonResponse(data)


@require_POST
def configuracion_api_key_save(request):
    if not _require_auth(request):
        return _redirect_login(request)
    provider = request.POST.get("provider")
    api_key = request.POST.get("api_key", "").strip()
    if not provider or not api_key:
        messages.error(request, "Provider y API Key son requeridos.")
        return redirect("web:configuracion-api-keys")
    result = http_client.intel_api_key_update(provider, {"api_key": api_key}, request)
    if result:
        messages.success(request, f"API Key de {provider} guardada exitosamente.")
    else:
        messages.error(request, f"Error al guardar API Key de {provider}.")
    return redirect("web:configuracion-api-keys")


@require_POST
def configuracion_api_key_delete(request, provider):
    if not _require_auth(request):
        return _redirect_login(request)
    if http_client.intel_api_key_delete(provider, request):
        messages.success(request, f"API Key de {provider} eliminada.")
    else:
        messages.error(request, f"Error al eliminar API Key de {provider}.")
    return redirect("web:configuracion-api-keys")


def configuracion_api_keys(request):
    if not _require_auth(request):
        return _redirect_login(request)
    api_keys = http_client.intel_api_keys(request)
    keys_by_provider = {k.get("provider"): k for k in api_keys if isinstance(k, dict)}

    providers_config = [
        {"provider": "abuseipdb", "name": "AbuseIPDB", "icon": "fa-flag", "color": "red",
         "desc": "Reputacion de direcciones IP", "current": keys_by_provider.get("abuseipdb")},
        {"provider": "macvendors", "name": "MAC Vendors", "icon": "fa-network-wired", "color": "cyan",
         "desc": "Fabricante por direccion MAC", "current": keys_by_provider.get("macvendors")},
        {"provider": "virustotal", "name": "VirusTotal", "icon": "fa-virus", "color": "amber",
         "desc": "Analisis de amenazas (IP, dominio, URL, hash)", "current": keys_by_provider.get("virustotal")},
    ]

    return render(request, "web_app/configuracion_api_keys.html", {
        "providers": providers_config,
    })


@require_POST
def configuracion_api_key_test(request, provider):
    if not _require_auth(request):
        return _redirect_login(request)
    result = http_client.intel_api_key_test(provider, request)
    if result.get("success"):
        messages.success(request, f"{provider}: {result.get('message', 'OK')}")
    else:
        messages.error(request, f"{provider}: {result.get('message', 'Error')}")
    return redirect("web:configuracion-api-keys")
