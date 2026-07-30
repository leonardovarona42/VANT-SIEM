import os
import logging

import requests
from django.conf import settings

logger = logging.getLogger("vant_web.http_client")


def _get_session():
    s = requests.Session()
    secret = getattr(settings, "SERVICE_SECRET", "") or os.getenv("SERVICE_SECRET", "")
    if secret:
        s.headers.update({"X-Service-Secret": secret})
    s.timeout = 15
    return s


def _auth_headers(request=None):
    headers = {}
    if request and request.session.get("jwt_token"):
        headers["Authorization"] = f"Bearer {request.session['jwt_token']}"
    return headers


def _service_call(method, url, request=None, **kwargs):
    try:
        s = _get_session()
        headers = _auth_headers(request)
        headers.update(kwargs.pop("headers", {}))
        resp = getattr(s, method)(url, headers=headers, **kwargs)
        return resp
    except requests.ConnectionError:
        logger.warning("Service unavailable: %s", url)
        return None
    except requests.Timeout:
        logger.warning("Service timeout: %s", url)
        return None
    except Exception as e:
        logger.error("Service call error: %s %s -> %s", method, url, e)
        return None


# ── Auth Service ──────────────────────────────────────────────────────

def auth_login(username, password):
    resp = _service_call(
        "post",
        f"{settings.AUTH_SERVICE_URL}/auth/api/login/",
        json={"username": username, "password": password},
    )
    if resp and resp.ok:
        return resp.json()
    return None


def auth_logout(request):
    resp = _service_call(
        "post",
        f"{settings.AUTH_SERVICE_URL}/auth/api/logout/",
        request=request,
    )
    return resp is not None and resp.ok


def auth_me(request):
    resp = _service_call(
        "get",
        f"{settings.AUTH_SERVICE_URL}/auth/api/users/me/",
        request=request,
    )
    if resp and resp.ok:
        data = resp.json()
        return data.get("user", data)
    return None


# ── Inventory Service ─────────────────────────────────────────────────

def get_agents(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/agents/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_agent(agent_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/agents/{agent_id}/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def get_agent_hardware(agent_id, request=None):
    agent = get_agent(agent_id, request)
    if agent and agent.get("hardware"):
        return agent["hardware"]
    return None


def get_agent_software(agent_id, request=None, **params):
    params["agent_id"] = agent_id
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/software/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_software_inventory(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/software/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_inventory_stats(request=None):
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/stats/dashboard/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {}


def inventory_health():
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/health/",
    )
    return resp is not None and resp.ok


def send_agent_command(agent_id, command_type, payload=None, request=None):
    resp = _service_call(
        "post",
        f"{settings.INVENTORY_SERVICE_URL}/api/agents/{agent_id}/command/",
        request=request,
        json={"command_type": command_type, "payload": payload or {}},
    )
    if resp and resp.ok:
        return resp.json()
    return None


def delete_agent(agent_id, request=None):
    resp = _service_call(
        "delete",
        f"{settings.INVENTORY_SERVICE_URL}/api/agents/{agent_id}/delete/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def get_agent_processes(agent_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/processes/latest/{agent_id}/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {"status": "no_data"}


def get_agent_services(agent_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.INVENTORY_SERVICE_URL}/api/agents/{agent_id}/services/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {"services": [], "total": 0}


def toggle_service_monitoring(agent_id, monitored_services, request=None):
    resp = _service_call(
        "post",
        f"{settings.INVENTORY_SERVICE_URL}/api/agents/{agent_id}/services/toggle/",
        request=request,
        json={"monitored_services": monitored_services},
    )
    if resp and resp.ok:
        return resp.json()
    return None


# ── Logs Service ──────────────────────────────────────────────────────

def get_events(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/events/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_event(event_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/events/{event_id}/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def get_log_sources(request=None):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/sources/list/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_log_source_host_ips(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/sources/host-ips/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_log_source_types(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/sources/source-types/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_log_field_values(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/events/field-values/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {}


def get_logs_histogram(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/events/histogram/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"timeline": [], "total": 0}


def get_logs_stats(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/statistics/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {}


def get_suricata_stats(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/statistics/suricata/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {}


def logs_health():
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/health/",
    )
    return resp is not None and resp.ok


def get_logs_storage_dashboard(request=None):
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/storage/dashboard/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {}


# ── SOC Service (DLP + Bitacora) ─────────────────────────────────────

def get_incidents(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/threats/dlp/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_incident(incident_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/threats/dlp/{incident_id}/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def acknowledge_incident(incident_id, request=None):
    resp = _service_call(
        "patch",
        f"{settings.SOC_SERVICE_URL}/soc/api/threats/dlp/{incident_id}/acknowledge/",
        request=request,
    )
    return resp is not None and resp.ok


def resolve_incident(incident_id, data, request=None):
    resp = _service_call(
        "patch",
        f"{settings.SOC_SERVICE_URL}/soc/api/threats/dlp/{incident_id}/resolve/",
        request=request,
        json=data,
    )
    return resp is not None and resp.ok


def get_policies(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/policies/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_policy(code, request=None):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/policies/{code}/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def create_policy(data, request=None):
    resp = _service_call(
        "post",
        f"{settings.SOC_SERVICE_URL}/soc/api/policies/",
        request=request,
        json=data,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def update_policy(code, data, request=None):
    resp = _service_call(
        "put",
        f"{settings.SOC_SERVICE_URL}/soc/api/policies/{code}/",
        request=request,
        json=data,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def delete_policy(code, request=None):
    resp = _service_call(
        "delete",
        f"{settings.SOC_SERVICE_URL}/soc/api/policies/{code}/",
        request=request,
    )
    return resp is not None and resp.ok


def get_soc_stats(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/stats/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {}


def soc_health():
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/health/",
    )
    return resp is not None and resp.ok


def get_scan_summaries(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/scans/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: Bitacora (Incidentes reales) ──────────────────────────────

def get_soc_incidents(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        data = resp.json()
        for r in data.get("results", []):
            _rewrite_incident_urls(r)
        return data
    return {"results": [], "count": 0}


def _rewrite_media_url(url):
    if url and "/media/" in url:
        return "/media/" + url.split("/media/", 1)[-1]
    return url


def _rewrite_incident_urls(data):
    if isinstance(data, dict):
        ev = data.get("evidencia")
        if ev:
            data["evidencia"] = _rewrite_media_url(ev)
    return data


def get_soc_incident(incident_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{incident_id}/",
        request=request,
    )
    if resp and resp.ok:
        return _rewrite_incident_urls(resp.json())
    return None


def transition_soc_incident(incident_id, action, data=None, request=None):
    resp = _service_call(
        "post",
        f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{incident_id}/{action}/",
        request=request,
        json=data or {},
    )
    return resp is not None and resp.ok


def update_soc_incident(incident_id, data, request=None):
    resp = _service_call(
        "patch",
        f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{incident_id}/",
        request=request,
        json=data,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def get_reportes(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/reportes/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: Categorias / Subcategorias ────────────────────────────────

def get_categorias(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/categorias/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_subcategorias(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/subcategorias/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: Responsables / Areas ──────────────────────────────────────

def get_responsables(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/responsables/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_areas(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/areas/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: Medidas ───────────────────────────────────────────────────

def get_medidas(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/medidas/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: Infraestructura / CMDB ────────────────────────────────────

def get_servicios(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/servicios/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_servicios_metrics(request=None):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/servicios/metrics/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {}


def get_servicio(servicio_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/servicios/{servicio_id}/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return None


def get_servicio_ips(servicio_id, request=None):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/servicio-ips/?servicio={servicio_id}",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_puertos(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/puertos/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


def get_conexiones(request=None, **params):
    resp = _service_call(
        "get",
        f"{settings.SOC_SERVICE_URL}/soc/api/conexiones/",
        request=request,
        params=params,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: CRUD helpers ───────────────────────────────────────────────

def create_responsable(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/responsables/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_responsable(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/responsables/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_responsable(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/responsables/{pk}/", request=request)
    return resp is not None and resp.ok


def create_area(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/areas/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_area(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/areas/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_area(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/areas/{pk}/", request=request)
    return resp is not None and resp.ok


def create_categoria(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/categorias/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_categoria(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/categorias/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_categoria(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/categorias/{pk}/", request=request)
    return resp is not None and resp.ok


def create_subcategoria(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/subcategorias/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_subcategoria(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/subcategorias/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_subcategoria(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/subcategorias/{pk}/", request=request)
    return resp is not None and resp.ok


def create_medida(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/medidas/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_medida(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/medidas/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_medida(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/medidas/{pk}/", request=request)
    return resp is not None and resp.ok


def get_involucrado(pk, request=None):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/involucrados/{pk}/", request=request)
    if resp and resp.ok:
        return resp.json()
    return None

def create_involucrado(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/involucrados/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_involucrado(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/involucrados/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_involucrado(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/involucrados/{pk}/", request=request)
    return resp is not None and resp.ok


def get_involucrados(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/involucrados/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: CRUD - Incidentes ──────────────────────────────────────────

def create_incidente(data, request=None, actor_username=""):
    headers = {"X-Suppress-Event": "true"}
    if actor_username:
        headers["X-Actor-Username"] = actor_username
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/", request=request, json=data, headers=headers)
    if resp and resp.ok:
        return resp.json()
    return None

def update_incidente(incident_id, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{incident_id}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_incidente(incident_id, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/{incident_id}/", request=request)
    return resp is not None and resp.ok


# ── SOC: CRUD - Reportes ───────────────────────────────────────────

def get_reporte(pk, request=None):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/reportes/{pk}/", request=request)
    if resp and resp.ok:
        return resp.json()
    return None

def create_reporte(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/reportes/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_reporte(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/reportes/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_reporte(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/reportes/{pk}/", request=request)
    return resp is not None and resp.ok


# ── SOC: CRUD - Servicios ──────────────────────────────────────────

def create_servicio(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/servicios/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_servicio(servicio_id, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/servicios/{servicio_id}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_servicio(servicio_id, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/servicios/{servicio_id}/", request=request)
    return resp is not None and resp.ok


# ── SOC: CRUD - Medidas Incidente ──────────────────────────────────

def get_medidas_incidente(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/medidas-incidente/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}

def create_medida_incidente(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/medidas-incidente/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def update_medida_incidente(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/soc/api/medidas-incidente/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_medida_incidente(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/medidas-incidente/{pk}/", request=request)
    return resp is not None and resp.ok


# ── SOC: CRUD - Involucrado Incidente ──────────────────────────────

def get_involucrado_incidente(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/involucrado-incidente/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}

def create_involucrado_incidente(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/soc/api/involucrado-incidente/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def delete_involucrado_incidente(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/soc/api/involucrado-incidente/{pk}/", request=request)
    return resp is not None and resp.ok


# ── SOC: Topologia / Redes ──────────────────────────────────────────

def get_conexiones_topologicas(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/conexiones/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}

def get_puertos_dispositivo(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/puertos/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}

def get_monitoreo_servicio(servicio_id, request=None, **params):
    params["servicio"] = servicio_id
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/monitoreo/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


# ── SOC: Metrics ────────────────────────────────────────────────────

def get_incidentes_metrics(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/incidentes/metrics/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"totales": {}, "total": 0, "tasa_resolucion": 0, "atencion": {"promedio": 0, "minimo": 0, "maximo": 0, "gauge": 0, "mensual": []}, "solucion": {"promedio": 0, "minimo": 0, "maximo": 0, "gauge": 0, "mensual": []}}


def get_reportes_metrics(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/soc/api/reportes/metrics/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"totales": {}, "total": 0, "tasa_resolucion": 0, "atencion": {"promedio": 0, "minimo": 0, "maximo": 0, "gauge": 0, "mensual": []}, "solucion": {"promedio": 0, "minimo": 0, "maximo": 0, "gauge": 0, "mensual": []}}


# ── Auth: Users CRUD ────────────────────────────────────────────────

def auth_list_users(request=None, **params):
    resp = _service_call("get", f"{settings.AUTH_SERVICE_URL}/auth/api/users/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"users": []}

def auth_create_user(data, request=None):
    resp = _service_call("post", f"{settings.AUTH_SERVICE_URL}/auth/api/users/create/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def auth_get_user(pk, request=None):
    resp = _service_call("get", f"{settings.AUTH_SERVICE_URL}/auth/api/users/{pk}/", request=request)
    if resp and resp.ok:
        return resp.json()
    return None

def auth_update_user(pk, data, request=None):
    resp = _service_call("put", f"{settings.AUTH_SERVICE_URL}/auth/api/users/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def auth_delete_user(pk, request=None):
    resp = _service_call("delete", f"{settings.AUTH_SERVICE_URL}/auth/api/users/{pk}/delete/", request=request)
    return resp is not None and resp.ok

def auth_reset_password(pk, new_password, request=None):
    resp = _service_call("post", f"{settings.AUTH_SERVICE_URL}/auth/api/users/{pk}/reset-password/", request=request, json={"password": new_password})
    return resp is not None and resp.ok


# ── Bus: Groups ─────────────────────────────────────────────────────

def bus_list_groups(request=None, **params):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/groups/", request=request, params=params)
    if resp and resp.ok:
        data = resp.json()
        if isinstance(data, list):
            return {"results": data}
        return data
    return {"results": []}

def bus_create_group(data, request=None):
    resp = _service_call("post", f"{settings.BUS_SERVICE_URL}/api/groups/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_update_group(pk, data, request=None):
    resp = _service_call("patch", f"{settings.BUS_SERVICE_URL}/api/groups/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_delete_group(pk, request=None):
    resp = _service_call("delete", f"{settings.BUS_SERVICE_URL}/api/groups/{pk}/", request=request)
    return resp is not None and resp.ok

def bus_get_group(pk, request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/groups/{pk}/", request=request)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_list_group_members(group_pk, request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/groups/{group_pk}/members/", request=request)
    if resp and resp.ok:
        data = resp.json()
        if isinstance(data, list):
            return {"results": data}
        return data
    return {"results": []}

def bus_add_group_member(group_pk, data, request=None):
    resp = _service_call("post", f"{settings.BUS_SERVICE_URL}/api/groups/{group_pk}/members/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_remove_group_member(group_pk, user_id, request=None):
    resp = _service_call("delete", f"{settings.BUS_SERVICE_URL}/api/groups/{group_pk}/members/?user_id={user_id}", request=request)
    return resp is not None and resp.ok


# ── Bus: Subscriptions ─────────────────────────────────────────────

def bus_list_subscriptions(group_pk=None, request=None):
    params = {}
    if group_pk:
        params["group"] = group_pk
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/subscriptions/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return []

def bus_create_subscription(data, request=None):
    resp = _service_call("post", f"{settings.BUS_SERVICE_URL}/api/subscriptions/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_delete_subscription(sub_id, request=None):
    resp = _service_call("delete", f"{settings.BUS_SERVICE_URL}/api/subscriptions/{sub_id}/", request=request)
    return resp is not None and resp.ok


# ── Bus: Email Config ───────────────────────────────────────────────

def bus_list_email_configs(request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/email-config/", request=request)
    if resp and resp.ok:
        data = resp.json()
        if isinstance(data, list):
            return {"results": data}
        if isinstance(data, dict):
            if "results" in data:
                return data
            return {"results": [data]}
    return {"results": []}

def bus_create_email_config(data, request=None):
    resp = _service_call("post", f"{settings.BUS_SERVICE_URL}/api/email-config/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_update_email_config(pk, data, request=None):
    resp = _service_call("put", f"{settings.BUS_SERVICE_URL}/api/email-config/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_delete_email_config(pk, request=None):
    data = {"is_active": False}
    resp = _service_call("put", f"{settings.BUS_SERVICE_URL}/api/email-config/", request=request, json=data)
    return resp is not None and resp.ok

def bus_test_email_config(pk=None, request=None):
    resp = _service_call("post", f"{settings.BUS_SERVICE_URL}/api/email-config/test/", request=request, json={"id": pk} if pk else {})
    return resp is not None and resp.ok


# ── Bus: Services (Orchestration) ───────────────────────────────────

def bus_list_services(request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/services/", request=request)
    if resp and resp.ok:
        data = resp.json()
        if isinstance(data, list):
            return {"results": data}
        return data
    return {"results": []}

def bus_get_service(pk, request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/services/{pk}/", request=request)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_create_service(data, request=None):
    resp = _service_call("post", f"{settings.BUS_SERVICE_URL}/api/services/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_update_service(pk, data, request=None):
    resp = _service_call("patch", f"{settings.BUS_SERVICE_URL}/api/services/{pk}/", request=request, json=data)
    if resp and resp.ok:
        return resp.json()
    return None

def bus_delete_service(pk, request=None):
    resp = _service_call("delete", f"{settings.BUS_SERVICE_URL}/api/services/{pk}/", request=request)
    return resp is not None and resp.ok

def bus_service_action(pk, action, request=None):
    resp = _service_call("post", f"{settings.BUS_SERVICE_URL}/api/services/{pk}/{action}/", request=request)
    return resp is not None and resp.ok

def bus_service_health(pk, request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/services/{pk}/health/", request=request)
    if resp and resp.ok:
        return resp.json()
    return []


# ── Bus: Dashboard ──────────────────────────────────────────────────

def bus_dashboard_summary(request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/dashboard/", request=request)
    if resp and resp.ok:
        return resp.json()
    return {}

def bus_dashboard_stats(request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/stats/", request=request)
    if resp and resp.ok:
        return resp.json()
    return {}


def bus_list_events(request=None, **params):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/events/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"count": 0, "results": []}


def bus_event_detail(event_id, request=None):
    resp = _service_call("get", f"{settings.BUS_SERVICE_URL}/api/events/{event_id}/", request=request)
    if resp and resp.ok:
        return resp.json()
    return None


# ============================================================================
#  GESTION DE BASE DE DATOS
# ============================================================================

def get_db_health(request=None):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/api/db/health/", request=request)
    if resp and resp.ok:
        return resp.json()
    return None


def post_db_optimize(action, table="", request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/api/db/optimize/", request=request, json={"action": action, "table": table})
    return resp and resp.ok


def get_retention_policies(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/api/db/retention-policies/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"count": 0, "results": []}


def create_retention_policy(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/api/db/retention-policies/", request=request, json=data)
    return resp and resp.ok


def update_retention_policy(pk, data, request=None):
    resp = _service_call("put", f"{settings.SOC_SERVICE_URL}/api/db/retention-policies/{pk}/", request=request, json=data)
    return resp and resp.ok


def delete_retention_policy(pk, request=None):
    resp = _service_call("delete", f"{settings.SOC_SERVICE_URL}/api/db/retention-policies/{pk}/", request=request)
    return resp and resp.ok


def get_backups(request=None, **params):
    resp = _service_call("get", f"{settings.SOC_SERVICE_URL}/api/db/backups/", request=request, params=params)
    if resp and resp.ok:
        return resp.json()
    return {"count": 0, "results": []}


def create_backup(data, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/api/db/backups/create_backup/", request=request, json=data)
    return resp.json() if resp and resp.ok else None


def restore_backup(pk, request=None):
    resp = _service_call("post", f"{settings.SOC_SERVICE_URL}/api/db/backups/{pk}/restore/", request=request)
    return resp and resp.ok


# ── Intelligence Service ─────────────────────────────────────────────

def intel_health(request=None):
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/health/", request=request)
    return resp.json() if resp and resp.ok else {"status": "unreachable"}


def intel_dashboard_stats(request=None):
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/dashboard/", request=request)
    return resp.json() if resp and resp.ok else {}


def intel_global_stats(request=None):
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/stats/", request=request)
    return resp.json() if resp and resp.ok else {}


def intel_ip_lookup(ip, request=None, force=False):
    params = {"ip": ip, "force": "1" if force else "0"}
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/ip/lookup/", request=request, params=params)
    return resp.json() if resp and resp.ok else None


def intel_mac_lookup(mac, request=None, force=False):
    params = {"mac": mac, "force": "1" if force else "0"}
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/mac/lookup/", request=request, params=params)
    return resp.json() if resp and resp.ok else None


def intel_vt_lookup(indicator, indicator_type, request=None, force=False):
    params = {"indicator": indicator, "indicator_type": indicator_type, "force": "1" if force else "0"}
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/vt/lookup/", request=request, params=params)
    return resp.json() if resp and resp.ok else None


def intel_ip_reports(request=None, page=1, page_size=50):
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/ip/reports/", request=request, params={"page": page, "page_size": page_size})
    return resp.json() if resp and resp.ok else {"count": 0, "results": []}


def intel_api_keys(request=None):
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/keys/", request=request)
    return resp.json() if resp and resp.ok else []


def intel_api_key_update(provider, data, request=None):
    resp = _service_call("put", f"{settings.INTELLIGENCE_SERVICE_URL}/api/keys/{provider}/", request=request, json=data)
    return resp.json() if resp and resp.ok else None


def intel_api_key_delete(provider, request=None):
    resp = _service_call("delete", f"{settings.INTELLIGENCE_SERVICE_URL}/api/keys/{provider}/", request=request)
    return resp and resp.ok


def intel_api_key_test(provider, request=None):
    resp = _service_call("post", f"{settings.INTELLIGENCE_SERVICE_URL}/api/keys/{provider}/test/", request=request)
    return resp.json() if resp else {"success": False, "message": "Servicio de inteligencia no disponible."}


def intel_scan_jobs(request=None, status=None, page=1, page_size=50):
    params = {"page": page, "page_size": page_size}
    if status:
        params["status"] = status
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/jobs/", request=request, params=params)
    return resp.json() if resp and resp.ok else {"count": 0, "results": []}


def intel_scan_job_create(data, request=None):
    resp = _service_call("post", f"{settings.INTELLIGENCE_SERVICE_URL}/api/jobs/create/", request=request, json=data)
    return resp.json() if resp and resp.ok else None


def intel_analytics_dashboard(request=None, hours=24):
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/analytics/dashboard/?hours={hours}", request=request)
    return resp.json() if resp and resp.ok else {"stats": {}}


def intel_analytics_geo(request=None, hours=24):
    resp = _service_call("get", f"{settings.INTELLIGENCE_SERVICE_URL}/api/analytics/geo/?hours={hours}", request=request, timeout=120)
    return resp.json() if resp and resp.ok else {"countries": [], "flows": [], "stats": {}}
