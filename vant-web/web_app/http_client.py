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
        f"{settings.INVENTORY_SERVICE_URL}/api/health/",
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
        f"{settings.LOGS_SERVICE_URL}/api/sources/",
        request=request,
    )
    if resp and resp.ok:
        return resp.json()
    return {"results": [], "count": 0}


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


def logs_health():
    resp = _service_call(
        "get",
        f"{settings.LOGS_SERVICE_URL}/api/health/",
    )
    return resp is not None and resp.ok


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
