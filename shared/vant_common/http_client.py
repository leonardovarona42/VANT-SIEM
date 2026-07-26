"""
VANT-SIEM Shared HTTP Client.
Connection-pooled requests with retry logic and service-to-service auth.
"""
import logging
import os
import time
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("vant_common.http_client")

SERVICE_SECRET = os.getenv("SERVICE_SECRET", "changeme-service-secret")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://127.0.0.1:8100")
BUS_SERVICE_URL = os.getenv("BUS_SERVICE_URL", "http://127.0.0.1:8600")

_session = None


def get_session():
    global _session
    if _session is None:
        _session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=20)
        _session.mount("http://", adapter)
        _session.mount("https://", adapter)
        _session.headers.update({"Content-Type": "application/json"})
    return _session


def service_request(method, url, **kwargs):
    session = get_session()
    headers = kwargs.pop("headers", {})
    headers["X-Service-Secret"] = SERVICE_SECRET
    kwargs["headers"] = headers
    kwargs.setdefault("timeout", 15)
    try:
        response = session.request(method, url, **kwargs)
        return response
    except requests.exceptions.ConnectionError as e:
        logger.error("service_request connection_error url=%s error=%s", url, e)
        raise
    except requests.exceptions.Timeout as e:
        logger.error("service_request timeout url=%s error=%s", url, e)
        raise


def auth_validate_agent_token(token):
    url = f"{AUTH_SERVICE_URL}/auth/api/agent/validate/"
    resp = service_request("POST", url, json={"token": token})
    if resp.status_code == 200:
        return resp.json()
    return None


def auth_validate_jwt(token):
    url = f"{AUTH_SERVICE_URL}/auth/api/validate/"
    resp = service_request("POST", url, json={"token": token})
    if resp.status_code == 200:
        return resp.json()
    return None


def bus_publish_alert(severity, title, message, source="", metadata=None):
    url = f"{BUS_SERVICE_URL}/api/alerts/send/"
    try:
        resp = service_request("POST", url, json={
            "severity": severity,
            "title": title,
            "message": message,
            "source": source,
            "metadata": metadata or {},
        }, timeout=5)
        return resp.status_code == 200
    except Exception as e:
        logger.warning("bus_publish_alert failed: %s", e)
        return False
