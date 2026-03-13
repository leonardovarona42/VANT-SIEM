import os
import socket
import subprocess
import sys
from pathlib import Path

from django.db import connections


_SCHEMA_APPLIED = False
_SERVICE_STARTED = False


def _project_root():
    return Path(__file__).resolve().parents[1]


def _schema_path():
    return _project_root() / "opensearch_service" / "service" / "schema.sql"


def _autostart_disabled_path():
    return _project_root() / ".opensearch_autostart.disabled"


def set_autostart_enabled(enabled):
    marker = _autostart_disabled_path()
    if enabled:
        if marker.exists():
            marker.unlink()
    else:
        marker.write_text("disabled", encoding="utf-8")


def is_autostart_enabled():
    return not _autostart_disabled_path().exists()


def apply_opensearch_schema():
    global _SCHEMA_APPLIED
    if _SCHEMA_APPLIED:
        return

    schema_path = _schema_path()
    if not schema_path.exists():
        print(f"[WARN] OpenSearch schema not found at {schema_path}")
        return

    sql = schema_path.read_text(encoding="utf-8")
    try:
        conn = connections["opensearch"]
    except Exception as exc:
        print(f"[WARN] OpenSearch DB alias not available: {exc}")
        return

    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        _SCHEMA_APPLIED = True
        print("[START] OpenSearch schema aplicado (os_sources, os_events_raw).")
    except Exception as exc:
        print(f"[WARN] No se pudo aplicar schema OpenSearch: {exc}")


def _is_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def start_opensearch_service():
    global _SERVICE_STARTED
    if _SERVICE_STARTED:
        return

    if os.getenv("VANT_OS_SERVICE_AUTOSTART", "1") in ("0", "false", "no"):
        print("[START] OpenSearch autostart deshabilitado por VANT_OS_SERVICE_AUTOSTART.")
        return
    if not is_autostart_enabled():
        print("[START] OpenSearch autostart deshabilitado por manage.py disable_opensearch.")
        return

    host = os.getenv("OS_SERVICE_HOST", "192.168.1.12")
    port = int(os.getenv("OS_SERVICE_PORT", "9201"))
    if _is_port_open(host, port):
        print(f"[START] OpenSearch service ya esta activo en {host}:{port}.")
        return

    service_path = _project_root() / "opensearch_service" / "service" / "app.py"
    if not service_path.exists():
        print(f"[WARN] OpenSearch service app not found: {service_path}")
        return

    logs_dir = _project_root() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = (logs_dir / "opensearch-service.log").open("a", encoding="utf-8")
    stderr_log = (logs_dir / "opensearch-service.err").open("a", encoding="utf-8")

    subprocess.Popen(
        [sys.executable, str(service_path)],
        stdout=stdout_log,
        stderr=stderr_log,
        cwd=str(service_path.parent),
        env=os.environ.copy(),
    )
    _SERVICE_STARTED = True
    print(f"[START] OpenSearch service iniciado en {host}:{port}.")
