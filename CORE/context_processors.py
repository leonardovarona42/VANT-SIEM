import logging
from django.db import connections, DEFAULT_DB_ALIAS

logger = logging.getLogger(__name__)


def _db_connected(alias):
    try:
        conn = connections[alias]
        conn.ensure_connection()
        return conn.is_usable()
    except Exception:
        return False


def service_health(request):
    return {
        'aegis_service_healthy': _db_connected('vant_dlp'),
        'inventory_service_healthy': _db_connected('vant_inventory'),
        'logs_service_healthy': _db_connected('vant_logs'),
    }
