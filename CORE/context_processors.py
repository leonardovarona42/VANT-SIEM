import requests
import logging

logger = logging.getLogger(__name__)

def service_health(request):
    services = {
        'logs_service': {'url': 'http://localhost:9201/logs/api/health/', 'key': 'logs_service_healthy'},
    }
    context = {}
    for key, config in services.items():
        try:
            resp = requests.get(config['url'], timeout=2)
            context[config['key']] = resp.status_code == 200
        except Exception:
            context[config['key']] = False
    return context
