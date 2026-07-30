import os
import subprocess
import platform
import logging

import requests as http_requests
from django.core.management.base import BaseCommand
from django.utils import timezone

from soc_app.models import Servicio

logger = logging.getLogger("vant_soc.check_icmp")

TIMEOUT = 3
COUNT = 2
SERVICE_SECRET = os.getenv("SERVICE_SECRET", "changeme-service-secret")
BUS_URL = "http://127.0.0.1:8600/api/events/receive/"


class Command(BaseCommand):
    help = "ICMP ping check for monitored services"

    def handle(self, *args, **options):
        services = Servicio.objects.filter(
            monitorear=True,
            protocolo_monitoreo="icmp",
            host__isnull=False,
        )

        if not services.exists():
            self.stdout.write("No services to monitor")
            return

        up_count = 0
        down_count = 0

        for svc in services:
            ip = str(svc.host)
            alive = self._ping(ip)

            new_state = "up" if alive else "down"
            old_state = svc.estado_monitoreo

            if old_state != new_state:
                svc.estado_monitoreo = new_state
                svc.save(update_fields=["estado_monitoreo"])
                self.stdout.write(f"  {svc.nombre}: {old_state} -> {new_state}")
                self._publish_event(svc, old_state, new_state)

            if alive:
                up_count += 1
            else:
                down_count += 1

        total = services.count()
        monitored = total
        disponibilidad = round((up_count / monitored) * 100, 1) if monitored else 0

        self.stdout.write(
            f"Checked {total} services: {up_count} up, {down_count} down, "
            f"disponibilidad {disponibilidad}%"
        )

    def _publish_event(self, svc, old_state, new_state):
        event_type = "servicio_up" if new_state == "up" else "servicio_down"
        severity = "info" if new_state == "up" else "high"
        payload = {
            "servicio_id": svc.id,
            "nombre": svc.nombre,
            "host": str(svc.host),
            "tipo": svc.tipo,
            "estado": new_state,
            "estado_anterior": old_state or "desconocido",
        }
        body = {
            "event_type": event_type,
            "source_service": "icmp_monitor",
            "entity_type": "servicio",
            "entity_id": str(svc.id),
            "actor_user_id": "",
            "actor_username": "icmp_monitor",
            "payload": payload,
            "severity": severity,
        }
        try:
            http_requests.post(
                BUS_URL,
                json=body,
                headers={"X-Service-Secret": SERVICE_SECRET},
                timeout=5,
            )
        except Exception as e:
            logger.warning("Failed to publish %s for %s: %s", event_type, svc.nombre, e)

    @staticmethod
    def _ping(host):
        param = "-n" if platform.system().lower() == "windows" else "-c"
        try:
            result = subprocess.run(
                ["ping", param, str(COUNT), "-W", str(TIMEOUT), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=TIMEOUT * COUNT + 5,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
