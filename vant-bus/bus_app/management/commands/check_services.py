import json
import logging
import time

import requests
from django.core.management.base import BaseCommand
from django.utils import timezone

from bus_app.event_bus import get_event_bus
from bus_app.models import ServiceConfig, ServiceHealthLog, SystemEvent

logger = logging.getLogger("bus_app.health_check")


class Command(BaseCommand):
    help = "Check health of all registered services and publish events on status changes"

    def handle(self, *args, **options):
        services = ServiceConfig.objects.filter(is_active=True)
        if not services.exists():
            self.stdout.write("No services registered")
            return

        up_count = 0
        down_count = 0
        events_created = 0

        for svc in services:
            url = f"http://{svc.host}:{svc.port}{svc.health_endpoint}"
            start = time.monotonic()
            status_str = "down"
            response_time = None
            details = {}

            try:
                resp = requests.get(url, timeout=5)
                response_time = int((time.monotonic() - start) * 1000)
                if resp.status_code == 200:
                    status_str = "healthy"
                    try:
                        details = resp.json()
                    except Exception:
                        details = {"raw": resp.text[:500]}
                else:
                    status_str = "degraded"
                    details = {"status_code": resp.status_code}
            except requests.ConnectionError:
                details = {"error": "connection_refused"}
            except requests.Timeout:
                details = {"error": "timeout"}
            except Exception as e:
                details = {"error": str(e)[:200]}

            old_status = svc.last_health_status
            svc.last_health_check = timezone.now()
            svc.last_health_status = status_str

            if status_str == "down":
                svc.consecutive_failures += 1
                down_count += 1
            else:
                svc.consecutive_failures = 0
                if status_str == "healthy":
                    up_count += 1

            svc.save(update_fields=["last_health_check", "last_health_status", "consecutive_failures"])

            ServiceHealthLog.objects.create(
                service=svc,
                status=status_str,
                response_time_ms=response_time,
                details=details,
            )

            if old_status in ("healthy", "unknown") and status_str == "down":
                event = SystemEvent.objects.create(
                    event_type="servicio_down",
                    source_service="bus",
                    entity_type="servicio",
                    entity_id=str(svc.id),
                    payload={
                        "service": svc.name,
                        "display_name": svc.display_name,
                        "host": svc.host,
                        "port": svc.port,
                        "consecutive_failures": svc.consecutive_failures,
                        "details": details,
                    },
                    severity="critical" if svc.is_critical else "high",
                )
                bus = get_event_bus()
                bus.publish_event("events", "servicio_down", {"event_id": event.id, "service": svc.name})
                events_created += 1

            elif old_status == "down" and status_str == "healthy":
                event = SystemEvent.objects.create(
                    event_type="servicio_up",
                    source_service="bus",
                    entity_type="servicio",
                    entity_id=str(svc.id),
                    payload={
                        "service": svc.name,
                        "display_name": svc.display_name,
                        "host": svc.host,
                        "port": svc.port,
                        "response_time_ms": response_time,
                    },
                    severity="info",
                )
                bus = get_event_bus()
                bus.publish_event("events", "servicio_up", {"event_id": event.id, "service": svc.name})
                events_created += 1

        self.stdout.write(
            f"Checked {services.count()} services: {up_count} up, {down_count} down, {events_created} events"
        )
