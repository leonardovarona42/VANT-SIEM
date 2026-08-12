from django.core.management.base import BaseCommand

from soar_app.models import CriticalPort, ThreatPort
from soar_app.services import DEFAULT_CRITICAL_PORTS, DEFAULT_TROJAN_PORTS


class Command(BaseCommand):
    help = "Carga los puertos críticos y de trojan/C2 por defecto (idempotente)"

    def handle(self, *args, **opts):
        created_c = 0
        for port, name in DEFAULT_CRITICAL_PORTS.items():
            _, was_created = CriticalPort.objects.get_or_create(
                port=port, defaults={"service_name": name, "severity": "critical"}
            )
            created_c += int(was_created)
        created_t = 0
        for port, name in DEFAULT_TROJAN_PORTS.items():
            _, was_created = ThreatPort.objects.get_or_create(
                port=port, defaults={"name": name, "severity": "high"}
            )
            created_t += int(was_created)
        self.stdout.write(self.style.SUCCESS(
            f"Puertos críticos: {CriticalPort.objects.count()} ({created_c} nuevos); "
            f"trojan/C2: {ThreatPort.objects.count()} ({created_t} nuevos)"
        ))
