import json
import logging

from django.core.management.base import BaseCommand

from vant_common.bus import EventBus

from soc_app.models import Reporte

logger = logging.getLogger(__name__)

SOAR_INFORMANTE = "SOAR Automatico"
SOAR_AREA = "Seguridad (SOAR)"


class Command(BaseCommand):
    help = (
        "Consume el stream 'threats' del bus y crea reportes automaticos "
        "cuando el servicio SOAR publica una prediccion (modo automatico)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--group", default="vant-soc-soar", help="Consumer group de Redis Stream"
        )
        parser.add_argument(
            "--consumer", default="vant-soc-soar-consumer", help="Nombre del consumidor"
        )

    def _on_event(self, fields):
        try:
            event_type = fields.get("event_type")
            if event_type not in ("soar_prediction", "soar_suggestion"):
                return
            data = fields.get("data")
            if isinstance(data, str):
                data = json.loads(data)
            if not isinstance(data, dict):
                return
            risk = data.get("risk") or "unknown"
            if risk not in ("high", "critical"):
                return
            descripcion = data.get("descripcion") or (
                f"[SOAR] Deteccion automatica - IP {data.get('ip')}\n"
                f"Score: {data.get('score')} | Riesgo: {risk}\n"
                f"Decision: {data.get('decision')}"
            )
            reporte = Reporte.objects.create(
                nombre_informante=SOAR_INFORMANTE,
                email_informante="",
                descripcion=descripcion,
                estado_solucion="nuevo",
            )
            logger.info(
                "Reporte SOAR #%s creado para IP %s (riesgo %s)",
                reporte.pk, data.get("ip"), risk,
            )
        except Exception:
            logger.exception("Fallo al crear reporte SOAR desde el bus")

    def handle(self, *args, **opts):
        self.stdout.write("[vant-soc] Consumidor SOAR iniciado (stream threats)...")
        bus = EventBus("vant-soc")
        bus.subscribe(
            "threats",
            self._on_event,
            group=opts["group"],
            consumer=opts["consumer"],
        )
