import logging
import time

from django.core.management.base import BaseCommand
from django.utils import timezone

from soar_app.models import get_or_create_config
from soar_app import services

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Consumidor de eventos -> features -> predicciones -> acciones (bucle continuo)"

    def add_arguments(self, parser):
        parser.add_argument("--poll", type=int, default=5, help="Segundos entre polls")
        parser.add_argument("--batch", type=int, default=500, help="Eventos por lote")
        parser.add_argument(
            "--simulate",
            action="store_true",
            help="Generar tráfico sintético si no hay eventos reales (pruebas)",
        )

    def handle(self, *args, **opts):
        cfg = get_or_create_config()
        self.stdout.write(f"[soar] Worker iniciado. Modo: {cfg.get_prediction_mode_display()}")
        cursor = cfg.last_cursor

        while True:
            try:
                cfg.refresh_from_db()
                if not cfg.enabled:
                    time.sleep(opts["poll"])
                    continue

                events = list(services.iter_events_since(cursor, limit=opts["batch"]))
                if not events and opts["simulate"]:
                    self.stdout.write("[soar] Sin eventos reales, simulando trafico...")
                    events = services.simulate_traffic(duration_seconds=2, interval=0.05)
                if events:
                    preds = services.analyze_and_act(
                        events, cfg, source_event_ids=[e["id"] for e in events]
                    )
                    last_id = events[-1]["id"]
                    cursor = last_id
                    cfg.events_processed += len(events)
                    cfg.predictions_made += len(preds)
                    cfg.last_cursor = cursor
                    cfg.last_run_at = timezone.now()
                    cfg.save()
                    self.stdout.write(
                        f"[soar] {len(events)} eventos, {len(preds)} predicciones, cursor={cursor}"
                    )
                else:
                    self.stdout.write("[soar] Sin eventos nuevos...")
            except KeyboardInterrupt:
                self.stdout.write("[soar] Detenido por el usuario")
                break
            except Exception as exc:
                logger.exception("Error en ciclo worker: %s", exc)
            time.sleep(opts["poll"])
