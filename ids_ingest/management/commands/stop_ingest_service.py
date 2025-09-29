from django.core.management.base import BaseCommand
from ids_ingest.services import ingest_service
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Detener servicio de ingesta automática de logs IDS/IPS'

    def handle(self, *args, **options):
        try:
            if not ingest_service.running:
                self.stdout.write(
                    self.style.WARNING('⚠️  El servicio de ingesta no está ejecutándose')
                )
                return
            
            # Detener el servicio
            ingest_service.stop()
            
            self.stdout.write(
                self.style.SUCCESS('✅ Servicio de ingesta detenido correctamente')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error deteniendo servicio: {e}')
            )
            logger.error(f'Error deteniendo servicio de ingesta: {e}')