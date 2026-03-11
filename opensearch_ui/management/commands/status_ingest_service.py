from django.core.management.base import BaseCommand
from opensearch_ui.services import ingest_service
from opensearch_ui.models import IDSIngestConfig
from django.utils import timezone
from datetime import timedelta
import json

class Command(BaseCommand):
    help = 'Verificar estado del servicio de ingesta automática'

    def handle(self, *args, **options):
        try:
            # Obtener estado del servicio
            status = ingest_service.get_status()
            
            # Obtener estadísticas adicionales
            configs = IDSIngestConfig.objects.all()
            active_configs = configs.filter(active=True)
            
            # Logs recientes
            from opensearch_ui.models import SuricataEveAlert, SnortLog
            recent_suricata = SuricataEveAlert.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count()
            
            recent_snort = SnortLog.objects.filter(
                timestamp__gte=timezone.now() - timedelta(hours=24)
            ).count()
            
            # Mostrar estado
            self.stdout.write(
                self.style.SUCCESS('📊 Estado del Servicio de Ingesta IDS/IPS')
            )
            self.stdout.write('=' * 50)
            
            # Estado del servicio
            if status['running']:
                self.stdout.write(
                    self.style.SUCCESS('🟢 Servicio: ACTIVO')
                )
            else:
                self.stdout.write(
                    self.style.ERROR('🔴 Servicio: INACTIVO')
                )
            
            # Hilos activos
            self.stdout.write(f'🧵 Hilos activos: {status["active_threads"]}/{status["total_threads"]}')
            
            # Estadísticas del servicio
            stats = status['stats']
            self.stdout.write(f'📈 Eventos procesados: {stats["total_processed"]}')
            self.stdout.write(f'❌ Errores: {stats["total_errors"]}')
            self.stdout.write(f'⚙️  Configuraciones activas: {stats["active_configs"]}')
            
            if stats['last_run']:
                self.stdout.write(f'🕐 Última ejecución: {stats["last_run"]}')
            else:
                self.stdout.write('🕐 Última ejecución: Nunca')
            
            # Configuraciones
            self.stdout.write('\n📋 Configuraciones:')
            for config in active_configs:
                status_icon = '🟢' if config.active else '🔴'
                last_run = config.last_run.strftime('%d/%m/%Y %H:%M') if config.last_run else 'Nunca'
                self.stdout.write(f'  {status_icon} {config.ids_type.upper()}: {config.log_path} (Última: {last_run})')
            
            # Logs recientes
            self.stdout.write(f'\n📊 Logs recientes (24h):')
            self.stdout.write(f'  Suricata: {recent_suricata}')
            self.stdout.write(f'  Snort: {recent_snort}')
            self.stdout.write(f'  Total: {recent_suricata + recent_snort}')
            
            # Colas
            if status['queues']:
                self.stdout.write(f'\n📦 Estado de colas:')
                for config_id, queue_size in status['queues'].items():
                    self.stdout.write(f'  Config {config_id}: {queue_size} elementos')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'❌ Error obteniendo estado: {e}')
            )
