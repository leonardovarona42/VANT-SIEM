from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from opensearch_ui.models import IDSIngestConfig
from opensearch_ui.services import ingest_service
import time
import logging
import threading
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Iniciar servicio de ingesta automática de logs IDS/IPS'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=60,
            help='Intervalo en segundos entre ejecuciones (default: 60)'
        )
        parser.add_argument(
            '--config-id',
            type=int,
            help='Procesar solo una configuración específica'
        )
        parser.add_argument(
            '--daemon',
            action='store_true',
            help='Ejecutar como daemon (modo continuo)'
        )

    def handle(self, *args, **options):
        interval = options.get('interval', 60)
        config_id = options.get('config_id')
        daemon_mode = options.get('daemon', False)
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Iniciando servicio de ingesta IDS/IPS (intervalo: {interval}s)'
            )
        )
        
        if daemon_mode:
            self.run_daemon(interval, config_id)
        else:
            self.run_single_execution(config_id)

    def run_daemon(self, interval, config_id):
        """Ejecutar como daemon continuo usando el servicio optimizado"""
        self.stdout.write(
            self.style.WARNING(
                'Modo daemon activado. Presiona Ctrl+C para detener.'
            )
        )
        
        try:
            # Usar el servicio optimizado
            success = ingest_service.start(interval)
            if success:
                self.stdout.write(
                    self.style.SUCCESS('Servicio de ingesta iniciado correctamente')
                )
                
                # Mantener el proceso vivo
                while ingest_service.running:
                    time.sleep(1)
            else:
                self.stdout.write(
                    self.style.ERROR('No se pudo iniciar el servicio de ingesta')
                )
        except KeyboardInterrupt:
            self.stdout.write(
                self.style.SUCCESS('Deteniendo servicio de ingesta...')
            )
            ingest_service.stop()
            self.stdout.write(
                self.style.SUCCESS('Servicio de ingesta detenido correctamente')
            )

    def run_single_execution(self, config_id):
        """Ejecutar una sola vez usando el servicio optimizado"""
        try:
            # Obtener configuraciones activas
            configs = IDSIngestConfig.objects.filter(active=True)
            if config_id:
                configs = configs.filter(id=config_id)
            
            if not configs.exists():
                self.stdout.write(
                    self.style.WARNING('No hay configuraciones activas')
                )
                return
            
            # Ejecutar ingesta para cada configuración usando el servicio
            for config in configs:
                self.stdout.write(f'Procesando configuración: {config}')
                
                try:
                    # Usar el servicio optimizado para procesamiento individual
                    ingest_service._process_config(config)
                    
                    self.stdout.write(
                        self.style.SUCCESS(
                            f'{config.ids_type.upper()} - Configuración procesada exitosamente'
                        )
                    )
                    
                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(f'Error en {config.ids_type.upper()}: {e}')
                    )
                    logger.error(f'Error procesando configuración {config.id}: {e}')
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error general: {e}')
            )
            logger.error(f'Error en servicio de ingesta: {e}')

    def process_config(self, config: IDSIngestConfig, force_full: bool, dry_run: bool, batch_size: int) -> tuple:
        """Procesar una configuración específica"""
        from django.core.management import call_command
        
        try:
            if config.ids_type == 'suricata':
                call_command('ingest_suricata_logs', log_dir=config.log_path, verbosity=0)
            elif config.ids_type == 'snort':
                call_command('ingest_snort_logs', log_dir=config.log_path, verbosity=0)
            else:
                logger.error(f'Tipo de IDS no soportado: {config.ids_type}')
                return (0, 1)
            return (1, 0)  # (processed, errors)
        except Exception as e:
            logger.error(f'Error procesando configuración {config.id}: {e}')
            return (0, 1)

