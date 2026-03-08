"""
Comando para rotar/truncar archivos de log de IDS/IPS después de la ingesta
Este comando elimina el contenido ya ingerido de los archivos de log originales
"""
import os
import shutil
import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from opensearch_ui.models import IDSIngestConfig

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Rota/trunca archivos de log de IDS/IPS eliminando contenido ya ingerido'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Mostrar qué se haría sin ejecutar la rotación'
        )
        parser.add_argument(
            '--backup',
            action='store_true',
            help='Crear backup de los archivos antes de rotar'
        )
        parser.add_argument(
            '--hours',
            type=int,
            default=5,
            help='Horas de retención antes de rotar (default: 5)'
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        create_backup = options['backup']
        retention_hours = options['hours']
        
        action = "simulando" if dry_run else "ejecutando"
        self.stdout.write(
            self.style.SUCCESS(f'Iniciando rotación de logs de IDS/IPS ({action})...')
        )
        
        # Obtener configuraciones activas de IDS/IPS
        configs = IDSIngestConfig.objects.filter(active=True)
        
        if not configs.exists():
            self.stdout.write(
                self.style.WARNING('No se encontraron configuraciones activas de IDS/IPS')
            )
            return
        
        total_rotated = 0
        
        for config in configs:
            self.stdout.write(f'\nProcesando configuración: {config.ids_type.upper()}')
            self.stdout.write(f'Ruta de logs: {config.log_path}')
            
            if not os.path.exists(config.log_path):
                self.stdout.write(
                    self.style.WARNING(f'  ⚠️ Ruta no existe: {config.log_path}')
                )
                continue
            
            # Verificar si es hora de rotar (basado en última ejecución)
            if config.last_run:
                time_since_last_run = timezone.now() - config.last_run
                if time_since_last_run < timedelta(hours=retention_hours):
                    self.stdout.write(
                        f'  ⏰ No es tiempo de rotar (última ejecución: {time_since_last_run} atrás)'
                    )
                    continue
            
            # Rotar archivos de log según el tipo
            rotated_count = self._rotate_log_files(
                config.log_path, 
                config.ids_type,
                create_backup, 
                dry_run
            )
            total_rotated += rotated_count
            
            if not dry_run and rotated_count > 0:
                # Actualizar posición de lectura a 0 para empezar desde el principio
                config.last_position = 0
                config.save()
                self.stdout.write(
                    self.style.SUCCESS(f'  ✅ Posición de lectura reiniciada')
                )
        
        if dry_run:
            self.stdout.write(
                self.style.SUCCESS(f'\nSimulación completada. Se rotarían {total_rotated} archivos.')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f'\nRotación completada. {total_rotated} archivos rotados.')
            )

    def _rotate_log_files(self, log_dir, ids_type, create_backup, dry_run):
        """Rotar archivos de log en un directorio según el tipo de IDS/IPS"""
        rotated_count = 0
        
        # Archivos de log según el tipo de IDS/IPS
        if ids_type == 'suricata':
            log_files = [
                'eve.json',
                'fast.log', 
                'stats.log',
                'suricata.log'
            ]
        elif ids_type == 'snort':
            log_files = [
                'alert.full',
                'alert.fast',
                'alerts.csv'
            ]
        else:
            self.stdout.write(f'    ⚠️ Tipo de IDS/IPS no soportado: {ids_type}')
            return 0
        
        for log_file in log_files:
            file_path = os.path.join(log_dir, log_file)
            
            if not os.path.exists(file_path):
                continue
            
            try:
                # Obtener información del archivo
                file_size = os.path.getsize(file_path)
                file_mtime = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                self.stdout.write(f'  📄 {log_file}: {file_size} bytes, modificado: {file_mtime}')
                
                if file_size == 0:
                    self.stdout.write(f'    ⏭️ Archivo vacío, saltando')
                    continue
                
                if dry_run:
                    self.stdout.write(f'    🔄 [DRY RUN] Se rotaría {log_file}')
                    rotated_count += 1
                    continue
                
                # Crear backup si se solicita
                if create_backup:
                    backup_path = f"{file_path}.backup.{timezone.now().strftime('%Y%m%d_%H%M%S')}"
                    shutil.copy2(file_path, backup_path)
                    self.stdout.write(f'    💾 Backup creado: {os.path.basename(backup_path)}')
                
                # Truncar el archivo (eliminar contenido)
                with open(file_path, 'w') as f:
                    f.truncate(0)
                
                self.stdout.write(f'    ✅ {log_file} rotado (contenido eliminado)')
                rotated_count += 1
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'    ❌ Error rotando {log_file}: {e}')
                )
        
        return rotated_count

