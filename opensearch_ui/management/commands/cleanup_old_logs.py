"""
Comando para limpiar logs antiguos basado en la configuración de retención
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
from opensearch_ui.models import (
    IDSIngestConfig, SuricataEveAlert, SuricataFlow, SuricataStats, 
    SuricataSystemLog, SuricataLog, SnortLog
)
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Limpiar logs antiguos basado en la configuración de retención'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Mostrar qué se haría sin ejecutar cambios',
        )
        parser.add_argument(
            '--days',
            type=int,
            help='Días de retención (sobrescribe configuración)',
        )
        parser.add_argument(
            '--model',
            type=str,
            help='Modelo específico a limpiar (opcional)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        retention_days = options.get('days')
        specific_model = options.get('model')
        
        if dry_run:
            self.stdout.write(self.style.WARNING('MODO DRY-RUN: No se realizarán cambios'))
        
        # Obtener configuración de retención
        if retention_days:
            self.stdout.write(f'📅 Usando {retention_days} días de retención (especificado)')
        else:
            configs = IDSIngestConfig.objects.filter(active=True)
            if configs.exists():
                retention_days = configs.first().retention_days
                self.stdout.write(f'📅 Usando {retention_days} días de retención (configuración)')
            else:
                retention_days = 30  # Default
                self.stdout.write(f'📅 Usando {retention_days} días de retención (default)')
        
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        self.stdout.write(f'🗓️ Eliminando logs anteriores a: {cutoff_date.strftime("%Y-%m-%d %H:%M:%S")}')
        
        models_to_clean = [
            ('SuricataEveAlert', SuricataEveAlert),
            ('SuricataFlow', SuricataFlow),
            ('SuricataStats', SuricataStats),
            ('SuricataSystemLog', SuricataSystemLog),
            ('SuricataLog', SuricataLog),
            ('SnortLog', SnortLog),
        ]
        
        if specific_model:
            models_to_clean = [(name, model) for name, model in models_to_clean 
                             if name.lower() == specific_model.lower()]
            if not models_to_clean:
                self.stdout.write(self.style.ERROR(f'Modelo {specific_model} no encontrado'))
                return
        
        total_records_removed = 0
        
        for model_name, model_class in models_to_clean:
            self.stdout.write(f'\n🔄 Limpiando {model_name}...')
            
            # Contar registros a eliminar
            old_records = model_class.objects.filter(timestamp__lt=cutoff_date)
            count_to_delete = old_records.count()
            
            if count_to_delete == 0:
                self.stdout.write(f'✅ {model_name}: No hay registros antiguos para eliminar')
                continue
            
            self.stdout.write(f'📊 {model_name}: {count_to_delete} registros antiguos encontrados')
            
            if not dry_run:
                # Eliminar en lotes para evitar problemas de memoria
                batch_size = 1000
                deleted_count = 0
                
                while True:
                    with transaction.atomic():
                        batch = old_records[:batch_size]
                        if not batch:
                            break
                        
                        batch_ids = [record.id for record in batch]
                        deleted_batch = model_class.objects.filter(id__in=batch_ids).delete()
                        deleted_count += deleted_batch[0]
                        
                        self.stdout.write(f'✅ {model_name}: {deleted_count} registros eliminados')
                
                self.stdout.write(f'🎉 {model_name}: {deleted_count} registros eliminados')
                total_records_removed += deleted_count
            else:
                self.stdout.write(f'🔍 {model_name}: Se eliminarían {count_to_delete} registros')
                total_records_removed += count_to_delete
        
        if dry_run:
            self.stdout.write(self.style.SUCCESS(f'\n✅ DRY-RUN completado. Se eliminarían {total_records_removed} registros antiguos.'))
        else:
            self.stdout.write(self.style.SUCCESS(f'\n🎉 Limpieza completada! {total_records_removed} registros antiguos eliminados.'))
            
            # Actualizar estadísticas de configuración
            for config in IDSIngestConfig.objects.filter(active=True):
                config.last_run = timezone.now()
                config.save()

