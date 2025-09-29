"""
Comando para limpiar logs duplicados basado en el campo log_hash
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from ids_ingest.models import (
    SuricataEveAlert, SuricataFlow, SuricataStats, 
    SuricataSystemLog, SuricataLog, SnortLog
)
from django.db.models import Count
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Limpiar logs duplicados basado en el campo log_hash'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Mostrar qué se haría sin ejecutar cambios',
        )
        parser.add_argument(
            '--model',
            type=str,
            help='Modelo específico a limpiar (opcional)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        specific_model = options.get('model')
        
        if dry_run:
            self.stdout.write(self.style.WARNING('MODO DRY-RUN: No se realizarán cambios'))
        
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
        
        total_duplicates_removed = 0
        
        for model_name, model_class in models_to_clean:
            self.stdout.write(f'\n🔄 Limpiando duplicados en {model_name}...')
            
            # Encontrar hashes duplicados
            duplicate_hashes = model_class.objects.values('log_hash').annotate(
                count=Count('log_hash')
            ).filter(count__gt=1)
            
            if not duplicate_hashes:
                self.stdout.write(f'✅ {model_name}: No se encontraron duplicados')
                continue
            
            duplicates_count = sum(hash_info['count'] - 1 for hash_info in duplicate_hashes)
            self.stdout.write(f'📊 {model_name}: {duplicates_count} registros duplicados encontrados')
            
            if not dry_run:
                removed_count = 0
                
                for hash_info in duplicate_hashes:
                    log_hash = hash_info['log_hash']
                    if not log_hash:  # Skip null hashes
                        continue
                    
                    # Obtener todos los registros con este hash
                    duplicate_records = model_class.objects.filter(log_hash=log_hash).order_by('created_at')
                    
                    # Mantener el más antiguo, eliminar el resto
                    records_to_delete = duplicate_records[1:]
                    
                    for record in records_to_delete:
                        record.delete()
                        removed_count += 1
                
                self.stdout.write(f'✅ {model_name}: {removed_count} duplicados eliminados')
                total_duplicates_removed += removed_count
            else:
                self.stdout.write(f'🔍 {model_name}: Se eliminarían {duplicates_count} duplicados')
                total_duplicates_removed += duplicates_count
        
        if dry_run:
            self.stdout.write(self.style.SUCCESS(f'\n✅ DRY-RUN completado. Se eliminarían {total_duplicates_removed} registros duplicados.'))
        else:
            self.stdout.write(self.style.SUCCESS(f'\n🎉 Limpieza completada! {total_duplicates_removed} duplicados eliminados.'))
