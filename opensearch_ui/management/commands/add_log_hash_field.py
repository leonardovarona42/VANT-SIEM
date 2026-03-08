"""
Comando para agregar el campo log_hash a los modelos existentes
y generar hashes para los registros existentes
"""
from django.core.management.base import BaseCommand
from django.db import transaction
from opensearch_ui.models import (
    SuricataEveAlert, SuricataFlow, SuricataStats, 
    SuricataSystemLog, SuricataLog, SnortLog
)
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Agregar campo log_hash a modelos existentes y generar hashes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Mostrar qué se haría sin ejecutar cambios',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('MODO DRY-RUN: No se realizarán cambios'))
        
        models_to_update = [
            ('SuricataEveAlert', SuricataEveAlert),
            ('SuricataFlow', SuricataFlow),
            ('SuricataStats', SuricataStats),
            ('SuricataSystemLog', SuricataSystemLog),
            ('SuricataLog', SuricataLog),
            ('SnortLog', SnortLog),
        ]
        
        for model_name, model_class in models_to_update:
            self.stdout.write(f'\n🔄 Procesando {model_name}...')
            
            # Contar registros sin hash
            records_without_hash = model_class.objects.filter(log_hash__isnull=True).count()
            
            if records_without_hash == 0:
                self.stdout.write(f'✅ {model_name}: Todos los registros ya tienen hash')
                continue
            
            self.stdout.write(f'📊 {model_name}: {records_without_hash} registros sin hash')
            
            if not dry_run:
                # Procesar en lotes para evitar problemas de memoria
                batch_size = 1000
                processed = 0
                
                while True:
                    with transaction.atomic():
                        batch = model_class.objects.filter(
                            log_hash__isnull=True
                        )[:batch_size]
                        
                        if not batch:
                            break
                        
                        for record in batch:
                            try:
                                record.log_hash = record.generate_hash()
                                record.save(update_fields=['log_hash'])
                                processed += 1
                            except Exception as e:
                                logger.error(f"Error generando hash para {model_name} ID {record.id}: {e}")
                                continue
                        
                        self.stdout.write(f'✅ {model_name}: {processed} registros procesados')
                
                self.stdout.write(f'🎉 {model_name}: Completado - {processed} registros actualizados')
            else:
                self.stdout.write(f'🔍 {model_name}: Se procesarían {records_without_hash} registros')
        
        if dry_run:
            self.stdout.write(self.style.SUCCESS('\n✅ DRY-RUN completado. Ejecuta sin --dry-run para aplicar cambios.'))
        else:
            self.stdout.write(self.style.SUCCESS('\n🎉 Proceso completado exitosamente!'))

