#!/usr/bin/env python3
"""
Comando de Django para ejecutar análisis automático de IA cada intervalo configurado
"""
import logging
import time
from django.core.management.base import BaseCommand
from django.utils import timezone
from IRIS.ai_incident_investigator import AIIncidentInvestigator
from IRIS.models import AIConfiguration, AIAnalysisLog

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Ejecuta análisis automático de IA según la configuración del sistema'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=300,  # 5 minutos por defecto
            help='Intervalo en segundos entre análisis (default: 300)',
        )
        parser.add_argument(
            '--once',
            action='store_true',
            help='Ejecutar solo una vez y salir',
        )

    def handle(self, *args, **options):
        interval = options['interval']
        once = options['once']

        self.stdout.write(
            self.style.SUCCESS(f'Iniciando análisis automático de IA - Intervalo: {interval}s')
        )

        if once:
            self.run_analysis()
            return

        # Bucle principal para análisis periódico
        while True:
            try:
                self.run_analysis()
                self.stdout.write(
                    self.style.SUCCESS(f'Esperando {interval} segundos para próximo análisis...')
                )
                time.sleep(interval)
            except KeyboardInterrupt:
                self.stdout.write(
                    self.style.WARNING('Análisis automático detenido por el usuario')
                )
                break
            except Exception as e:
                logger.error(f'Error en análisis automático: {str(e)}')
                self.stdout.write(
                    self.style.ERROR(f'Error en análisis automático: {str(e)}')
                )
                time.sleep(interval)  # Esperar antes de reintentar

    def run_analysis(self):
        """Ejecuta un ciclo de análisis de IA"""
        try:
            # Verificar configuración
            config = AIConfiguration.objects.first()
            if not config:
                config = AIConfiguration.objects.create()
                self.stdout.write(
                    self.style.WARNING('Configuración creada por defecto')
                )

            if not config.auto_analysis_enabled:
                self.stdout.write(
                    self.style.WARNING('Análisis automático desactivado en configuración')
                )
                return

            # Ejecutar análisis
            investigator = AIIncidentInvestigator()
            predictions_created, incidents_created = investigator.analyze_recent_logs(
                hours_back=config.analysis_interval_hours
            )

            # Log del análisis
            AIAnalysisLog.objects.create(
                analysis_type='auto_analysis',
                start_time=timezone.now() - timezone.timedelta(hours=config.analysis_interval_hours),
                end_time=timezone.now(),
                incidents_created=incidents_created,
                success=True
            )

            self.stdout.write(
                self.style.SUCCESS(
                    f'Análisis completado: {predictions_created} predicciones, '
                    f'{incidents_created} incidentes - {timezone.now()}'
                )
            )

        except Exception as e:
            logger.error(f'Error ejecutando análisis automático: {str(e)}')

            # Log del error
            AIAnalysisLog.objects.create(
                analysis_type='auto_analysis',
                start_time=timezone.now(),
                end_time=timezone.now(),
                success=False,
                error_message=str(e)
            )

            self.stdout.write(
                self.style.ERROR(f'Error en análisis automático: {str(e)}')
            )