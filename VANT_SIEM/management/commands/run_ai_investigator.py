from django.core.management.base import BaseCommand
from IRIS.ai_incident_investigator import AIIncidentInvestigator
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Ejecutar sistema de IA para investigación automática de incidentes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Horas hacia atrás para analizar logs (default: 24)'
        )
        parser.add_argument(
            '--train-only',
            action='store_true',
            help='Solo entrenar modelos, no analizar logs'
        )
        parser.add_argument(
            '--feedback',
            nargs=3,
            metavar=('INCIDENT_ID', 'IS_FALSE_POSITIVE', 'CORRECT_CLASSIFICATION'),
            help='Incorporar feedback humano: ID_INCIDENTE TRUE/FALSE "CLASIFICACION_CORRECTA"'
        )

    def handle(self, *args, **options):
        investigator = AIIncidentInvestigator()

        if options['feedback']:
            # Procesar feedback humano
            incident_id, is_fp, correct_class = options['feedback']
            is_false_positive = is_fp.lower() == 'true'
            correct_classification = correct_class if correct_class != 'None' else None

            self.stdout.write(f"Incorporando feedback para incidente {incident_id}...")
            investigator.incorporate_human_feedback(
                int(incident_id),
                is_false_positive,
                correct_classification
            )
            self.stdout.write(self.style.SUCCESS("Feedback incorporado exitosamente"))

        elif options['train_only']:
            # Solo entrenar modelos
            self.stdout.write("Entrenando modelos de IA...")
            investigator.train_models()
            self.stdout.write(self.style.SUCCESS("Modelos entrenados exitosamente"))

        else:
            # Análisis completo
            hours_back = options['hours']
            self.stdout.write(f"Analizando logs de las últimas {hours_back} horas...")

            incidents_created = investigator.analyze_recent_logs(hours_back)

            self.stdout.write(self.style.SUCCESS(
                f"Análisis completado. Incidentes creados: {incidents_created}"
            ))

            # Mostrar reporte de rendimiento
            self.stdout.write("\n" + investigator.get_performance_report())

            # Mostrar incidentes recientes creados por IA
            from EVENT_M.models import Incidente
            from django.utils import timezone
            from datetime import timedelta

            recent_ai_incidents = Incidente.objects.filter(
                reporte__nombre_informante='Sistema de IA Automático',
                fecha_hora__gte=timezone.now() - timedelta(hours=hours_back)
            )

            if recent_ai_incidents:
                self.stdout.write(f"\nIncidentes creados por IA en las últimas {hours_back} horas:")
                for inc in recent_ai_incidents:
                    self.stdout.write(f"  • {inc.id}: {inc.nombre_incidente}")
                    self.stdout.write(f"    Estado: {inc.estado_solucion}")
                    self.stdout.write(f"    Creado: {inc.fecha_hora}")
                    medidas_count = inc.medidaincidente_set.count()
                    self.stdout.write(f"    Medidas aplicadas: {medidas_count}\n")