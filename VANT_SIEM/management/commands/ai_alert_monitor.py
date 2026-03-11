from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from datetime import timedelta
import json
import logging

from VANT_SIEM.ollama_service import ollama_service
from VANT_SIEM.logging_system import event_logger
from opensearch_ui.models import IDSAlert, SnortLog, SuricataEveAlert
from EVENT_M.models import Area, Reporte, Responsable

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Monitorea alertas de Snort y Suricata cada 5 minutos y genera reportes automáticos con IA'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Forzar ejecución incluso si no hay alertas nuevas',
        )

    def handle(self, *args, **options):
        self.stdout.write('🚀 Iniciando monitoreo automático de alertas con IA...')

        try:
            # Verificar si Ollama está disponible
            if not ollama_service.test_connection():
                self.stdout.write(
                    self.style.WARNING('⚠️ Ollama no está disponible. Omitiendo monitoreo automático.')
                )
                return

            # Obtener alertas de los últimos 5 minutos
            five_minutes_ago = timezone.now() - timedelta(minutes=5)

            # Alertas IDS
            recent_ids_alerts = IDSAlert.objects.filter(timestamp__gte=five_minutes_ago)
            critical_alerts = recent_ids_alerts.filter(severity='Critical')

            # Logs Snort
            recent_snort_logs = SnortLog.objects.filter(timestamp__gte=five_minutes_ago)

            # Logs Suricata
            recent_suricata_alerts = SuricataEveAlert.objects.filter(timestamp__gte=five_minutes_ago)

            total_new_alerts = (
                recent_ids_alerts.count() +
                recent_snort_logs.count() +
                recent_suricata_alerts.count()
            )

            if total_new_alerts == 0 and not options['force']:
                self.stdout.write('📊 No hay alertas nuevas en los últimos 5 minutos.')
                return

            self.stdout.write(
                f'📊 Encontradas {total_new_alerts} alertas nuevas en los últimos 5 minutos:'
            )
            self.stdout.write(f'   • IDS Alerts: {recent_ids_alerts.count()}')
            self.stdout.write(f'   • Snort Logs: {recent_snort_logs.count()}')
            self.stdout.write(f'   • Suricata Alerts: {recent_suricata_alerts.count()}')
            self.stdout.write(f'   • Alertas Críticas: {critical_alerts.count()}')

            # Preparar datos para análisis de IA
            alert_data = {
                'ids_alerts': [
                    {
                        'timestamp': alert.timestamp.isoformat(),
                        'severity': alert.severity,
                        'message': alert.message,
                        'src_ip': alert.src_ip,
                        'dst_ip': alert.dest_ip,
                        'protocol': alert.protocol,
                        'src_port': alert.src_port,
                        'dst_port': alert.dst_port,
                    } for alert in recent_ids_alerts.order_by('-timestamp')[:50]
                ],
                'snort_logs': [
                    {
                        'timestamp': log.timestamp.isoformat(),
                        'src_ip': log.src_ip,
                        'dst_ip': log.dst_ip,
                        'protocol': log.protocol,
                        'severity': log.severity,
                        'message': log.message,
                    } for log in recent_snort_logs.order_by('-timestamp')[:50]
                ],
                'suricata_alerts': [
                    {
                        'timestamp': alert.timestamp.isoformat(),
                        'src_ip': alert.src_ip,
                        'dest_ip': alert.dest_ip,
                        'severity': alert.severity,
                        'signature': alert.signature,
                        'category': alert.category,
                    } for alert in recent_suricata_alerts.order_by('-timestamp')[:50]
                ],
                'summary': {
                    'total_alerts': total_new_alerts,
                    'critical_alerts': critical_alerts.count(),
                    'time_period': 'últimos 5 minutos',
                    'generated_at': timezone.now().isoformat(),
                }
            }

            # Generar análisis con IA
            self.stdout.write('🤖 Generando análisis con IA...')

            analysis_prompt = f"""
Analiza las siguientes alertas de seguridad detectadas en los últimos 5 minutos y genera un reporte ejecutivo completo:

DATOS DE ALERTAS:
{json.dumps(alert_data, indent=2, ensure_ascii=False)}

INSTRUCCIONES PARA EL REPORTE:
1. **Resumen Ejecutivo**: Describe la situación general de seguridad
2. **Análisis de Amenazas**: Identifica patrones, IPs sospechosas, tipos de ataques
3. **Alertas Críticas**: Enfócate en las alertas de alta severidad
4. **Tendencias**: Compara con períodos anteriores si es posible
5. **Recomendaciones**: Acciones específicas a tomar
6. **Métricas Clave**: Estadísticas importantes

IMPORTANTE:
- Responde en español
- Sé específico y técnico
- Incluye IPs, puertos y firmas exactas cuando sea relevante
- Prioriza las amenazas más peligrosas
- Proporciona recomendaciones accionables

REPORTE DE ALERTAS - ANÁLISIS IA:
"""

            system_prompt = """Eres un analista de ciberseguridad experto especializado en IDS/IPS.
Tu tarea es analizar alertas de Snort y Suricata para identificar amenazas reales y proporcionar insights valiosos."""

            ai_analysis = ollama_service._call_ollama(analysis_prompt, system_prompt)

            if not ai_analysis or len(ai_analysis.strip()) < 100:
                self.stdout.write(
                    self.style.WARNING('⚠️ No se pudo generar análisis con IA. Usando análisis básico.')
                )
                ai_analysis = self._generate_basic_analysis(alert_data)

            # Crear reporte automático
            with transaction.atomic():
                # Obtener o crear área de IA
                # Nota: El modelo Area requiere responsables, pero para simplificar usaremos el primer responsable disponible
                try:
                    # Intentar obtener área existente
                    ai_area = Area.objects.get(nombre='VANT-SIEM-AI-Monitor')
                except Area.DoesNotExist:
                    # Si no existe, necesitamos crear un responsable temporal o usar uno existente
                    try:
                        # Usar el primer responsable disponible como temporal
                        default_responsable = Responsable.objects.first()
                        if not default_responsable:
                            # Crear responsable temporal si no hay ninguno
                            default_responsable = Responsable.objects.create(
                                nombres='Sistema',
                                apellidos='IA',
                                email='ia@vantsiem.local',
                                telefono_particular='00000000',
                                telefono_corp='00000000',
                                tipo='Sistema',
                                descripcion='Responsable temporal para reportes de IA'
                            )

                        ai_area = Area.objects.create(
                            nombre='VANT-SIEM-AI-Monitor',
                            acronimo='AI-MON',
                            cuadro_centro=default_responsable,
                            rsi=default_responsable,
                            admin=default_responsable
                        )
                        self.stdout.write(f'✅ Área AI creada: {ai_area.nombre}')
                    except Exception as area_error:
                        self.stdout.write(
                            self.style.ERROR(f'❌ Error creando área AI: {str(area_error)}')
                        )
                        # Usar la primera área disponible como fallback
                        ai_area = Area.objects.first()
                        if not ai_area:
                            raise Exception("No hay áreas disponibles en el sistema")
                        self.stdout.write(f'⚠️ Usando área existente como fallback: {ai_area.nombre}')

                # Crear el reporte
                report_title = f'Reporte Automático IA - Alertas {timezone.now().strftime("%d/%m/%Y %H:%M")}'

                # Preparar contenido del reporte
                report_content = f"""
# {report_title}

## Información General
- **Fecha de Generación**: {timezone.now().strftime('%d/%m/%Y %H:%M:%S')}
- **Período Analizado**: Últimos 5 minutos
- **Total de Alertas**: {total_new_alerts}
- **Alertas Críticas**: {critical_alerts.count()}

## Alertas Detectadas
- **IDS Alerts**: {recent_ids_alerts.count()}
- **Snort Logs**: {recent_snort_logs.count()}
- **Suricata Alerts**: {recent_suricata_alerts.count()}

## Análisis de Inteligencia Artificial

{ai_analysis}

## Datos Técnicos (JSON)
```json
{json.dumps(alert_data, indent=2, ensure_ascii=False)}
```

---
*Reporte generado automáticamente por VANT-SIEM con análisis de IA*
"""

                new_report = Reporte.objects.create(
                    nombre_informante=report_title,
                    email_informante='ia@vantsiem.local',  # Email del sistema IA
                    descripcion=report_content[:2000],  # Limitar longitud
                    estado_solucion='abierto',
                    area=ai_area,
                    fecha_hora=timezone.now()
                )

                # Log del evento
                event_logger.log_event(
                    event_type='AI_AUTO_MONITOR_REPORT',
                    description=f'Reporte de monitoreo automático generado: {report_title}',
                    details={
                        'report_id': new_report.id,
                        'alerts_analyzed': total_new_alerts,
                        'critical_alerts': critical_alerts.count(),
                        'analysis_length': len(ai_analysis),
                        'time_period': '5 minutes'
                    },
                    target_model='Reporte',
                    target_id=new_report.id
                )

                self.stdout.write(
                    self.style.SUCCESS(
                        f'✅ Reporte automático generado exitosamente: ID {new_report.id}'
                    )
                )
                self.stdout.write(f'📄 Título: {report_title}')
                self.stdout.write(f'📊 Alertas analizadas: {total_new_alerts}')

        except Exception as e:
            logger.error(f'Error en monitoreo automático de alertas: {str(e)}')
            self.stdout.write(
                self.style.ERROR(f'❌ Error en monitoreo automático: {str(e)}')
            )

    def _generate_basic_analysis(self, alert_data):
        """Genera un análisis básico cuando la IA no está disponible"""
        total_alerts = alert_data['summary']['total_alerts']
        critical_alerts = alert_data['summary']['critical_alerts']

        analysis = f"""
## Análisis Básico de Alertas

### Resumen Ejecutivo
Se detectaron {total_alerts} alertas de seguridad en los últimos 5 minutos, incluyendo {critical_alerts} alertas críticas.

### Alertas por Sistema
- IDS: {len(alert_data['ids_alerts'])} alertas
- Snort: {len(alert_data['snort_logs'])} logs
- Suricata: {len(alert_data['suricata_alerts'])} alertas

### Recomendaciones
1. Revisar las alertas críticas inmediatamente
2. Investigar IPs sospechosas detectadas
3. Verificar configuraciones de IDS/IPS
4. Considerar bloqueo de IPs maliciosas

### Alertas Críticas Detectadas
"""

        if critical_alerts > 0:
            analysis += f"Se encontraron {critical_alerts} alertas de severidad crítica que requieren atención inmediata.\n"

        analysis += "\n*Análisis generado automáticamente - Se recomienda revisión manual detallada*"

        return analysis
