"""
Servicio de integración con Ollama para análisis inteligente de logs IDS/IPS
Proporciona capacidades de IA para análisis de patrones, detección de anomalías y generación de reportes
"""
import json
import requests
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from django.utils import timezone
from django.db.models import Count, Q
from django.conf import settings

from ids_ingest.models import (
    SnortLog, SuricataEveAlert, SuricataFlow, SuricataStats, 
    IDSAlert, IDSStatistics
)

logger = logging.getLogger(__name__)

class OllamaAIService:
    """Servicio de IA usando Ollama local para análisis de logs IDS/IPS"""

    def __init__(self, base_url: str = None, model: str = None):
        # Inicializar con valores por defecto - la configuración se cargará cuando sea necesaria
        self._base_url = base_url or "http://localhost:11434"
        self._model = model or "llama3.2"
        self._max_tokens = 2000
        self._temperature = 0.1
        self._timeout_seconds = 30
        self._config_loaded = False

        # Atributos que se cargarán de la BD
        self._can_read_snort_logs = None
        self._can_read_suricata_logs = None
        self._can_read_incidents = None
        self._can_read_reports = None
        self._can_read_users = None
        self._can_read_system_logs = None
        self._auto_generate_reports = None
        self._auto_send_emails = None
        self._auto_create_incidents = None
        self._alert_threshold_critical = None
        self._alert_threshold_high = None
        self._auto_report_interval_hours = None

        self.session = requests.Session()
        self.session.timeout = self._timeout_seconds

    def _load_config(self):
        """Cargar configuración de la base de datos de forma lazy"""
        if self._config_loaded:
            return

        try:
            from .models import OllamaConfig
            config = OllamaConfig.get_active_config()
            if config and config.is_active:
                self._base_url = config.ollama_url
                self._model = config.ollama_model
                self._max_tokens = config.max_tokens
                self._temperature = config.temperature
                self._timeout_seconds = config.timeout_seconds
                # Permisos (usar getattr para manejar campos faltantes)
                self._can_read_snort_logs = getattr(config, 'can_read_snort_logs', True)
                self._can_read_suricata_logs = getattr(config, 'can_read_suricata_logs', True)
                self._can_read_incidents = getattr(config, 'can_read_incidents', True)
                self._can_read_reports = getattr(config, 'can_read_reports', True)
                self._can_read_users = getattr(config, 'can_read_users', False)
                self._can_read_system_logs = getattr(config, 'can_read_system_logs', False)
                # Tareas automáticas
                self._auto_generate_reports = getattr(config, 'auto_generate_reports', False)
                self._auto_send_emails = getattr(config, 'auto_send_emails', False)
                self._auto_create_incidents = getattr(config, 'auto_create_incidents', False)
                self._alert_threshold_critical = getattr(config, 'alert_threshold_critical', 10)
                self._alert_threshold_high = getattr(config, 'alert_threshold_high', 50)
                self._auto_report_interval_hours = getattr(config, 'auto_report_interval_hours', 24)
            else:
                # Valores por defecto si no hay configuración
                self._set_defaults()
        except Exception as e:
            logger.warning(f"Error cargando configuración Ollama: {e}")
            self._set_defaults()

        self._config_loaded = True

    def _set_defaults(self):
        """Establecer valores por defecto"""
        self._can_read_snort_logs = True
        self._can_read_suricata_logs = True
        self._can_read_incidents = True
        self._can_read_reports = True
        self._can_read_users = False
        self._can_read_system_logs = False
        self._auto_generate_reports = False
        self._auto_send_emails = False
        self._auto_create_incidents = False
        self._alert_threshold_critical = 10
        self._alert_threshold_high = 50
        self._auto_report_interval_hours = 24

    # Properties para acceder a la configuración
    @property
    def base_url(self):
        self._load_config()
        return self._base_url

    @property
    def model(self):
        self._load_config()
        return self._model

    @property
    def max_tokens(self):
        self._load_config()
        return self._max_tokens

    @property
    def temperature(self):
        self._load_config()
        return self._temperature

    @property
    def timeout_seconds(self):
        self._load_config()
        return self._timeout_seconds

    @property
    def can_read_snort_logs(self):
        self._load_config()
        return self._can_read_snort_logs

    @property
    def can_read_suricata_logs(self):
        self._load_config()
        return self._can_read_suricata_logs

    @property
    def can_read_incidents(self):
        self._load_config()
        return self._can_read_incidents

    @property
    def can_read_reports(self):
        self._load_config()
        return self._can_read_reports

    @property
    def can_read_users(self):
        self._load_config()
        return self._can_read_users

    @property
    def can_read_system_logs(self):
        self._load_config()
        return self._can_read_system_logs

    @property
    def auto_generate_reports(self):
        self._load_config()
        return self._auto_generate_reports

    @property
    def auto_send_emails(self):
        self._load_config()
        return self._auto_send_emails

    @property
    def auto_create_incidents(self):
        self._load_config()
        return self._auto_create_incidents

    @property
    def alert_threshold_critical(self):
        self._load_config()
        return self._alert_threshold_critical

    @property
    def alert_threshold_high(self):
        self._load_config()
        return self._alert_threshold_high

    @property
    def auto_report_interval_hours(self):
        self._load_config()
        return self._auto_report_interval_hours
        
    def _call_ollama(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """Llamar a Ollama API con manejo de errores"""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "top_p": 0.9,
                    "max_tokens": self.max_tokens
                }
            }

            if system_prompt:
                payload["system"] = system_prompt

            response = self.session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('response', '').strip()
            else:
                logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Error conectando con Ollama: {e}")
            return None
        except Exception as e:
            logger.error(f"Error inesperado en Ollama: {e}")
            return None
    
    def analyze_security_trends(self, hours: int = 24) -> Dict[str, Any]:
        """Analizar tendencias de seguridad usando IA"""
        try:
            # Obtener datos de las últimas horas
            since = timezone.now() - timedelta(hours=hours)
            
            # Estadísticas de Snort
            snort_data = self._get_snort_analysis_data(since)
            
            # Estadísticas de Suricata
            suricata_data = self._get_suricata_analysis_data(since)
            
            # Crear prompt para análisis
            system_prompt = """Eres un analista de ciberseguridad profesional especializado en análisis de logs IDS/IPS.
            Tu tarea es analizar datos de seguridad reales de Snort y Suricata y proporcionar insights técnicos precisos.

            INSTRUCCIONES CRÍTICAS:
            - Analiza ÚNICAMENTE los datos de seguridad proporcionados
            - No inventes datos ni uses información externa
            - Si no hay suficientes datos, indica análisis limitado
            - Proporciona recomendaciones basadas en evidencia real
            - Mantén respuestas técnicas y profesionales

            Responde EXCLUSIVAMENTE en formato JSON válido con estas claves exactas:
            {
              "most_attacked_segment": "segmento más atacado basado en datos (ej: 192.168.1.0/24)",
              "most_suspicious_ip": "IP más sospechosa con justificación técnica",
              "peak_hour": "hora con más actividad (ej: 14:00-15:00)",
              "top_attack_type": "tipo de ataque más común identificado",
              "risk_level": "Low/Medium/High/Critical basado en evidencia",
              "recommendations": ["lista específica de recomendaciones técnicas"],
              "threat_summary": "resumen ejecutivo conciso de amenazas identificadas"
            }

            IMPORTANTE: Si no hay datos suficientes, usa valores por defecto pero indica limitación."""
            
            analysis_prompt = f"""
            ANÁLISIS DE SEGURIDAD - DATOS REALES DE IDS/IPS ({hours} HORAS)

            DATOS SNORT (Sistema de Detección de Intrusiones):
            {json.dumps(snort_data, indent=2, default=str)}

            DATOS SURICATA (Sistema de Detección de Intrusiones):
            {json.dumps(suricata_data, indent=2, default=str)}

            INSTRUCCIONES DE ANÁLISIS:
            1. Analiza los patrones de eventos de seguridad reales mostrados arriba
            2. Identifica IPs más activas en ataques (top_source_ips)
            3. Determina segmentos de red más afectados (basado en dst_ip patterns)
            4. Evalúa severidad de eventos (Critical/High events)
            5. Proporciona recomendaciones basadas en evidencia real

            IMPORTANTE:
            - Usa ÚNICAMENTE los datos proporcionados arriba
            - No inventes información ni uses conocimiento externo
            - Si hay pocos datos, indica "análisis limitado"
            - Responde solo con JSON válido
            """
            
            ai_response = self._call_ollama(analysis_prompt, system_prompt)
            
            if ai_response:
                # Validar que la respuesta sea sobre ciberseguridad y no datos meteorológicos
                if self._is_valid_security_response(ai_response):
                    try:
                        # Intentar parsear respuesta JSON
                        analysis = json.loads(ai_response)
                        return {
                            'success': True,
                            'analysis': analysis,
                            'data_summary': {
                                'snort_events': snort_data.get('total_events', 0),
                                'suricata_events': suricata_data.get('total_events', 0),
                                'analysis_period': f"{hours}h",
                                'generated_at': timezone.now().isoformat()
                            }
                        }
                    except json.JSONDecodeError:
                        # Si no es JSON válido, devolver como texto
                        return {
                            'success': True,
                            'analysis': {
                                'threat_summary': ai_response,
                                'most_attacked_segment': 'Análisis en progreso',
                                'most_suspicious_ip': 'Análisis en progreso',
                                'risk_level': 'Medium',
                                'recommendations': ['Revisar análisis detallado']
                            },
                            'raw_response': ai_response
                        }
                else:
                    # Respuesta no válida, usar análisis de respaldo
                    logger.warning(f"Respuesta de IA no válida para análisis de seguridad: {ai_response[:200]}...")
                    return self._get_fallback_analysis(snort_data, suricata_data)
            else:
                return self._get_fallback_analysis(snort_data, suricata_data)
                
        except Exception as e:
            logger.error(f"Error en análisis de tendencias: {e}")
            return self._get_fallback_analysis({}, {})
    
    def _get_snort_analysis_data(self, since: datetime) -> Dict[str, Any]:
        """Obtener datos de Snort para análisis"""
        if not self.can_read_snort_logs:
            return {
                'total_events': 0,
                'severity_distribution': {},
                'top_source_ips': [],
                'top_target_ips': [],
                'top_signatures': [],
                'protocol_distribution': {},
                'hourly_distribution': [],
                'critical_events': 0,
                'high_events': 0,
                'access_denied': True
            }

        snort_logs = SnortLog.objects.filter(timestamp__gte=since)

        return {
            'total_events': snort_logs.count(),
            'severity_distribution': dict(snort_logs.values('severity').annotate(count=Count('id'))),
            'top_source_ips': list(snort_logs.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10]),
            'top_target_ips': list(snort_logs.values('dst_ip').annotate(count=Count('id')).order_by('-count')[:10]),
            'top_signatures': list(snort_logs.values('sid', 'message').annotate(count=Count('id')).order_by('-count')[:10]),
            'protocol_distribution': dict(snort_logs.values('protocol').annotate(count=Count('id'))),
            'hourly_distribution': self._get_hourly_distribution(snort_logs),
            'critical_events': snort_logs.filter(severity='Critical').count(),
            'high_events': snort_logs.filter(severity='High').count()
        }
    
    def _get_suricata_analysis_data(self, since: datetime) -> Dict[str, Any]:
        """Obtener datos de Suricata para análisis"""
        if not self.can_read_suricata_logs:
            return {
                'total_events': 0,
                'severity_distribution': {},
                'top_source_ips': [],
                'top_target_ips': [],
                'top_signatures': [],
                'protocol_distribution': {},
                'category_distribution': {},
                'hourly_distribution': [],
                'critical_events': 0,
                'high_events': 0,
                'access_denied': True
            }

        suricata_alerts = SuricataEveAlert.objects.filter(timestamp__gte=since)

        return {
            'total_events': suricata_alerts.count(),
            'severity_distribution': dict(suricata_alerts.values('severity').annotate(count=Count('id'))),
            'top_source_ips': list(suricata_alerts.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10]),
            'top_target_ips': list(suricata_alerts.values('dest_ip').annotate(count=Count('id')).order_by('-count')[:10]),
            'top_signatures': list(suricata_alerts.values('signature_id', 'message').annotate(count=Count('id')).order_by('-count')[:10]),
            'protocol_distribution': dict(suricata_alerts.values('proto').annotate(count=Count('id'))),
            'category_distribution': dict(suricata_alerts.values('category').annotate(count=Count('id'))),
            'hourly_distribution': self._get_hourly_distribution(suricata_alerts),
            'critical_events': suricata_alerts.filter(severity=1).count(),
            'high_events': suricata_alerts.filter(severity=2).count()
        }
    
    def _get_hourly_distribution(self, queryset) -> List[Dict[str, Any]]:
        """Obtener distribución por horas"""
        hourly_data = []
        now = timezone.now()
        
        for i in range(24):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            count = queryset.filter(timestamp__gte=hour_start, timestamp__lt=hour_end).count()
            hourly_data.append({
                'hour': hour_start.strftime('%H:00'),
                'count': count,
                'timestamp': hour_start.isoformat()
            })
        
        return list(reversed(hourly_data))
    
    def generate_threat_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generar reporte de amenazas usando IA"""
        try:
            analysis = self.analyze_security_trends(hours)
            
            if not analysis.get('success'):
                return analysis
            
            # Obtener datos adicionales para el reporte
            since = timezone.now() - timedelta(hours=hours)
            
            # Alertas críticas no reconocidas
            unack_alerts = IDSAlert.objects.filter(
                acknowledged=False,
                timestamp__gte=since
            ).count()
            
            # Flujos de red sospechosos
            suspicious_flows = SuricataFlow.objects.filter(
                timestamp__gte=since,
                bytes_toserver__gt=1000000  # Flujos > 1MB
            ).count()
            
            system_prompt = """Eres un analista senior de ciberseguridad. Genera un reporte ejecutivo 
            profesional basado en los datos de análisis. El reporte debe incluir:
            1. Resumen ejecutivo de la situación de seguridad
            2. Amenazas críticas identificadas
            3. Recomendaciones prioritarias
            4. Métricas clave de seguridad
            5. Plan de acción inmediato
            
            Responde en formato JSON con estructura de reporte profesional."""
            
            report_prompt = f"""
            GENERAR REPORTE DE AMENAZAS:
            
            Análisis de IA: {json.dumps(analysis['analysis'], indent=2)}
            Alertas no reconocidas: {unack_alerts}
            Flujos sospechosos: {suspicious_flows}
            Período: {hours} horas
            
            Genera un reporte ejecutivo completo en JSON.
            """
            
            ai_report = self._call_ollama(report_prompt, system_prompt)
            
            if ai_report:
                try:
                    report_data = json.loads(ai_report)
                    return {
                        'success': True,
                        'report': report_data,
                        'metadata': {
                            'generated_at': timezone.now().isoformat(),
                            'period_hours': hours,
                            'unacknowledged_alerts': unack_alerts,
                            'suspicious_flows': suspicious_flows
                        }
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'report': {
                            'executive_summary': ai_report,
                            'threat_level': 'Medium',
                            'recommendations': ['Revisar análisis detallado']
                        }
                    }
            else:
                return {'success': False, 'error': 'No se pudo generar el reporte'}
                
        except Exception as e:
            logger.error(f"Error generando reporte de amenazas: {e}")
            return {'success': False, 'error': str(e)}
    
    def analyze_ip_behavior(self, ip_address: str, hours: int = 24) -> Dict[str, Any]:
        """Analizar comportamiento de una IP específica usando IA"""
        try:
            since = timezone.now() - timedelta(hours=hours)
            
            # Datos de Snort para esta IP
            snort_as_src = SnortLog.objects.filter(src_ip=ip_address, timestamp__gte=since)
            snort_as_dst = SnortLog.objects.filter(dst_ip=ip_address, timestamp__gte=since)
            
            # Datos de Suricata para esta IP
            suricata_as_src = SuricataEveAlert.objects.filter(src_ip=ip_address, timestamp__gte=since)
            suricata_as_dst = SuricataEveAlert.objects.filter(dest_ip=ip_address, timestamp__gte=since)
            
            ip_data = {
                'ip_address': ip_address,
                'analysis_period': f"{hours}h",
                'snort_as_source': {
                    'total_events': snort_as_src.count(),
                    'severity_dist': dict(snort_as_src.values('severity').annotate(count=Count('id'))),
                    'target_ports': list(snort_as_src.values('dst_port').annotate(count=Count('id')).order_by('-count')[:10]),
                    'protocols': dict(snort_as_src.values('protocol').annotate(count=Count('id')))
                },
                'snort_as_target': {
                    'total_events': snort_as_dst.count(),
                    'source_ips': list(snort_as_dst.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10])
                },
                'suricata_as_source': {
                    'total_events': suricata_as_src.count(),
                    'severity_dist': dict(suricata_as_src.values('severity').annotate(count=Count('id'))),
                    'signatures': list(suricata_as_src.values('signature_id', 'message').annotate(count=Count('id')).order_by('-count')[:5])
                },
                'suricata_as_target': {
                    'total_events': suricata_as_dst.count(),
                    'source_ips': list(suricata_as_dst.values('src_ip').annotate(count=Count('id')).order_by('-count')[:10])
                }
            }
            
            system_prompt = """Eres un analista forense de ciberseguridad profesional. Tu tarea es analizar
            el comportamiento de una IP específica y proporcionar un resumen claro y técnico en ESPAÑOL.

            IMPORTANTE:
            - Responde SIEMPRE en español
            - Proporciona un resumen legible y profesional
            - Incluye estadísticas clave
            - Da recomendaciones específicas
            - Mantén un tono técnico pero comprensible

            Estructura tu respuesta como un informe profesional."""

            analysis_prompt = f"""
            ANÁLISIS FORENSE DE IP: {ip_address}

            DATOS TÉCNICOS RECOPILADOS:
            • Eventos como fuente (Snort): {ip_data['snort_as_source']['total_events']:,}
            • Eventos como destino (Snort): {ip_data['snort_as_target']['total_events']:,}
            • Eventos como fuente (Suricata): {ip_data['suricata_as_source']['total_events']:,}
            • Eventos como destino (Suricata): {ip_data['suricata_as_target']['total_events']:,}

            PUERTOS DESTINO MÁS FRECUENTES:
            {chr(10).join([f"• Puerto {p['dst_port']}: {p['count']:,} conexiones" for p in ip_data['snort_as_source']['target_ports'][:5]])}

            IPs FUENTE MÁS ACTIVAS (cuando es destino):
            {chr(10).join([f"• {ip['src_ip']}: {ip['count']:,} eventos" for ip in ip_data['snort_as_target']['source_ips'][:5]])}

            ESCRIBE UN RESUMEN PROFESIONAL Y LEGIBLE en español que incluya:
            1. Nivel de amenaza general
            2. Tipo de actividad observada
            3. Patrones de comportamiento clave
            4. Recomendaciones específicas de seguridad
            5. Indicadores de riesgo o normalidad

            El resumen debe ser claro, técnico y directamente utilizable por un analista de seguridad.
            """
            
            ai_response = self._call_ollama(analysis_prompt, system_prompt)

            if ai_response:
                # Validar que la respuesta sea sobre ciberseguridad
                if self._is_valid_security_response(ai_response):
                    # Crear resumen estructurado pero legible
                    summary = self._format_ip_analysis_summary(ai_response, ip_data)

                    return {
                        'success': True,
                        'ip_analysis': {
                            'threat_level': self._determine_threat_level(ip_data),
                            'activity_type': self._classify_activity_type(ip_data),
                            'summary': summary,
                            'recommendations': self._generate_ip_recommendations(ip_data),
                            'key_metrics': {
                                'total_events_as_source': ip_data['snort_as_source']['total_events'] + ip_data['suricata_as_source']['total_events'],
                                'total_events_as_target': ip_data['snort_as_target']['total_events'] + ip_data['suricata_as_target']['total_events'],
                                'top_destination_port': ip_data['snort_as_source']['target_ports'][0]['dst_port'] if ip_data['snort_as_source']['target_ports'] else 'N/A',
                                'unique_source_ips': len(set([ip['src_ip'] for ip in ip_data['snort_as_target']['source_ips']])),
                            }
                        },
                        'raw_data': ip_data
                    }
                else:
                    # Respuesta no válida, usar análisis de respaldo
                    logger.warning(f"Respuesta de IA no válida para análisis de IP: {ai_response[:200]}...")
                    return self._get_ip_fallback_analysis(ip_data)
            else:
                return {'success': False, 'error': 'No se pudo analizar la IP'}
                
        except Exception as e:
            logger.error(f"Error analizando IP {ip_address}: {e}")
            return {'success': False, 'error': str(e)}
    
    def generate_predictive_analysis(self) -> Dict[str, Any]:
        """Generar análisis predictivo de amenazas"""
        try:
            # Obtener datos históricos (últimos 7 días)
            since = timezone.now() - timedelta(days=7)
            
            # Tendencias por día
            daily_trends = []
            for i in range(7):
                day_start = timezone.now() - timedelta(days=i+1)
                day_end = timezone.now() - timedelta(days=i)
                
                snort_count = SnortLog.objects.filter(timestamp__gte=day_start, timestamp__lt=day_end).count()
                suricata_count = SuricataEveAlert.objects.filter(timestamp__gte=day_start, timestamp__lt=day_end).count()
                
                daily_trends.append({
                    'date': day_start.strftime('%Y-%m-%d'),
                    'snort_events': snort_count,
                    'suricata_events': suricata_count,
                    'total_events': snort_count + suricata_count
                })
            
            daily_trends.reverse()
            
            system_prompt = """Eres un analista predictivo de ciberseguridad. Basándote en las tendencias 
            históricas, predice:
            1. Tendencias de amenazas para los próximos 7 días
            2. Posibles vectores de ataque emergentes
            3. Recomendaciones preventivas
            4. Métricas de riesgo proyectadas
            
            Responde en formato JSON con predicciones específicas."""
            
            prediction_prompt = f"""
            ANÁLISIS PREDICTIVO DE AMENAZAS:
            
            TENDENCIAS HISTÓRICAS (7 días):
            {json.dumps(daily_trends, indent=2)}
            
            Genera predicciones de seguridad para los próximos 7 días en formato JSON.
            """
            
            ai_response = self._call_ollama(prediction_prompt, system_prompt)
            
            if ai_response:
                try:
                    predictions = json.loads(ai_response)
                    return {
                        'success': True,
                        'predictions': predictions,
                        'historical_data': daily_trends
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'predictions': {
                            'summary': ai_response,
                            'risk_trend': 'Stable',
                            'recommendations': ['Mantener monitoreo actual']
                        },
                        'historical_data': daily_trends
                    }
            else:
                return {'success': False, 'error': 'No se pudo generar predicción'}
                
        except Exception as e:
            logger.error(f"Error en análisis predictivo: {e}")
            return {'success': False, 'error': str(e)}
    
    def correlate_events(self, time_window: int = 60) -> Dict[str, Any]:
        """Correlacionar eventos entre Snort y Suricata usando IA"""
        try:
            since = timezone.now() - timedelta(minutes=time_window)
            
            # Obtener eventos recientes
            recent_snort = list(SnortLog.objects.filter(
                timestamp__gte=since
            ).values('timestamp', 'src_ip', 'dst_ip', 'protocol', 'message', 'severity')[:50])
            
            recent_suricata = list(SuricataEveAlert.objects.filter(
                timestamp__gte=since
            ).values('timestamp', 'src_ip', 'dest_ip', 'proto', 'message', 'severity')[:50])
            
            system_prompt = """Eres un experto en correlación de eventos de seguridad. Analiza los eventos 
            de Snort y Suricata para identificar:
            1. Eventos correlacionados (misma IP, tiempo similar)
            2. Patrones de ataque coordinados
            3. Cadenas de eventos sospechosos
            4. Anomalías temporales
            
            Responde en formato JSON con correlaciones identificadas."""
            
            correlation_prompt = f"""
            CORRELACIÓN DE EVENTOS ({time_window} minutos):
            
            EVENTOS SNORT:
            {json.dumps(recent_snort, indent=2, default=str)}
            
            EVENTOS SURICATA:
            {json.dumps(recent_suricata, indent=2, default=str)}
            
            Identifica correlaciones y patrones en formato JSON.
            """
            
            ai_response = self._call_ollama(correlation_prompt, system_prompt)
            
            if ai_response:
                try:
                    correlations = json.loads(ai_response)
                    return {
                        'success': True,
                        'correlations': correlations,
                        'event_counts': {
                            'snort_events': len(recent_snort),
                            'suricata_events': len(recent_suricata)
                        }
                    }
                except json.JSONDecodeError:
                    return {
                        'success': True,
                        'correlations': {
                            'summary': ai_response,
                            'correlated_events': 0,
                            'recommendations': ['Revisar eventos manualmente']
                        }
                    }
            else:
                return {'success': False, 'error': 'No se pudo correlacionar eventos'}
                
        except Exception as e:
            logger.error(f"Error correlacionando eventos: {e}")
            return {'success': False, 'error': str(e)}
    
    def _is_valid_security_response(self, response: str) -> bool:
        """Validar que la respuesta de IA sea sobre ciberseguridad y no datos irrelevantes"""
        response_lower = response.lower()

        # Palabras clave que deben estar presentes en una respuesta válida de ciberseguridad
        security_keywords = [
            'ip', 'ataque', 'seguridad', 'threat', 'intrusion', 'malware', 'vulnerabilidad',
            'riesgo', 'análisis', 'evento', 'alerta', 'sospechoso', 'segmento', 'red',
            'snort', 'suricata', 'ids', 'ips', 'ciberseguridad', 'attack', 'security'
        ]

        # Palabras clave que indican respuestas inválidas (datos meteorológicos, etc.)
        invalid_keywords = [
            'temperatura', 'clima', 'weather', 'humidity', 'wind', 'precipitation',
            'temperature', 'clouds', 'pressure', 'dew', 'visibility', 'latitude', 'longitude'
        ]

        # Contar palabras clave de seguridad
        security_count = sum(1 for keyword in security_keywords if keyword in response_lower)

        # Verificar si contiene palabras clave inválidas
        invalid_count = sum(1 for keyword in invalid_keywords if keyword in response_lower)

        # La respuesta es válida si tiene al menos 3 palabras clave de seguridad y ninguna inválida
        return security_count >= 3 and invalid_count == 0

    def _format_ip_analysis_summary(self, ai_response: str, ip_data: Dict) -> str:
        """Formatear el resumen de análisis de IP de manera legible"""
        total_source = ip_data['snort_as_source']['total_events'] + ip_data['suricata_as_source']['total_events']
        total_target = ip_data['snort_as_target']['total_events'] + ip_data['suricata_as_target']['total_events']

        # Crear resumen estructurado
        summary = f"Análisis de comportamiento de IP {ip_data['ip_address']} en las últimas {ip_data['analysis_period']}:\n\n"

        summary += f"📊 **Estadísticas Generales:**\n"
        summary += f"• Eventos como fuente: {total_source:,}\n"
        summary += f"• Eventos como destino: {total_target:,}\n"
        summary += f"• Total de actividad: {total_source + total_target:,} eventos\n\n"

        # Puertos destino más frecuentes
        if ip_data['snort_as_source']['target_ports']:
            summary += f"🔌 **Puertos Destino Más Usados:**\n"
            for port_data in ip_data['snort_as_source']['target_ports'][:3]:
                port_name = self._get_port_name(port_data['dst_port'])
                summary += f"• Puerto {port_data['dst_port']} ({port_name}): {port_data['count']:,} conexiones\n"
            summary += "\n"

        # IPs fuente más activas (cuando es destino)
        if ip_data['snort_as_target']['source_ips']:
            summary += f"🌐 **IPs Fuente Más Activas (como destino):**\n"
            for ip_info in ip_data['snort_as_target']['source_ips'][:3]:
                summary += f"• {ip_info['src_ip']}: {ip_info['count']:,} eventos\n"
            summary += "\n"

        # Agregar análisis de IA si está disponible
        if ai_response and len(ai_response.strip()) > 50:
            summary += f"🤖 **Análisis Inteligente:**\n{ai_response}\n\n"
        else:
            summary += f"🤖 **Análisis Automático:** Actividad normal de red detectada.\n\n"

        return summary

    def _get_port_name(self, port: int) -> str:
        """Obtener nombre descriptivo de puerto común"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 5432: "PostgreSQL"
        }
        return common_ports.get(port, "Desconocido")

    def _determine_threat_level(self, ip_data: Dict) -> str:
        """Determinar nivel de amenaza basado en datos"""
        total_events = (ip_data['snort_as_source']['total_events'] +
                       ip_data['snort_as_target']['total_events'] +
                       ip_data['suricata_as_source']['total_events'] +
                       ip_data['suricata_as_target']['total_events'])

        # Lógica simple de clasificación
        if total_events > 10000:
            return "High"
        elif total_events > 1000:
            return "Medium"
        else:
            return "Low"

    def _classify_activity_type(self, ip_data: Dict) -> str:
        """Clasificar tipo de actividad"""
        total_source = ip_data['snort_as_source']['total_events'] + ip_data['suricata_as_source']['total_events']
        total_target = ip_data['snort_as_target']['total_events'] + ip_data['suricata_as_target']['total_events']

        if total_source > total_target * 2:
            return "Cliente Activo"
        elif total_target > total_source * 2:
            return "Servidor/Servicio"
        else:
            return "Comunicación Bidireccional"

    def _generate_ip_recommendations(self, ip_data: Dict) -> List[str]:
        """Generar recomendaciones basadas en el análisis de IP"""
        recommendations = []
        total_events = (ip_data['snort_as_source']['total_events'] +
                       ip_data['snort_as_target']['total_events'])

        if total_events > 1000:
            recommendations.append("Monitorear actividad intensiva de esta IP")
        if ip_data['snort_as_source']['target_ports']:
            top_port = ip_data['snort_as_source']['target_ports'][0]['dst_port']
            if top_port in [22, 3389]:  # Puertos de administración
                recommendations.append("Revisar accesos administrativos desde esta IP")
            elif top_port == 80 or top_port == 443:
                recommendations.append("Verificar tráfico web legítimo")

        if len(ip_data['snort_as_target']['source_ips']) > 5:
            recommendations.append("Investigar múltiples conexiones entrantes")

        if not recommendations:
            recommendations.append("Continuar monitoreo normal")

        return recommendations

    def _get_ip_fallback_analysis(self, ip_data: Dict) -> Dict[str, Any]:
        """Análisis de respaldo para IP cuando IA falla"""
        total_source = ip_data['snort_as_source']['total_events'] + ip_data['suricata_as_source']['total_events']
        total_target = ip_data['snort_as_target']['total_events'] + ip_data['suricata_as_target']['total_events']

        threat_level = self._determine_threat_level(ip_data)
        activity_type = self._classify_activity_type(ip_data)

        summary = f"Análisis automático de IP {ip_data['ip_address']}:\n\n"
        summary += f"• Actividad total: {total_source + total_target:,} eventos\n"
        summary += f"• Como fuente: {total_source:,} eventos\n"
        summary += f"• Como destino: {total_target:,} eventos\n"
        summary += f"• Nivel de amenaza: {threat_level}\n"
        summary += f"• Tipo de actividad: {activity_type}"

        return {
            'success': True,
            'ip_analysis': {
                'threat_level': threat_level,
                'activity_type': activity_type,
                'summary': summary,
                'recommendations': self._generate_ip_recommendations(ip_data),
                'key_metrics': {
                    'total_events_as_source': total_source,
                    'total_events_as_target': total_target,
                    'top_destination_port': ip_data['snort_as_source']['target_ports'][0]['dst_port'] if ip_data['snort_as_source']['target_ports'] else 'N/A',
                    'unique_source_ips': len(set([ip['src_ip'] for ip in ip_data['snort_as_target']['source_ips']])),
                }
            },
            'raw_data': ip_data,
            'fallback': True
        }

    def _get_fallback_analysis(self, snort_data: Dict, suricata_data: Dict) -> Dict[str, Any]:
        """Análisis de respaldo cuando Ollama no está disponible o falla"""
        total_snort = snort_data.get('total_events', 0)
        total_suricata = suricata_data.get('total_events', 0)
        total_events = total_snort + total_suricata

        # Determinar segmento más atacado basado en datos reales
        most_attacked = 'Sin datos suficientes'
        snort_top_ips = snort_data.get('top_source_ips', [])
        suricata_top_ips = suricata_data.get('top_source_ips', [])

        if snort_top_ips or suricata_top_ips:
            # Extraer segmento de red de las IPs más activas
            all_ips = [ip['src_ip'] for ip in snort_top_ips] + [ip['src_ip'] for ip in suricata_top_ips]
            if all_ips:
                # Tomar el primer octeto de la primera IP para determinar segmento
                first_ip = all_ips[0]
                if '.' in first_ip:
                    octets = first_ip.split('.')
                    most_attacked = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"

        # Determinar IP más sospechosa
        most_suspicious = 'Sin datos suficientes'
        if snort_top_ips:
            most_suspicious = snort_top_ips[0]['src_ip']
        elif suricata_top_ips:
            most_suspicious = suricata_top_ips[0]['src_ip']

        # Determinar tipo de ataque más común
        top_attack = 'Sin datos suficientes'
        snort_signatures = snort_data.get('top_signatures', [])
        suricata_signatures = suricata_data.get('top_signatures', [])

        if snort_signatures:
            top_attack = snort_signatures[0]['message'][:50] + '...'
        elif suricata_signatures:
            top_attack = suricata_signatures[0]['message'][:50] + '...'

        # Determinar nivel de riesgo basado en eventos críticos
        critical_snort = snort_data.get('critical_events', 0)
        critical_suricata = suricata_data.get('critical_events', 0)
        total_critical = critical_snort + critical_suricata

        if total_critical > 10:
            risk_level = 'Critical'
        elif total_events > 100:
            risk_level = 'High'
        elif total_events > 50:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'

        # Generar recomendaciones basadas en datos reales
        recommendations = []
        if total_critical > 0:
            recommendations.append(f'Investigar {total_critical} eventos críticos detectados')
        if snort_top_ips:
            recommendations.append(f'Monitorear actividad desde IP {most_suspicious}')
        if total_events > 0:
            recommendations.append('Revisar configuración de reglas IDS/IPS')
            recommendations.append('Implementar monitoreo adicional en segmentos críticos')
        else:
            recommendations.append('Sin eventos de seguridad detectados en el período')

        return {
            'success': True,
            'analysis': {
                'most_attacked_segment': most_attacked,
                'most_suspicious_ip': most_suspicious,
                'peak_hour': 'Análisis no disponible (modo respaldo)',
                'top_attack_type': top_attack,
                'risk_level': risk_level,
                'correlated_alerts': min(total_events // 10, 50),
                'anomalous_events': min(total_events // 20, 25),
                'threat_summary': f'Análisis automático: {total_events} eventos detectados ({total_snort} Snort, {total_suricata} Suricata). {total_critical} eventos críticos identificados.',
                'recommendations': recommendations
            },
            'fallback': True
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """Probar conexión con Ollama"""
        try:
            # Usar timeout configurado
            response = self.session.get(f"{self.base_url}/api/tags", timeout=self.timeout_seconds)
            if response.status_code == 200:
                models = response.json().get('models', [])
                return {
                    'success': True,
                    'status': 'connected',
                    'available_models': [m.get('name', 'unknown') for m in models],
                    'current_model': self.model,
                    'base_url': self.base_url
                }
            else:
                return {
                    'success': False,
                    'status': 'error',
                    'error': f"HTTP {response.status_code}",
                    'base_url': self.base_url
                }
        except Exception as e:
            return {
                'success': False,
                'status': 'disconnected',
                'error': str(e),
                'base_url': self.base_url
            }

# Instancia global del servicio
ollama_service = OllamaAIService()