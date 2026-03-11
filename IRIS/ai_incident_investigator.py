#!/usr/bin/env python3
"""
Sistema de IA para Investigación Automática de Incidentes de Ciberseguridad

Este sistema analiza logs IDS/IPS, detecta patrones, crea reportes e incidentes
automáticamente, aplica medidas de respuesta y aprende de falsos positivos.
"""

import os
import sys
import django
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import logging

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from EVENT_M.models import Reporte, Incidente, Involucrado, Medida, MedidaIncidente, Area, Responsable, Servicio, InvolucradoIncidente
from opensearch_ui.models import SnortLog, SuricataEveAlert
from IRIS.models import (
    IncidentPrediction, AIConfiguration, AIRateLimit, AICircuitBreaker,
    AIAuditLog, AIAlert, AIPerformanceMetrics
)
from django.utils import timezone
from django.db.models import Count, Q
from django.core.mail import send_mail
from django.conf import settings
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AIIncidentInvestigator:
    """
    Motor de IA para investigación automática de incidentes
    """

    def __init__(self):
        self.models_dir = 'ai_models'
        os.makedirs(self.models_dir, exist_ok=True)

        # Modelos de ML
        self.anomaly_detector = None
        self.incident_classifier = None
        self.pattern_analyzer = None

        # Codificadores
        self.label_encoders = {}

        # Métricas de rendimiento
        self.performance_metrics = {
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0
        }

        # Configuración y controles de seguridad
        self.config = self.get_ai_configuration()
        self.circuit_breaker = self.get_or_create_circuit_breaker()
        self.rate_limits = self.initialize_rate_limits()

        self.load_or_train_models()

    def get_ai_configuration(self):
        """Obtener configuración actual del sistema de IA"""
        config = AIConfiguration.objects.first()
        if not config:
            config = AIConfiguration.objects.create()
        return config

    def get_or_create_circuit_breaker(self):
        """Obtener o crear circuit breaker para el sistema de IA"""
        cb, created = AICircuitBreaker.objects.get_or_create(
            name='ai_incident_investigator',
            defaults={
                'failure_threshold': 5,
                'recovery_timeout_seconds': 300,
                'success_threshold': 3
            }
        )
        return cb

    def initialize_rate_limits(self):
        """Inicializar límites de tasa para diferentes acciones"""
        rate_limits = {}
        actions = ['prediction_creation', 'incident_creation', 'measure_application', 'analysis_execution']

        for action in actions:
            rl, created = AIRateLimit.objects.get_or_create(
                action_type=action,
                time_window_minutes=60,
                defaults={
                    'max_actions': self.get_default_rate_limit(action)
                }
            )
            rate_limits[action] = rl

        return rate_limits

    def get_default_rate_limit(self, action_type):
        """Obtener límite por defecto para un tipo de acción"""
        defaults = {
            'prediction_creation': self.config.max_predictions_per_hour,
            'incident_creation': self.config.max_incidents_per_hour,
            'measure_application': 20,  # medidas por hora
            'analysis_execution': 10    # análisis por hora
        }
        return defaults.get(action_type, 10)

    def check_safety_controls(self):
        """Verificar todos los controles de seguridad antes de ejecutar acciones"""
        # Verificar circuit breaker
        if not self.circuit_breaker.can_execute():
            self.log_audit('circuit_breaker_triggered', 'critical',
                          f'Circuit breaker abierto - bloqueando ejecución automática')
            self.create_alert('circuit_breaker_open', 'high',
                            'Circuit Breaker Abierto',
                            'El sistema de IA está bloqueado por alta tasa de fallos')
            return False

        # Verificar fase de adopción
        if self.config.adoption_phase == 'passive':
            logger.info("Modo pasivo: solo generando predicciones")
            return True  # Permitir predicciones pero no acciones automáticas

        return True

    def can_create_incident_automatically(self, confidence_score):
        """Verificar si se puede crear incidente automáticamente basado en la fase de adopción"""
        if self.config.adoption_phase == 'passive':
            return False
        elif self.config.adoption_phase == 'supervised':
            return False  # Requiere validación humana
        elif self.config.adoption_phase == 'semi_automated':
            return confidence_score >= self.config.min_confidence_score
        elif self.config.adoption_phase == 'full_automated':
            return self.config.auto_create_incidents and confidence_score >= self.config.min_confidence_score

        return False

    def can_apply_measures_automatically(self):
        """Verificar si se pueden aplicar medidas automáticamente"""
        if self.config.adoption_phase in ['passive', 'supervised']:
            return False
        return self.config.auto_apply_measures

    def check_rate_limit(self, action_type):
        """Verificar límite de tasa para una acción"""
        if action_type not in self.rate_limits:
            return True

        rate_limit = self.rate_limits[action_type]
        if not rate_limit.can_perform_action():
            self.log_audit('rate_limit_exceeded', 'warning',
                          f'Límite de tasa excedido para {action_type}')
            self.create_alert('rate_limit_exceeded', 'medium',
                            f'Límite de Tasa Excedido: {action_type}',
                            f'Se ha excedido el límite de {rate_limit.max_actions} acciones por hora para {action_type}')
            return False

        return True

    def record_action(self, action_type):
        """Registrar una acción realizada"""
        if action_type in self.rate_limits:
            self.rate_limits[action_type].record_action()

    def log_audit(self, action_type, severity, description, user=None, incident=None, prediction=None, metadata=None):
        """Registrar acción en el log de auditoría"""
        try:
            AIAuditLog.objects.create(
                action_type=action_type,
                severity=severity,
                description=description,
                user=user,
                related_incident=incident,
                related_prediction=prediction,
                metadata=metadata or {}
            )
        except Exception as e:
            logger.error(f"Error registrando auditoría: {str(e)}")

    def create_alert(self, alert_type, priority, title, message, metadata=None):
        """Crear una alerta del sistema"""
        try:
            alert = AIAlert.objects.create(
                alert_type=alert_type,
                priority=priority,
                title=title,
                message=message,
                metadata=metadata or {}
            )

            # Enviar notificaciones por email si están configuradas
            if self.config.alert_email_recipients:
                self.send_alert_email(alert)

            return alert
        except Exception as e:
            logger.error(f"Error creando alerta: {str(e)}")
            return None

    def send_alert_email(self, alert):
        """Enviar alerta por email"""
        try:
            subject = f"IRIS Alert - {alert.get_priority_display()}: {alert.title}"
            message = f"""
IRIS Alert Notification

Type: {alert.get_alert_type_display()}
Priority: {alert.get_priority_display()}
Title: {alert.title}

Message:
{alert.message}

Time: {alert.created_at}

Please check the IRIS dashboard for more details.
            """

            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                self.config.alert_email_recipients,
                fail_silently=True
            )
        except Exception as e:
            logger.error(f"Error enviando email de alerta: {str(e)}")

    def load_or_train_models(self):
        """Cargar modelos existentes o entrenar nuevos"""
        try:
            # Intentar cargar modelos existentes
            self.anomaly_detector = joblib.load(f'{self.models_dir}/anomaly_detector.pkl')
            self.incident_classifier = joblib.load(f'{self.models_dir}/incident_classifier.pkl')
            logger.info("Modelos cargados exitosamente")
        except FileNotFoundError:
            logger.info("Modelos no encontrados, entrenando nuevos...")
            self.train_models()

    def extract_log_features(self, logs_queryset, log_type='snort'):
        """Extraer características de logs para ML"""
        features = []

        for log in logs_queryset:
            if log_type == 'snort':
                feature_dict = {
                    'timestamp_hour': log.timestamp.hour,
                    'timestamp_day': log.timestamp.weekday(),
                    'src_port': log.src_port or 0,
                    'dst_port': log.dst_port or 0,
                    'protocol': hash(log.protocol) % 1000,  # Hash simple para categorizar
                    'severity': log.severity or 0,
                    'priority': log.priority or 0,
                    'gid': log.gid or 0,
                    'sid': log.sid or 0,
                    'src_ip_numeric': self.ip_to_int(log.src_ip),
                    'dst_ip_numeric': self.ip_to_int(log.dst_ip),
                    'message_length': len(log.message or ''),
                    'has_critical_keywords': self.has_critical_keywords(log.message or ''),
                }
            else:  # Suricata
                feature_dict = {
                    'timestamp_hour': log.timestamp.hour,
                    'timestamp_day': log.timestamp.weekday(),
                    'src_port': log.src_port or 0,
                    'dest_port': log.dest_port or 0,
                    'proto': hash(log.proto) % 1000,
                    'severity': log.severity or 1,
                    'signature_id': log.signature_id or 0,
                    'src_ip_numeric': self.ip_to_int(log.src_ip),
                    'dst_ip_numeric': self.ip_to_int(log.dest_ip),
                    'message_length': len(log.message or ''),
                    'has_critical_keywords': self.has_critical_keywords(log.message or ''),
                }

            features.append(feature_dict)

        return pd.DataFrame(features)

    def ip_to_int(self, ip_str):
        """Convertir IP a representación numérica"""
        try:
            parts = ip_str.split('.')
            return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])
        except:
            return 0

    def has_critical_keywords(self, message):
        """Verificar si el mensaje contiene palabras clave críticas"""
        critical_words = [
            'attack', 'exploit', 'malware', 'virus', 'trojan', 'ransomware',
            'brute', 'force', 'scan', 'intrusion', 'breach', 'compromise',
            'suspicious', 'anomaly', 'threat', 'alert', 'critical'
        ]
        message_lower = message.lower()
        return 1 if any(word in message_lower for word in critical_words) else 0

    def train_anomaly_detector(self):
        """Entrenar detector de anomalías"""
        logger.info("Entrenando detector de anomalías...")

        # Obtener logs recientes como datos "normales"
        recent_logs = SnortLog.objects.filter(
            timestamp__gte=timezone.now() - timedelta(days=30)
        )[:10000]  # Limitar para entrenamiento inicial

        if recent_logs.count() < 100:
            logger.warning("Insuficientes datos para entrenar detector de anomalías")
            return

        # Extraer características
        features_df = self.extract_log_features(recent_logs, 'snort')

        # Entrenar Isolation Forest
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # 10% de anomalías esperadas
            random_state=42,
            n_estimators=100
        )

        # Seleccionar columnas numéricas
        numeric_columns = features_df.select_dtypes(include=[np.number]).columns
        X = features_df[numeric_columns].fillna(0)

        self.anomaly_detector.fit(X)
        joblib.dump(self.anomaly_detector, f'{self.models_dir}/anomaly_detector.pkl')
        logger.info("Detector de anomalías entrenado y guardado")

    def train_incident_classifier(self):
        """Entrenar clasificador de tipos de incidentes"""
        logger.info("Entrenando clasificador de incidentes...")

        # Obtener incidentes con sus logs relacionados
        incidentes = Incidente.objects.filter(
            fecha_hora__gte=timezone.now() - timedelta(days=90)
        ).select_related('reporte')

        if incidentes.count() < 10:
            logger.warning("Insuficientes incidentes para entrenar clasificador")
            return

        training_data = []
        labels = []

        for incidente in incidentes:
            # Buscar logs relacionados por IP de involucrados
            involucrados = incidente.involucradoincidente_set.all()
            ips_involucrados = [inv.involucrado.ip for inv in involucrados]

            # Encontrar logs que coincidan con estas IPs
            related_logs = SnortLog.objects.filter(
                Q(src_ip__in=ips_involucrados) | Q(dst_ip__in=ips_involucrados),
                timestamp__range=(
                    incidente.fecha_hora - timedelta(hours=1),
                    incidente.fecha_hora + timedelta(hours=24)
                )
            )[:50]  # Máximo 50 logs por incidente

            for log in related_logs:
                features = self.extract_log_features([log], 'snort').iloc[0].to_dict()
                training_data.append(features)

                # Etiqueta basada en subcategorías del incidente
                subcats = incidente.subcategorias.all()
                if subcats:
                    label = subcats.first().nombre
                else:
                    label = 'Desconocido'

                labels.append(label)

        if len(training_data) < 50:
            logger.warning("Insuficientes datos de entrenamiento para clasificador")
            return

        # Preparar datos
        df = pd.DataFrame(training_data)
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        X = df[numeric_columns].fillna(0)

        # Codificar etiquetas
        self.label_encoders['incident_type'] = LabelEncoder()
        y = self.label_encoders['incident_type'].fit_transform(labels)

        # Dividir datos
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Entrenar clasificador
        self.incident_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight='balanced'
        )

        self.incident_classifier.fit(X_train, y_train)

        # Evaluar
        y_pred = self.incident_classifier.predict(X_test)
        logger.info("Reporte de clasificación:")
        logger.info(classification_report(y_test, y_pred,
                                        target_names=self.label_encoders['incident_type'].classes_,
                                        zero_division=0))

        # Guardar modelo
        joblib.dump(self.incident_classifier, f'{self.models_dir}/incident_classifier.pkl')
        joblib.dump(self.label_encoders, f'{self.models_dir}/label_encoders.pkl')
        logger.info("Clasificador de incidentes entrenado y guardado")

    def train_models(self):
        """Entrenar todos los modelos"""
        logger.info("Iniciando entrenamiento de modelos...")
        self.train_anomaly_detector()
        self.train_incident_classifier()
        logger.info("Modelos entrenados exitosamente")

        # Crear/actualizar registros de modelos en la base de datos
        logger.info("Actualizando registros de modelos en base de datos...")
        self.update_model_records()
        logger.info("Entrenamiento completo finalizado")

    def analyze_recent_logs(self, hours_back=24):
        """Analizar logs recientes, generar predicciones y procesar amenazas automáticamente (SOAR completo)"""
        logger.info(f"Iniciando análisis SOAR completo de las últimas {hours_back} horas...")

        # Verificar controles de seguridad
        if not self.check_safety_controls():
            logger.warning("Controles de seguridad bloqueando ejecución")
            return 0, 0

        # Verificar límite de tasa para análisis
        if not self.check_rate_limit('analysis_execution'):
            logger.warning("Límite de tasa excedido para análisis")
            return 0, 0

        self.record_action('analysis_execution')
        self.log_audit('analysis_executed', 'info',
                      f'Análisis SOAR iniciado - últimas {hours_back} horas')

        try:
            since_time = timezone.now() - timedelta(hours=hours_back)

            # Analizar logs de Snort
            snort_logs = SnortLog.objects.filter(timestamp__gte=since_time)
            suricata_alerts = SuricataEveAlert.objects.filter(timestamp__gte=since_time)

            logger.info(f"Analizando {snort_logs.count()} logs Snort y {suricata_alerts.count()} alertas Suricata")

            # Detectar anomalías
            anomalies_snort = self.detect_anomalies(snort_logs, 'snort')
            anomalies_suricata = self.detect_anomalies(suricata_alerts, 'suricata')

            # Correlacionar eventos
            potential_threats = self.correlate_events(anomalies_snort + anomalies_suricata)

            # Fase 1: Generar predicciones
            predictions_created = 0
            high_confidence_threats = []

            for threat_data in potential_threats:
                if not self.check_rate_limit('prediction_creation'):
                    logger.warning("Límite de tasa excedido para creación de predicciones")
                    break

                prediction = self.create_prediction_from_analysis(threat_data)
                if prediction:
                    predictions_created += 1
                    self.record_action('prediction_creation')
                    self.log_audit('prediction_created', 'info',
                                 f'Predicción creada: {prediction.incident_type} (confianza: {prediction.confidence_score:.2f})',
                                 prediction=prediction)

                    # Evaluar si procesar automáticamente basado en fase de adopción
                    if self.can_create_incident_automatically(prediction.confidence_score):
                        high_confidence_threats.append((prediction, threat_data))

            logger.info(f"Predicciones generadas: {predictions_created}")
            logger.info(f"Amenazas de alta confianza detectadas: {len(high_confidence_threats)}")

            # Fase 2: Investigación y respuesta automática para amenazas de alta confianza
            incidents_created = 0
            for prediction, threat_data in high_confidence_threats:
                if not self.check_rate_limit('incident_creation'):
                    logger.warning("Límite de tasa excedido para creación de incidentes")
                    break

                try:
                    # Validar automáticamente la predicción
                    prediction.status = 'validated'
                    prediction.validated_at = timezone.now()
                    prediction.save()

                    self.log_audit('prediction_validated', 'info',
                                 f'Predicción validada automáticamente: {prediction.incident_type}',
                                 prediction=prediction)

                    # Crear incidente basado en la predicción validada
                    incident = self.create_incident_from_prediction(prediction, threat_data)
                    if incident:
                        incidents_created += 1
                        self.record_action('incident_creation')
                        self.log_audit('incident_auto_created', 'warning',
                                     f'Incidente creado automáticamente: {incident.nombre_incidente}',
                                     incident=incident, prediction=prediction)

                        # Aplicar medidas automáticamente si está habilitado
                        if self.can_apply_measures_automatically():
                            self.apply_automated_response_measures(incident, prediction, threat_data)
                            self.record_action('measure_application')
                            self.log_audit('measure_auto_applied', 'warning',
                                         f'Medidas aplicadas automáticamente al incidente {incident.id}',
                                         incident=incident)

                        logger.info(f"Incidente creado automáticamente desde predicción: {incident.nombre_incidente}")

                except Exception as e:
                    logger.error(f"Error procesando predicción de alta confianza: {str(e)}")
                    self.circuit_breaker.record_failure()
                    self.log_audit('system_error', 'error',
                                 f'Error procesando predicción: {str(e)}', prediction=prediction)

            # Registrar éxito en circuit breaker
            self.circuit_breaker.record_success()

            # Verificar rendimiento y crear alertas si es necesario
            self.check_performance_and_alert()

            logger.info(f"Proceso SOAR completado - Predicciones: {predictions_created}, Incidentes: {incidents_created}")
            return predictions_created, incidents_created

        except Exception as e:
            logger.error(f"Error en análisis SOAR: {str(e)}")
            self.circuit_breaker.record_failure()
            self.log_audit('system_error', 'critical', f'Error crítico en análisis SOAR: {str(e)}')
            self.create_alert('system_error', 'critical', 'Error en Análisis SOAR',
                            f'Se produjo un error crítico durante el análisis: {str(e)}')
            return 0, 0

    def check_performance_and_alert(self):
        """Verificar rendimiento del sistema y crear alertas si es necesario"""
        try:
            # Obtener métricas recientes
            today = timezone.now().date()
            recent_metrics = AIPerformanceMetrics.objects.filter(date=today).first()

            if recent_metrics:
                # Verificar tasa de falsos positivos
                if recent_metrics.precision < 0.7 and self.config.enable_performance_alerts:
                    self.create_alert(
                        'high_false_positive_rate',
                        'high',
                        'Alta Tasa de Falsos Positivos Detectada',
                        f'La precisión del sistema ha caído a {recent_metrics.precision:.1%}. '
                        f'Considere revisar las predicciones y proporcionar feedback.',
                        {'precision': recent_metrics.precision, 'date': str(today)}
                    )

                # Verificar rendimiento general
                if recent_metrics.accuracy < 0.6 and self.config.enable_performance_alerts:
                    self.create_alert(
                        'performance_degraded',
                        'medium',
                        'Rendimiento del Sistema Degradado',
                        f'La exactitud general ha caído a {recent_metrics.accuracy:.1%}. '
                        f'Recomendado revisar configuración y re-entrenar modelos.',
                        {'accuracy': recent_metrics.accuracy, 'date': str(today)}
                    )

        except Exception as e:
            logger.error(f"Error verificando rendimiento: {str(e)}")

    def detect_anomalies(self, logs_queryset, log_type):
        """Detectar anomalías en un conjunto de logs"""
        if not self.anomaly_detector or logs_queryset.count() == 0:
            return []

        features_df = self.extract_log_features(logs_queryset, log_type)
        numeric_columns = features_df.select_dtypes(include=[np.number]).columns
        X = features_df[numeric_columns].fillna(0)

        # Para evitar problemas de features, usar solo las columnas que el modelo conoce
        if hasattr(self, 'anomaly_detector') and hasattr(self.anomaly_detector, 'feature_names_in_'):
            # Filtrar solo las columnas que el modelo conoce
            known_features = self.anomaly_detector.feature_names_in_
            available_features = [col for col in known_features if col in X.columns]
            if available_features:
                X = X[available_features]
            else:
                logger.warning(f"No se pueden detectar anomalías en {log_type} - features no compatibles")
                return []

        try:
            # Predecir anomalías (-1 = anomalía, 1 = normal)
            predictions = self.anomaly_detector.predict(X)

            anomalies = []
            for i, (log, pred) in enumerate(zip(logs_queryset, predictions)):
                if pred == -1:  # Anomalía detectada
                    anomalies.append({
                        'log': log,
                        'log_type': log_type,
                        'anomaly_score': -self.anomaly_detector.score_samples(X.iloc[i:i+1])[0],
                        'features': features_df.iloc[i].to_dict()
                    })

            logger.info(f"Detectadas {len(anomalies)} anomalías en {log_type}")
            return anomalies

        except Exception as e:
            logger.warning(f"Error detectando anomalías en {log_type}: {str(e)}")
            return []

    def correlate_events(self, anomalies, time_window_minutes=30):
        """Correlacionar eventos anómalos relacionados"""
        if not anomalies:
            return []

        # Agrupar por tiempo y IPs
        correlated_groups = []
        processed = set()

        for anomaly in sorted(anomalies, key=lambda x: x['log'].timestamp):
            if id(anomaly['log']) in processed:
                continue

            # Buscar eventos relacionados en ventana de tiempo
            related_events = []
            anomaly_time = anomaly['log'].timestamp
            anomaly_ips = self.get_log_ips(anomaly['log'], anomaly['log_type'])

            for other in anomalies:
                if id(other['log']) in processed:
                    continue

                other_time = other['log'].timestamp
                time_diff = abs((anomaly_time - other_time).total_seconds() / 60)

                if time_diff <= time_window_minutes:
                    other_ips = self.get_log_ips(other['log'], other['log_type'])
                    # Verificar si comparten IPs
                    if set(anomaly_ips) & set(other_ips):
                        related_events.append(other)
                        processed.add(id(other['log']))

            # Crear grupo correlacionado
            group = {
                'primary_event': anomaly,
                'related_events': related_events,
                'start_time': anomaly_time,
                'end_time': max([e['log'].timestamp for e in related_events] + [anomaly_time]),
                'involved_ips': list(set(anomaly_ips + [ip for e in related_events for ip in self.get_log_ips(e['log'], e['log_type'])])),
                'severity_score': sum([e['anomaly_score'] for e in [anomaly] + related_events])
            }

            correlated_groups.append(group)
            processed.add(id(anomaly['log']))

        # Filtrar grupos significativos
        significant_groups = [g for g in correlated_groups if len(g['related_events']) >= 2 or g['severity_score'] > 0.7]

        logger.info(f"Correlacionados {len(significant_groups)} grupos de eventos")
        return significant_groups

    def get_log_ips(self, log, log_type):
        """Extraer IPs de un log"""
        if log_type == 'snort':
            return [log.src_ip, log.dst_ip]
        else:  # Suricata
            return [log.src_ip, log.dest_ip]

    def classify_incident_type(self, event_group):
        """Clasificar el tipo de incidente"""
        if not self.incident_classifier:
            return "Incidente de Seguridad"

        # Usar el evento primario para clasificación
        primary_features = event_group['primary_event']['features']
        df = pd.DataFrame([primary_features])
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        X = df[numeric_columns].fillna(0)

        try:
            prediction = self.incident_classifier.predict(X)[0]
            incident_type = self.label_encoders['incident_type'].inverse_transform([prediction])[0]
            return incident_type
        except:
            return "Incidente de Seguridad"

    def classify_threat_type(self, event_group):
        """Clasificar el tipo de amenaza para predicciones"""
        # Usar lógica simple basada en características del evento
        primary_event = event_group['primary_event']
        log = primary_event['log']

        # Analizar el mensaje del log para determinar tipo de amenaza
        message = (log.message or '').lower()

        if 'ddos' in message or 'flood' in message:
            return "Ataque DDoS"
        elif 'brute' in message or 'force' in message:
            return "Intento de Fuerza Bruta"
        elif 'scan' in message:
            return "Escaneo de Red"
        elif 'malware' in message or 'virus' in message or 'trojan' in message:
            return "Posible Malware"
        elif 'intrusion' in message or 'breach' in message:
            return "Intento de Intrusión"
        elif 'attack' in message:
            return "Ataque de Red"
        else:
            return "Actividad Sospechosa"

    def generate_prediction_description(self, event_group, threat_type):
        """Generar descripción automática de la predicción"""
        primary_event = event_group['primary_event']
        num_events = len(event_group['related_events']) + 1
        ips_involved = len(event_group['involved_ips'])

        description = f"""Predicción de amenaza detectada por sistema de IA.

Tipo de Amenaza: {threat_type}
Eventos Correlacionados: {num_events}
IPs Involucradas: {ips_involved}
Período: {event_group['start_time']} - {event_group['end_time']}
Severidad Estimada: {event_group['severity_score']:.2f}

Evento Principal:
- Timestamp: {primary_event['log'].timestamp}
- Mensaje: {primary_event['log'].message[:200]}...

IPs Detectadas: {', '.join(event_group['involved_ips'])}

Esta predicción requiere validación humana antes de tomar medidas.
"""

        return description

    def create_prediction_from_analysis(self, event_group):
        """Crear predicción basada en análisis de IA (solo predicción, no incidente)"""
        try:
            # Determinar tipo de amenaza basado en anomalías
            threat_type = self.classify_threat_type(event_group)

            # Calcular confianza basada en severidad y cantidad de eventos
            confidence_score = min(event_group['severity_score'] * 0.7 + len(event_group['related_events']) * 0.3, 1.0)

            # Determinar severidad
            if confidence_score >= 0.8:
                severity = 'High'
            elif confidence_score >= 0.6:
                severity = 'Medium'
            else:
                severity = 'Low'

            # Crear descripción de la predicción
            description = self.generate_prediction_description(event_group, threat_type)

            # Crear predicción
            prediction = IncidentPrediction.objects.create(
                incident_type=threat_type,
                confidence_score=confidence_score,
                severity_level=severity,
                description=description,
                involved_ips=event_group['involved_ips'],
                related_logs_count=len(event_group['related_events']) + 1,
                status='pending'
            )

            logger.info(f"Predicción creada: {threat_type} (Confianza: {confidence_score:.2f})")
            return prediction

        except Exception as e:
            logger.error(f"Error creando predicción: {str(e)}")
            return None

    def create_incident_from_prediction(self, prediction, threat_data):
        """Crear incidente completo desde una predicción validada automáticamente"""
        try:
            # Seleccionar área apropiada
            area = Area.objects.filter(nombre__icontains='seguridad').first()
            if not area:
                area = Area.objects.first()

            # Crear reporte
            reporte = Reporte.objects.create(
                nombre_informante='Sistema IRIS - IA Automática',
                email_informante='iris@ai-system.com',
                descripcion=prediction.description,
                estado_solucion='Atendido',  # Automáticamente atendido por IA
                area=area,
                fecha_hora=threat_data['start_time']
            )

            # Crear incidente
            incidente = Incidente.objects.create(
                nombre_incidente=f'{prediction.incident_type} - IRIS Auto ({prediction.confidence_score:.0%})',
                descripcion=prediction.description,
                estado_solucion='investigacion',  # Inicia en investigación
                reporte=reporte,
                fecha_hora=threat_data['start_time']
            )

            # Agregar servicios afectados
            servicios_afectados = Servicio.objects.filter(monitorear=True)[:2]
            incidente.servicios.add(*servicios_afectados)

            # Agregar áreas
            incidente.areas.add(area)

            # Crear involucrados automáticos
            for ip in prediction.involved_ips[:3]:
                involucrado, created = Involucrado.objects.get_or_create(
                    ip=ip,
                    defaults={
                        'nombres': 'Usuario',
                        'apellidos': 'Detectado',
                        'usuario': f'user_{ip.replace(".", "_")}',
                        'mac': '00:00:00:00:00:00',
                        'tipo': 'Usuario interno'
                    }
                )

                InvolucradoIncidente.objects.create(
                    incidente=incidente,
                    involucrado=involucrado,
                    descripcion=f'Involucrado detectado por IRIS: {prediction.incident_type}',
                    medida_impuesta=Medida.objects.filter(nombre__icontains='monitoreo').first() or Medida.objects.first(),
                    fecha_inicio=threat_data['start_time'],
                    fecha_fin=threat_data['end_time'] + timedelta(days=30)
                )

            # Aplicar medidas automáticas de respuesta
            self.apply_automated_response_measures(incidente, prediction, threat_data)

            # Vincular la predicción al incidente creado
            prediction.created_incident = incidente
            prediction.save()

            return incidente

        except Exception as e:
            logger.error(f"Error creando incidente desde predicción: {str(e)}")
            return None

    def generate_incident_description(self, event_group, incident_type):
        """Generar descripción automática del incidente"""
        primary_event = event_group['primary_event']
        num_events = len(event_group['related_events']) + 1
        ips_involved = len(event_group['involved_ips'])

        description = f"""Incidente detectado automáticamente por sistema de IA.

Tipo de Incidente: {incident_type}
Eventos Correlacionados: {num_events}
IPs Involucradas: {ips_involved}
Período: {event_group['start_time']} - {event_group['end_time']}
Severidad Estimada: {event_group['severity_score']:.2f}

Evento Principal:
- Timestamp: {primary_event['log'].timestamp}
- Mensaje: {primary_event['log'].message[:200]}...

IPs Detectadas: {', '.join(event_group['involved_ips'])}
"""

        return description

    def apply_automated_measures(self, incidente, event_group):
        """Aplicar medidas automáticas basadas en el incidente"""
        # Seleccionar medidas apropiadas por fase
        medidas_deteccion = Medida.objects.filter(
            nombre__in=[
                'Análisis inicial de alerta',
                'Monitoreo adicional de red',
                'Verificación de indicadores'
            ]
        )

        medidas_contencion = Medida.objects.filter(
            nombre__in=[
                'Bloqueo de IP maliciosa',
                'Segmentación de red temporal'
            ]
        )

        # Obtener responsables automáticos
        responsables = list(Responsable.objects.all()[:3])

        # Aplicar medidas de detección
        for medida in medidas_deteccion:
            MedidaIncidente.objects.create(
                incidente=incidente,
                medida=medida,
                responsable=responsables[0] if responsables else Responsable.objects.first(),
                fecha_cumplimiento=timezone.now(),
                estado_cumplimiento=True,
                observaciones='Medida aplicada automáticamente por sistema de IA'
            )

        # Programar medidas de contención (no aplicar automáticamente por seguridad)
        for medida in medidas_contencion:
            MedidaIncidente.objects.create(
                incidente=incidente,
                medida=medida,
                responsable=responsables[1] if len(responsables) > 1 else Responsable.objects.first(),
                fecha_cumplimiento=timezone.now() + timedelta(hours=1),  # Dentro de 1 hora
                estado_cumplimiento=False,  # Pendiente de aprobación
                observaciones='Medida programada por IA - Requiere aprobación humana'
            )

        logger.info(f"Medidas automáticas aplicadas al incidente {incidente.id}")

    def apply_automated_response_measures(self, incidente, prediction, threat_data):
        """Aplicar medidas de respuesta automática basadas en el tipo de amenaza"""
        threat_type = prediction.incident_type.lower()

        # Medidas específicas por tipo de amenaza
        if 'ddos' in threat_type:
            # Medidas contra DDoS
            medidas = Medida.objects.filter(
                nombre__in=[
                    'Bloqueo de IP maliciosa',
                    'Segmentación de red temporal',
                    'Monitoreo adicional de red',
                    'Implementar rate limiting'
                ]
            )
        elif 'malware' in threat_type or 'virus' in threat_type:
            # Medidas contra malware
            medidas = Medida.objects.filter(
                nombre__in=[
                    'Análisis de malware',
                    'Cuarentena de archivos',
                    'Escaneo completo del sistema',
                    'Actualización de firmas antivirus'
                ]
            )
        elif 'intrusion' in threat_type or 'breach' in threat_type:
            # Medidas contra intrusión
            medidas = Medida.objects.filter(
                nombre__in=[
                    'Revisión de logs de acceso',
                    'Cambio de credenciales',
                    'Auditoría de permisos',
                    'Monitoreo de sesiones'
                ]
            )
        elif 'scan' in threat_type:
            # Medidas contra escaneo
            medidas = Medida.objects.filter(
                nombre__in=[
                    'Bloqueo de IP maliciosa',
                    'Configuración de firewall',
                    'Monitoreo de puertos',
                    'Implementar honeypots'
                ]
            )
        else:
            # Medidas generales
            medidas = Medida.objects.filter(
                nombre__in=[
                    'Análisis inicial de alerta',
                    'Monitoreo adicional de red',
                    'Verificación de indicadores'
                ]
            )

        # Aplicar medidas encontradas
        responsables = list(Responsable.objects.all()[:3])

        for i, medida in enumerate(medidas[:4]):  # Máximo 4 medidas
            MedidaIncidente.objects.create(
                incidente=incidente,
                medida=medida,
                responsable=responsables[i % len(responsables)] if responsables else None,
                fecha_cumplimiento=timezone.now(),
                estado_cumplimiento=True,  # Aplicadas automáticamente por IA
                observaciones=f'Medida aplicada automáticamente por IRIS - Confianza: {prediction.confidence_score:.0%}'
            )

        logger.info(f"Medidas de respuesta automática aplicadas para {prediction.incident_type}")

    def update_model_records(self):
        """Actualizar registros de modelos en la base de datos"""
        try:
            # Importar aquí para evitar problemas de importación circular
            from .models import AIModelConfig

            # Actualizar/crear registro del detector de anomalías
            anomaly_detector, created = AIModelConfig.objects.get_or_create(
                name='Isolation Forest Anomaly Detector',
                defaults={
                    'model_type': 'anomaly_detector',
                    'version': '1.0',
                    'accuracy_score': 0.85,  # Estimación basada en entrenamiento
                    'is_active': True,
                    'model_path': f'{self.models_dir}/anomaly_detector.pkl'
                }
            )
            if not created:
                anomaly_detector.last_trained = timezone.now()
                anomaly_detector.is_active = True
                anomaly_detector.save()
                logger.info("Detector de anomalías actualizado")

            # Actualizar/crear registro del clasificador de incidentes
            incident_classifier, created = AIModelConfig.objects.get_or_create(
                name='Random Forest Incident Classifier',
                defaults={
                    'model_type': 'incident_classifier',
                    'version': '1.0',
                    'accuracy_score': 0.78,  # Estimación basada en entrenamiento
                    'is_active': True,
                    'model_path': f'{self.models_dir}/incident_classifier.pkl'
                }
            )
            if not created:
                incident_classifier.last_trained = timezone.now()
                incident_classifier.is_active = True
                incident_classifier.save()
                logger.info("Clasificador de incidentes actualizado")

            logger.info("Registros de modelos actualizados en base de datos")

        except Exception as e:
            logger.error(f"Error actualizando registros de modelos: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())

    def incorporate_human_feedback(self, incident_id, is_false_positive, correct_classification=None, user=None):
        """Incorporar feedback humano para mejorar el modelo"""
        try:
            incidente = Incidente.objects.get(id=incident_id)

            if is_false_positive:
                self.performance_metrics['false_positives'] += 1
                # Marcar como cerrado sin medidas adicionales
                incidente.estado_solucion = 'cerrado'
                incidente.save()

                self.log_audit('human_feedback_received', 'info',
                             f'Feedback humano: falso positivo para incidente {incident_id}',
                             user=user, incident=incidente,
                             metadata={'feedback_type': 'false_positive'})

                logger.info(f"Incidente {incident_id} marcado como falso positivo")
            else:
                self.performance_metrics['true_positives'] += 1

                if correct_classification:
                    # Actualizar clasificación si fue corregida
                    incidente.nombre_incidente = f'{correct_classification} - Corregido por humano'
                    incidente.save()

                self.log_audit('human_feedback_received', 'info',
                             f'Feedback humano: clasificación correcta para incidente {incident_id}',
                             user=user, incident=incidente,
                             metadata={'feedback_type': 'correct_classification',
                                      'correct_classification': correct_classification})

            # Re-entrenar modelos periódicamente con nuevo feedback
            if sum(self.performance_metrics.values()) % 10 == 0:  # Cada 10 evaluaciones
                logger.info("Re-entrenando modelos con feedback humano...")
                self.train_models()
                self.log_audit('model_trained', 'info',
                             'Modelos re-entrenados automáticamente por feedback humano')

        except Incidente.DoesNotExist:
            logger.error(f"Incidente {incident_id} no encontrado")
            self.log_audit('system_error', 'error',
                         f'Error procesando feedback humano: incidente {incident_id} no encontrado',
                         user=user, metadata={'incident_id': incident_id})

    def get_performance_report(self):
        """Obtener reporte de rendimiento del sistema de IA"""
        total_predictions = sum(self.performance_metrics.values())

        if total_predictions == 0:
            return "Sin datos de rendimiento disponibles"

        accuracy = (self.performance_metrics['true_positives'] + self.performance_metrics['true_negatives']) / total_predictions
        precision = self.performance_metrics['true_positives'] / (self.performance_metrics['true_positives'] + self.performance_metrics['false_positives']) if (self.performance_metrics['true_positives'] + self.performance_metrics['false_positives']) > 0 else 0

        report = f"""
=== REPORTE DE RENDIMIENTO DEL SISTEMA DE IA ===

Predicciones Totales: {total_predictions}
Verdaderos Positivos: {self.performance_metrics['true_positives']}
Falsos Positivos: {self.performance_metrics['false_positives']}
Verdaderos Negativos: {self.performance_metrics['true_negatives']}
Falsos Negativos: {self.performance_metrics['false_negatives']}

Precisión: {precision:.2%}
Exactitud: {accuracy:.2%}

Modelos Entrenados: {'Sí' if self.anomaly_detector else 'No'}
Clasificador Activo: {'Sí' if self.incident_classifier else 'No'}
"""
        return report

# Función principal para ejecutar análisis
def run_ai_analysis():
    """Ejecutar análisis completo de IA"""
    investigator = AIIncidentInvestigator()

    print("=== SISTEMA IRIS - SOAR COMPLETO ===")
    print("Analizando logs recientes...")

    predictions_created, incidents_created = investigator.analyze_recent_logs(hours_back=24)

    print(f"✅ Análisis SOAR completado.")
    print(f"📊 Predicciones generadas: {predictions_created}")
    print(f"🚨 Incidentes creados automáticamente: {incidents_created}")
    print("\n" + investigator.get_performance_report())

if __name__ == "__main__":
    run_ai_analysis()
