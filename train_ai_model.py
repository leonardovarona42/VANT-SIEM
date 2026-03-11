#!/usr/bin/env python3
"""
Script avanzado para entrenar el modelo de IA de IRIS usando datos históricos completos
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
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import joblib
import logging

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from opensearch_ui.models import SnortLog, SuricataEveAlert
from EVENT_M.models import Reporte, Incidente, Involucrado, Medida, MedidaIncidente, InvolucradoIncidente
from django.utils import timezone
from django.db.models import Count, Q, Avg, Max, Min

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AdvancedAIInvestigator:
    """
    Sistema avanzado de IA para investigación automática usando datos históricos completos
    """

    def __init__(self):
        self.models_dir = 'ai_models'
        os.makedirs(self.models_dir, exist_ok=True)

        # Modelos avanzados
        self.anomaly_detector = None
        self.incident_classifier = None
        self.threat_predictor = None
        self.risk_assessor = None

        # Codificadores y escaladores
        self.label_encoders = {}
        self.scalers = {}

        # Estadísticas de rendimiento
        self.performance_stats = {
            'anomaly_detection': {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0},
            'incident_classification': {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0},
            'threat_prediction': {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0}
        }

        # Cargar o entrenar modelos
        self.load_or_train_models()

    def load_or_train_models(self):
        """Cargar modelos existentes o entrenar nuevos con datos históricos"""
        try:
            logger.info("Intentando cargar modelos existentes...")
            self.anomaly_detector = joblib.load(f'{self.models_dir}/anomaly_detector.pkl')
            self.incident_classifier = joblib.load(f'{self.models_dir}/incident_classifier.pkl')
            self.threat_predictor = joblib.load(f'{self.models_dir}/threat_predictor.pkl')
            self.risk_assessor = joblib.load(f'{self.models_dir}/risk_assessor.pkl')
            self.label_encoders = joblib.load(f'{self.models_dir}/label_encoders.pkl')
            self.scalers = joblib.load(f'{self.models_dir}/scalers.pkl')
            logger.info("✅ Modelos cargados exitosamente")
        except FileNotFoundError:
            logger.info("🔄 Modelos no encontrados, entrenando nuevos con datos históricos...")
            self.train_all_models()

    def extract_comprehensive_features(self, logs_queryset, log_type='snort'):
        """Extraer características comprehensivas incluyendo datos históricos"""
        features = []

        # Obtener estadísticas globales para contextualizar
        global_stats = self.get_global_statistics()

        for log in logs_queryset:
            if log_type == 'snort':
                base_features = {
                    # Características temporales
                    'timestamp_hour': log.timestamp.hour,
                    'timestamp_day': log.timestamp.weekday(),
                    'timestamp_month': log.timestamp.month,
                    'is_weekend': 1 if log.timestamp.weekday() >= 5 else 0,
                    'is_business_hours': 1 if 9 <= log.timestamp.hour <= 17 else 0,

                    # Características de red
                    'src_port': log.src_port or 0,
                    'dst_port': log.dst_port or 0,
                    'protocol_hash': hash(log.protocol or '') % 1000,

                    # Severidad y prioridad
                    'severity': log.severity or 0,
                    'priority': log.priority or 0,
                    'gid': log.gid or 0,
                    'sid': log.sid or 0,

                    # IPs numéricas
                    'src_ip_numeric': self.ip_to_int(log.src_ip),
                    'dst_ip_numeric': self.ip_to_int(log.dst_ip),

                    # Características de contenido
                    'message_length': len(log.message or ''),
                    'has_critical_keywords': self.has_critical_keywords(log.message or ''),
                    'has_attack_keywords': self.has_attack_keywords(log.message or ''),
                    'has_malware_keywords': self.has_malware_keywords(log.message or ''),
                }
            else:  # Suricata
                base_features = {
                    # Características temporales
                    'timestamp_hour': log.timestamp.hour,
                    'timestamp_day': log.timestamp.weekday(),
                    'timestamp_month': log.timestamp.month,
                    'is_weekend': 1 if log.timestamp.weekday() >= 5 else 0,
                    'is_business_hours': 1 if 9 <= log.timestamp.hour <= 17 else 0,

                    # Características de red
                    'src_port': log.src_port or 0,
                    'dest_port': log.dest_port or 0,
                    'proto_hash': hash(log.proto or '') % 1000,

                    # Severidad
                    'severity': log.severity or 1,
                    'signature_id': log.signature_id or 0,

                    # IPs numéricas
                    'src_ip_numeric': self.ip_to_int(log.src_ip),
                    'dst_ip_numeric': self.ip_to_int(log.dest_ip),

                    # Características de contenido
                    'message_length': len(log.message or ''),
                    'has_critical_keywords': self.has_critical_keywords(log.message or ''),
                    'has_attack_keywords': self.has_attack_keywords(log.message or ''),
                    'has_malware_keywords': self.has_malware_keywords(log.message or ''),
                }

            # Agregar características contextuales basadas en datos históricos
            contextual_features = self.add_contextual_features(base_features, log, log_type, global_stats)
            features.append({**base_features, **contextual_features})

        return pd.DataFrame(features)

    def get_global_statistics(self):
        """Obtener estadísticas globales de los datos históricos"""
        stats = {}

        # Estadísticas de IPs
        snort_ips = SnortLog.objects.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')
        suricata_ips = SuricataEveAlert.objects.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')

        stats['top_snort_ips'] = {ip['src_ip']: ip['count'] for ip in snort_ips[:20]}
        stats['top_suricata_ips'] = {ip['src_ip']: ip['count'] for ip in suricata_ips[:20]}

        # Estadísticas de puertos
        stats['common_src_ports'] = list(SnortLog.objects.values('src_port').annotate(count=Count('src_port')).order_by('-count')[:10])
        stats['common_dst_ports'] = list(SnortLog.objects.values('dst_port').annotate(count=Count('dst_port')).order_by('-count')[:10])

        # Estadísticas de incidentes
        incident_stats = Incidente.objects.values('estado_solucion').annotate(count=Count('estado_solucion'))
        stats['incident_states'] = {stat['estado_solucion']: stat['count'] for stat in incident_stats}

        # Estadísticas de medidas aplicadas
        measure_stats = MedidaIncidente.objects.values('medida__nombre').annotate(count=Count('medida__nombre'))
        stats['applied_measures'] = {stat['medida__nombre']: stat['count'] for stat in measure_stats}

        return stats

    def add_contextual_features(self, base_features, log, log_type, global_stats):
        """Agregar características contextuales basadas en el historial"""
        contextual = {}

        # Frecuencia de IP en datos históricos
        if log_type == 'snort':
            ip_key = log.src_ip
        else:
            ip_key = log.src_ip

        contextual['src_ip_frequency_snort'] = global_stats['top_snort_ips'].get(ip_key, 0)
        contextual['src_ip_frequency_suricata'] = global_stats['top_suricata_ips'].get(ip_key, 0)
        contextual['src_ip_total_frequency'] = contextual['src_ip_frequency_snort'] + contextual['src_ip_frequency_suricata']

        # Puerto común
        if log_type == 'snort':
            port_key = log.src_port
            contextual['src_port_common'] = any(p['src_port'] == port_key for p in global_stats['common_src_ports'])
            contextual['dst_port_common'] = any(p['dst_port'] == log.dst_port for p in global_stats['common_dst_ports'])
        else:
            port_key = log.src_port
            contextual['src_port_common'] = any(p['src_port'] == port_key for p in global_stats['common_src_ports'])
            contextual['dst_port_common'] = any(p['dest_port'] == log.dest_port for p in global_stats['common_dst_ports'])

        # Hora del día vs patrones históricos
        hour = base_features['timestamp_hour']
        contextual['is_peak_hour'] = 1 if hour in [9, 10, 11, 14, 15, 16] else 0
        contextual['is_off_hour'] = 1 if hour in [2, 3, 4, 5, 6] else 0

        # Convertir booleanos a numéricos
        for key in contextual:
            if isinstance(contextual[key], bool):
                contextual[key] = 1 if contextual[key] else 0

        return contextual

    def ip_to_int(self, ip_str):
        """Convertir IP a representación numérica"""
        try:
            parts = ip_str.split('.')
            return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + int(parts[2]) * 256 + int(parts[3])
        except:
            return 0

    def has_critical_keywords(self, message):
        """Verificar palabras clave críticas"""
        critical_words = [
            'attack', 'exploit', 'malware', 'virus', 'trojan', 'ransomware',
            'brute', 'force', 'scan', 'intrusion', 'breach', 'compromise',
            'suspicious', 'anomaly', 'threat', 'alert', 'critical', 'danger'
        ]
        message_lower = message.lower()
        return 1 if any(word in message_lower for word in critical_words) else 0

    def has_attack_keywords(self, message):
        """Verificar palabras clave de ataque"""
        attack_words = [
            'attack', 'exploit', 'brute', 'force', 'scan', 'intrusion',
            'breach', 'compromise', 'hack', 'exploit', 'injection', 'overflow'
        ]
        message_lower = message.lower()
        return 1 if any(word in message_lower for word in attack_words) else 0

    def has_malware_keywords(self, message):
        """Verificar palabras clave de malware"""
        malware_words = [
            'malware', 'virus', 'trojan', 'ransomware', 'worm', 'spyware',
            'backdoor', 'rootkit', 'keylogger', 'botnet', 'c2', 'command'
        ]
        message_lower = message.lower()
        return 1 if any(word in message_lower for word in malware_words) else 0

    def train_anomaly_detector(self):
        """Entrenar detector de anomalías avanzado"""
        logger.info("Entrenando detector de anomalias avanzado...")

        # Obtener logs históricos (últimos 6 meses)
        since_date = timezone.now() - timedelta(days=180)

        snort_logs = SnortLog.objects.filter(timestamp__gte=since_date)[:50000]
        suricata_alerts = SuricataEveAlert.objects.filter(timestamp__gte=since_date)[:50000]

        if snort_logs.count() < 1000:
            logger.warning("⚠️ Insuficientes datos de Snort para entrenar detector de anomalías")
            return

        logger.info(f"📊 Usando {snort_logs.count()} logs Snort y {suricata_alerts.count()} alertas Suricata")

        # Extraer características comprehensivas
        snort_features = self.extract_comprehensive_features(snort_logs, 'snort')
        suricata_features = self.extract_comprehensive_features(suricata_alerts, 'suricata')

        # Combinar datasets
        all_features = pd.concat([snort_features, suricata_features], ignore_index=True)

        # Seleccionar columnas numéricas
        numeric_columns = all_features.select_dtypes(include=[np.number]).columns
        X = all_features[numeric_columns].fillna(0)

        # Escalar características
        self.scalers['anomaly_detector'] = StandardScaler()
        X_scaled = self.scalers['anomaly_detector'].fit_transform(X)

        # Entrenar Isolation Forest avanzado
        self.anomaly_detector = IsolationForest(
            contamination=0.05,  # 5% de anomalías esperadas (más conservador)
            random_state=42,
            n_estimators=200,    # Más árboles para mejor precisión
            max_samples=0.8,     # Usar 80% de los datos por árbol
            max_features=0.8     # Usar 80% de las características
        )

        self.anomaly_detector.fit(X_scaled)

        # Guardar modelo y scaler
        joblib.dump(self.anomaly_detector, f'{self.models_dir}/anomaly_detector.pkl')
        logger.info("✅ Detector de anomalías avanzado entrenado y guardado")

    def train_incident_classifier(self):
        """Entrenar clasificador de incidentes usando datos históricos"""
        logger.info("🎯 Entrenando clasificador de incidentes avanzado...")

        # Obtener incidentes con datos históricos completos
        incidentes = Incidente.objects.filter(
            fecha_hora__gte=timezone.now() - timedelta(days=365)
        ).select_related('reporte').prefetch_related('involucradoincidente_set__involucrado')

        if incidentes.count() < 20:
            logger.warning("⚠️ Insuficientes incidentes históricos para entrenar clasificador")
            return

        logger.info(f"📊 Entrenando con {incidentes.count()} incidentes históricos")

        training_data = []
        labels = []

        for incidente in incidentes:
            # Obtener logs relacionados con el incidente
            involucrados = incidente.involucradoincidente_set.all()
            ips_involucrados = [inv.involucrado.ip for inv in involucrados if inv.involucrado.ip]

            if not ips_involucrados:
                continue

            # Buscar logs relacionados por IP y tiempo
            related_snort = SnortLog.objects.filter(
                Q(src_ip__in=ips_involucrados) | Q(dst_ip__in=ips_involucrados),
                timestamp__range=(
                    incidente.fecha_hora - timedelta(hours=2),
                    incidente.fecha_hora + timedelta(days=1)
                )
            )[:30]

            related_suricata = SuricataEveAlert.objects.filter(
                Q(src_ip__in=ips_involucrados) | Q(dest_ip__in=ips_involucrados),
                timestamp__range=(
                    incidente.fecha_hora - timedelta(hours=2),
                    incidente.fecha_hora + timedelta(days=1)
                )
            )[:30]

            # Procesar logs de Snort
            for log in related_snort:
                features = self.extract_comprehensive_features([log], 'snort').iloc[0].to_dict()
                training_data.append(features)

                # Etiqueta basada en subcategorías o tipo de incidente
                subcats = incidente.subcategorias.all()
                if subcats.exists():
                    label = subcats.first().nombre
                else:
                    # Clasificar basado en el nombre del incidente
                    incident_name = incidente.nombre_incidente.lower()
                    if 'malware' in incident_name or 'virus' in incident_name:
                        label = 'Malware'
                    elif 'ataque' in incident_name or 'attack' in incident_name:
                        label = 'Ataque de Red'
                    elif 'intrusion' in incident_name:
                        label = 'Intrusión'
                    elif 'ddos' in incident_name:
                        label = 'DDoS'
                    else:
                        label = 'Incidente General'

                labels.append(label)

            # Procesar alertas de Suricata
            for alert in related_suricata:
                features = self.extract_comprehensive_features([alert], 'suricata').iloc[0].to_dict()
                training_data.append(features)
                labels.append(label)  # Usar la misma etiqueta

        if len(training_data) < 100:
            logger.warning("⚠️ Insuficientes datos de entrenamiento")
            return

        # Preparar datos
        df = pd.DataFrame(training_data)
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        X = df[numeric_columns].fillna(0)

        # Escalar características
        self.scalers['incident_classifier'] = StandardScaler()
        X_scaled = self.scalers['incident_classifier'].fit_transform(X)

        # Codificar etiquetas
        self.label_encoders['incident_type'] = LabelEncoder()
        y = self.label_encoders['incident_type'].fit_transform(labels)

        # Balancear clases si es necesario
        unique_labels, counts = np.unique(y, return_counts=True)
        min_samples = min(counts)

        if min_samples < 5:
            logger.warning("⚠️ Algunas clases tienen muy pocos ejemplos, resultados pueden ser sesgados")

        # Dividir datos
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        # Entrenar clasificador avanzado
        self.incident_classifier = RandomForestClassifier(
            n_estimators=150,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced',
            n_jobs=-1  # Usar todos los cores disponibles
        )

        self.incident_classifier.fit(X_train, y_train)

        # Evaluar rendimiento
        y_pred = self.incident_classifier.predict(X_test)

        # Calcular métricas
        self.performance_stats['incident_classification']['accuracy'] = accuracy_score(y_test, y_pred)
        self.performance_stats['incident_classification']['precision'] = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        self.performance_stats['incident_classification']['recall'] = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        self.performance_stats['incident_classification']['f1'] = f1_score(y_test, y_pred, average='weighted', zero_division=0)

        logger.info("📈 Reporte de clasificación de incidentes:")
        logger.info(classification_report(y_test, y_pred,
                                        target_names=self.label_encoders['incident_type'].classes_,
                                        zero_division=0))

        # Guardar modelo y componentes
        joblib.dump(self.incident_classifier, f'{self.models_dir}/incident_classifier.pkl')
        logger.info("✅ Clasificador de incidentes avanzado entrenado y guardado")

    def train_threat_predictor(self):
        """Entrenar predictor de amenazas basado en patrones históricos"""
        logger.info("🔮 Entrenando predictor de amenazas...")

        # Usar datos de medidas aplicadas para predecir amenazas futuras
        medidas_aplicadas = MedidaIncidente.objects.filter(
            fecha_cumplimiento__gte=timezone.now() - timedelta(days=180)
        ).select_related('incidente', 'medida')

        if medidas_aplicadas.count() < 50:
            logger.warning("⚠️ Insuficientes medidas aplicadas para entrenar predictor de amenazas")
            return

        training_data = []
        threat_labels = []

        for medida in medidas_aplicadas:
            incidente = medida.incidente

            # Obtener logs relacionados con el incidente
            involucrados = incidente.involucradoincidente_set.all()
            ips_involucrados = [inv.involucrado.ip for inv in involucrados if inv.involucrado.ip]

            if not ips_involucrados:
                continue

            # Buscar logs previos al incidente (ventana de predicción)
            prediction_window_start = incidente.fecha_hora - timedelta(hours=24)
            prediction_window_end = incidente.fecha_hora - timedelta(hours=1)

            related_logs = SnortLog.objects.filter(
                Q(src_ip__in=ips_involucrados) | Q(dst_ip__in=ips_involucrados),
                timestamp__range=(prediction_window_start, prediction_window_end)
            )[:20]

            if related_logs.exists():
                # Agregar características de todos los logs relacionados
                for log in related_logs:
                    features = self.extract_comprehensive_features([log], 'snort').iloc[0].to_dict()
                    features['hours_to_incident'] = (incidente.fecha_hora - log.timestamp).total_seconds() / 3600
                    training_data.append(features)

                    # Etiqueta basada en la medida aplicada
                    medida_nombre = medida.medida.nombre.lower()
                    if 'bloqueo' in medida_nombre or 'block' in medida_nombre:
                        threat_level = 'high'
                    elif 'monitoreo' in medida_nombre or 'monitor' in medida_nombre:
                        threat_level = 'medium'
                    else:
                        threat_level = 'low'

                    threat_labels.append(threat_level)

        if len(training_data) < 50:
            logger.warning("⚠️ Insuficientes datos para predictor de amenazas")
            return

        # Preparar datos
        df = pd.DataFrame(training_data)
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        X = df[numeric_columns].fillna(0)

        # Escalar
        self.scalers['threat_predictor'] = StandardScaler()
        X_scaled = self.scalers['threat_predictor'].fit_transform(X)

        # Codificar etiquetas
        self.label_encoders['threat_level'] = LabelEncoder()
        y = self.label_encoders['threat_level'].fit_transform(threat_labels)

        # Dividir datos
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        # Entrenar predictor
        self.threat_predictor = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42,
            class_weight='balanced'
        )

        self.threat_predictor.fit(X_train, y_train)

        # Evaluar
        y_pred = self.threat_predictor.predict(X_test)
        self.performance_stats['threat_prediction']['accuracy'] = accuracy_score(y_test, y_pred)
        self.performance_stats['threat_prediction']['precision'] = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        self.performance_stats['threat_prediction']['recall'] = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        self.performance_stats['threat_prediction']['f1'] = f1_score(y_test, y_pred, average='weighted', zero_division=0)

        logger.info("🎯 Reporte de predicción de amenazas:")
        logger.info(classification_report(y_test, y_pred,
                                        target_names=self.label_encoders['threat_level'].classes_,
                                        zero_division=0))

        # Guardar modelo
        joblib.dump(self.threat_predictor, f'{self.models_dir}/threat_predictor.pkl')
        logger.info("✅ Predictor de amenazas entrenado y guardado")

    def train_risk_assessor(self):
        """Entrenar evaluador de riesgo basado en patrones históricos"""
        logger.info("⚠️ Entrenando evaluador de riesgo...")

        # Usar frecuencia de IPs y patrones para evaluar riesgo
        ip_risks = {}

        # Calcular riesgo basado en frecuencia y tipos de incidentes
        all_incidentes = Incidente.objects.filter(
            fecha_hora__gte=timezone.now() - timedelta(days=365)
        ).prefetch_related('involucradoincidente_set__involucrado')

        for incidente in all_incidentes:
            for inv_inc in incidente.involucradoincidente_set.all():
                ip = inv_inc.involucrado.ip
                if ip:
                    if ip not in ip_risks:
                        ip_risks[ip] = {'incidents': 0, 'severity_sum': 0, 'last_incident': None}

                    ip_risks[ip]['incidents'] += 1
                    # Estimar severidad basada en medidas aplicadas
                    medidas_criticas = ['Bloqueo de IP', 'Segmentación de red', 'Aislamiento']
                    severity = 3 if any(m in str(inv_inc.medida_impuesta) for m in medidas_criticas) else 1
                    ip_risks[ip]['severity_sum'] += severity

                    if not ip_risks[ip]['last_incident'] or incidente.fecha_hora > ip_risks[ip]['last_incident']:
                        ip_risks[ip]['last_incident'] = incidente.fecha_hora

        # Crear dataset de evaluación de riesgo
        risk_data = []
        for ip, risk_info in ip_risks.items():
            # Obtener estadísticas de logs para esta IP
            snort_count = SnortLog.objects.filter(
                Q(src_ip=ip) | Q(dst_ip=ip),
                timestamp__gte=timezone.now() - timedelta(days=30)
            ).count()

            suricata_count = SuricataEveAlert.objects.filter(
                Q(src_ip=ip) | Q(dest_ip=ip),
                timestamp__gte=timezone.now() - timedelta(days=30)
            ).count()

            # Calcular puntuación de riesgo
            base_risk = min(risk_info['incidents'] * 2 + risk_info['severity_sum'], 10)
            activity_risk = min((snort_count + suricata_count) / 100, 5)
            total_risk = base_risk + activity_risk

            risk_data.append({
                'ip_numeric': self.ip_to_int(ip),
                'incident_count': risk_info['incidents'],
                'severity_sum': risk_info['severity_sum'],
                'snort_activity': snort_count,
                'suricata_activity': suricata_count,
                'days_since_last_incident': (timezone.now() - risk_info['last_incident']).days if risk_info['last_incident'] else 365,
                'risk_score': total_risk
            })

        if len(risk_data) < 10:
            logger.warning("⚠️ Insuficientes datos para evaluador de riesgo")
            return

        # Preparar datos para modelo de regresión
        df = pd.DataFrame(risk_data)
        X = df.drop('risk_score', axis=1)
        y = df['risk_score']

        # Escalar
        self.scalers['risk_assessor'] = StandardScaler()
        X_scaled = self.scalers['risk_assessor'].fit_transform(X)

        # Entrenar modelo simple de regresión (podría mejorarse con algoritmos más avanzados)
        from sklearn.ensemble import RandomForestRegressor
        self.risk_assessor = RandomForestRegressor(
            n_estimators=50,
            random_state=42
        )

        self.risk_assessor.fit(X_scaled, y)

        # Guardar modelo
        joblib.dump(self.risk_assessor, f'{self.models_dir}/risk_assessor.pkl')
        logger.info("✅ Evaluador de riesgo entrenado y guardado")

    def train_all_models(self):
        """Entrenar todos los modelos avanzados"""
        logger.info("🤖 Iniciando entrenamiento completo del sistema de IA IRIS")

        try:
            self.train_anomaly_detector()
            self.train_incident_classifier()
            self.train_threat_predictor()
            self.train_risk_assessor()

            # Guardar codificadores y escaladores
            joblib.dump(self.label_encoders, f'{self.models_dir}/label_encoders.pkl')
            joblib.dump(self.scalers, f'{self.models_dir}/scalers.pkl')

            logger.info("🎉 ¡Entrenamiento completo exitoso!")
            self.print_training_summary()

        except Exception as e:
            logger.error(f"❌ Error durante el entrenamiento: {str(e)}")
            raise

    def print_training_summary(self):
        """Imprimir resumen del entrenamiento"""
        print("\n" + "="*60)
        print("📊 RESUMEN DEL ENTRENAMIENTO DE IA IRIS")
        print("="*60)

        print("\n🔍 DETECTOR DE ANOMALÍAS:")
        print(f"   Estado: {'✅ Entrenado' if self.anomaly_detector else '❌ No entrenado'}")
        if self.anomaly_detector:
            print("   Características: Detección avanzada con Isolation Forest")
            print("   Dataset: Logs históricos de Snort + Suricata")

        print("\n🎯 CLASIFICADOR DE INCIDENTES:")
        print(f"   Estado: {'✅ Entrenado' if self.incident_classifier else '❌ No entrenado'}")
        if self.incident_classifier and 'incident_classification' in self.performance_stats:
            stats = self.performance_stats['incident_classification']
            print(f"   Precisión: {stats['accuracy']:.2%}")
            print(f"   Precision: {stats['precision']:.2%}")
            print(f"   Recall: {stats['recall']:.2%}")
            print(f"   Clases: {len(self.label_encoders.get('incident_type', {}).classes_) if 'incident_type' in self.label_encoders else 0}")

        print("\n🔮 PREDICTOR DE AMENAZAS:")
        print(f"   Estado: {'✅ Entrenado' if self.threat_predictor else '❌ No entrenado'}")
        if self.threat_predictor and 'threat_prediction' in self.performance_stats:
            stats = self.performance_stats['threat_prediction']
            print(f"   Precisión: {stats['accuracy']:.2%}")

        print("\n⚠️ EVALUADOR DE RIESGO:")
        print(f"   Estado: {'✅ Entrenado' if self.risk_assessor else '❌ No entrenado'}")

        print("\n📈 MÉTRICAS GENERALES:")
        print(f"   Modelo de Anomalías: {'✅' if self.anomaly_detector else '❌'}")
        print(f"   Modelo de Clasificación: {'✅' if self.incident_classifier else '❌'}")
        print(f"   Modelo de Predicción: {'✅' if self.threat_predictor else '❌'}")
        print(f"   Modelo de Riesgo: {'✅' if self.risk_assessor else '❌'}")

        print("\n💾 MODELOS GUARDADOS EN:")
        print(f"   Directorio: {self.models_dir}/")
        print(f"   Archivos: anomaly_detector.pkl, incident_classifier.pkl, threat_predictor.pkl, risk_assessor.pkl")

        print("\n🎯 EL SISTEMA IRIS ESTÁ LISTO PARA OPERAR")
        print("="*60)

# Función principal
def main():
    """Función principal para entrenar el sistema de IA"""
    print("ENTRENANDO SISTEMA DE IA IRIS CON DATOS HISTORICOS")
    print("="*60)

    investigator = AdvancedAIInvestigator()

    # Ejecutar análisis de prueba
    print("\n🧪 EJECUTANDO ANÁLISIS DE PRUEBA...")
    incidents_created = investigator.analyze_recent_logs(hours_back=6)  # Solo últimas 6 horas para prueba

    print(f"\n✅ Análisis completado. Incidentes creados en prueba: {incidents_created}")

if __name__ == "__main__":
    main()
