"""
Servicio profesional de ingesta de logs IDS/IPS
Maneja threading, reconexiones, y monitoreo robusto
"""
import os
import json
import time
import threading
import logging
import queue
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from django.utils import timezone
from django.db import transaction, connection
from django.core.management import call_command
from django.conf import settings
from .models import IDSIngestConfig, SuricataEveAlert, SuricataFlow, SuricataStats, SuricataSystemLog, SuricataLog, SnortLog
from .parsers import (
    parse_suricata_eve_json, parse_suricata_fast_log, 
    parse_suricata_stats_log, parse_suricata_system_log,
    parse_snort_alert_full, get_snort_log_type
)

logger = logging.getLogger(__name__)

class IngestService:
    """Servicio profesional de ingesta con threading y manejo robusto de errores"""
    
    def __init__(self):
        self.running = False
        self.threads = {}
        self.queues = {}
        self.lock = threading.Lock()
        self.stats = {
            'total_processed': 0,
            'total_errors': 0,
            'last_run': None,
            'active_configs': 0
        }
        
    def start(self, interval: int = 60):
        """Iniciar servicio de ingesta"""
        if self.running:
            logger.warning("Servicio de ingesta ya está ejecutándose")
            return False
            
        self.running = True
        logger.info(f"🚀 Iniciando servicio de ingesta (intervalo: {interval}s)")
        
        # Iniciar hilo principal
        main_thread = threading.Thread(
            target=self._main_loop, 
            args=(interval,),
            daemon=True,
            name="IngestMainThread"
        )
        main_thread.start()
        self.threads['main'] = main_thread
        
        return True
    
    def stop(self):
        """Detener servicio de ingesta"""
        if not self.running:
            return
            
        logger.info("🛑 Deteniendo servicio de ingesta...")
        self.running = False
        
        # Esperar a que terminen los hilos
        for name, thread in self.threads.items():
            if thread.is_alive():
                thread.join(timeout=5)
                if thread.is_alive():
                    logger.warning(f"Hilo {name} no terminó correctamente")
        
        self.threads.clear()
        self.queues.clear()
        logger.info("✅ Servicio de ingesta detenido")
    
    def _main_loop(self, interval: int):
        """Loop principal del servicio"""
        while self.running:
            try:
                # Obtener configuraciones activas
                configs = IDSIngestConfig.objects.filter(active=True)
                self.stats['active_configs'] = configs.count()
                
                if configs.exists():
                    logger.info(f"📊 Procesando {configs.count()} configuraciones activas")
                    
                    # Procesar cada configuración en hilos separados
                    for config in configs:
                        if not self.running:
                            break
                            
                        # Crear cola para esta configuración si no existe
                        if config.id not in self.queues:
                            self.queues[config.id] = queue.Queue(maxsize=1000)
                        
                        # Iniciar hilo de procesamiento si no existe
                        thread_name = f"Config-{config.id}"
                        if thread_name not in self.threads or not self.threads[thread_name].is_alive():
                            thread = threading.Thread(
                                target=self._process_config,
                                args=(config,),
                                daemon=True,
                                name=thread_name
                            )
                            thread.start()
                            self.threads[thread_name] = thread
                
                # Actualizar estadísticas
                self.stats['last_run'] = timezone.now()
                
            except Exception as e:
                logger.error(f"❌ Error en loop principal: {e}")
                self.stats['total_errors'] += 1
            
            # Esperar antes de la siguiente iteración
            time.sleep(interval)
    
    def _process_config(self, config: IDSIngestConfig):
        """Procesar una configuración específica"""
        try:
            logger.info(f"🔄 Procesando configuración {config.ids_type.upper()}: {config.log_path}")

            # Verificar que la ruta existe
            if not os.path.exists(config.log_path):
                logger.warning(f"⚠️ Ruta no existe: {config.log_path}")
                # Actualizar last_run incluso si hay error para evitar reintentos constantes
                config.last_run = timezone.now()
                config.save(update_fields=['last_run'])
                return

            # Verificar permisos de lectura
            if not os.access(config.log_path, os.R_OK):
                logger.warning(f"⚠️ Sin permisos de lectura: {config.log_path}")
                config.last_run = timezone.now()
                config.save(update_fields=['last_run'])
                return

            # Procesar archivos según el tipo
            if config.ids_type == 'suricata':
                self._process_suricata_config(config)
            elif config.ids_type == 'snort':
                self._process_snort_config(config)
            else:
                logger.warning(f"⚠️ Tipo de IDS no soportado: {config.ids_type}")
                config.last_run = timezone.now()
                config.save(update_fields=['last_run'])
                return

            # Actualizar última ejecución
            config.last_run = timezone.now()
            config.save(update_fields=['last_run'])

            logger.info(f"✅ Configuración {config.ids_type.upper()} procesada exitosamente")

        except Exception as e:
            logger.error(f"❌ Error procesando configuración {config.id}: {e}", exc_info=True)
            self.stats['total_errors'] += 1
            # Actualizar last_run incluso en caso de error para evitar bucles
            try:
                config.last_run = timezone.now()
                config.save(update_fields=['last_run'])
            except Exception as save_error:
                logger.error(f"❌ Error actualizando last_run para config {config.id}: {save_error}")
    
    def _process_suricata_config(self, config: IDSIngestConfig):
        """Procesar configuración de Suricata"""
        log_dir = config.log_path
        
        # Procesar eve.json
        eve_file = os.path.join(log_dir, 'eve.json')
        if os.path.exists(eve_file):
            self._process_eve_file(eve_file, config)
        
        # Procesar fast.log
        fast_file = os.path.join(log_dir, 'fast.log')
        if os.path.exists(fast_file):
            self._process_fast_file(fast_file, config)
        
        # Procesar stats.log
        stats_file = os.path.join(log_dir, 'stats.log')
        if os.path.exists(stats_file):
            self._process_stats_file(stats_file, config)
        
        # Procesar suricata.log
        system_file = os.path.join(log_dir, 'suricata.log')
        if os.path.exists(system_file):
            self._process_system_file(system_file, config)
    
    def _process_snort_config(self, config: IDSIngestConfig):
        """Procesar configuración de Snort"""
        log_path = config.log_path

        # Verificar si es un archivo específico o un directorio
        if os.path.isfile(log_path):
            # Es un archivo específico
            filename = os.path.basename(log_path)
            if filename == 'alert.full' or filename.endswith('.full'):
                self._process_snort_alert_file(log_path, config)
            else:
                self._process_snort_other_file(log_path, config, filename)
            return

        # Es un directorio
        if not os.path.exists(log_path):
            logger.warning(f"⚠️ Directorio no existe: {log_path}")
            return

        # Procesar alert.full (prioridad) - buscar varias variaciones
        alert_files = ['alert.full', 'alert_full.txt', 'alert.full.txt']
        alert_processed = False
        for alert_filename in alert_files:
            alert_file = os.path.join(log_path, alert_filename)
            if os.path.exists(alert_file):
                self._process_snort_alert_file(alert_file, config)
                alert_processed = True
                break
        if not alert_processed:
            logger.warning(f"⚠️ Archivo alert.full no encontrado en: {log_path}")

        # Procesar otros archivos de Snort si existen
        for filename in ['alerts.fast', 'alert.fast', 'alerts.csv', 'alert_fast.txt', 'snort.log']:
            file_path = os.path.join(log_path, filename)
            if os.path.exists(file_path):
                self._process_snort_other_file(file_path, config, filename)

        # Escanear directorio en busca de otros archivos de Snort
        if os.path.isdir(log_path):
            try:
                for file_name in os.listdir(log_path):
                    if file_name.startswith('alert') and (file_name.endswith('.fast') or file_name.endswith('.txt') or file_name.endswith('.full')):
                        file_path = os.path.join(log_path, file_name)
                        if os.path.isfile(file_path) and file_name not in ['alerts.fast', 'alert.fast', 'alerts.csv', 'alert_fast.txt', 'alert.full', 'alert_full.txt', 'alert.full.txt']:
                            # Determinar si es archivo full o fast
                            if file_name.endswith('.full') or 'full' in file_name:
                                self._process_snort_alert_file(file_path, config)
                            else:
                                self._process_snort_other_file(file_path, config, file_name)
            except Exception as e:
                logger.warning(f"Error escaneando directorio {log_path}: {e}")
    
    def _process_snort_alert_file(self, file_path: str, config: IDSIngestConfig):
        """Procesar archivo alert.full de Snort"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Leer desde la última posición si está disponible
                if config.last_position > 0:
                    f.seek(config.last_position)
                
                batch = []
                batch_size = 100
                processed = 0
                
                # El formato alert.full es multi-línea por evento. Usar readline() para permitir tell().
                current_block = []
                while True:
                    pos_before = f.tell()
                    line = f.readline()
                    if not line:
                        # EOF
                        break
                    
                    if not line.strip():
                        if current_block:
                            try:
                                from .parsers import parse_snort_alert_block
                                parsed = parse_snort_alert_block(current_block)
                                if parsed:
                                    batch.append(parsed)
                                    processed += 1
                            except Exception as e:
                                logger.warning(f"Error parseando bloque Snort en {file_path}: {e}")
                            finally:
                                current_block = []
                                # Actualizar última posición segura al inicio del próximo bloque
                                config.last_position = f.tell()
                                config.save()
                        continue
                    
                    current_block.append(line.rstrip('\n'))
                    
                    if len(batch) >= batch_size:
                        self._save_snort_batch(batch)
                        batch = []
                        # Posicionar última posición conocida
                        config.last_position = pos_before
                        config.save()
                
                # Procesar el último bloque si quedó sin separador
                if current_block:
                    try:
                        from .parsers import parse_snort_alert_block
                        parsed = parse_snort_alert_block(current_block)
                        if parsed:
                            batch.append(parsed)
                            processed += 1
                    except Exception as e:
                        logger.warning(f"Error parseando bloque final Snort en {file_path}: {e}")
                
                # Procesar lote final
                if batch:
                    self._save_snort_batch(batch)
                
                logger.info(f"✅ Snort Alert: {processed} eventos procesados")
                self.stats['total_processed'] += processed
                
        except Exception as e:
            logger.error(f"❌ Error procesando alert.full: {e}")
            raise
    
    def _process_snort_other_file(self, file_path: str, config: IDSIngestConfig, filename: str):
        """Procesar otros archivos de Snort (fast, csv)"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Leer desde la última posición si está disponible
                if config.last_position > 0:
                    f.seek(config.last_position)

                batch = []
                batch_size = 100
                processed = 0

                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue

                    try:
                        if filename.endswith('.csv') or 'csv' in filename:
                            # Procesar CSV
                            parsed = self._parse_snort_csv_line(line)
                        else:
                            # Procesar fast log usando el parser principal
                            from .parsers import parse_snort_line
                            parsed = parse_snort_line(line)

                        if parsed:
                            batch.append(parsed)
                            processed += 1

                            if len(batch) >= batch_size:
                                self._save_snort_batch(batch)
                                batch = []

                                config.last_position = f.tell()
                                config.save()

                    except Exception as e:
                        logger.warning(f"Error parseando línea {line_num} en {file_path}: {e}")
                        continue

                # Procesar lote final
                if batch:
                    self._save_snort_batch(batch)

                logger.info(f"✅ Snort {filename}: {processed} eventos procesados")
                self.stats['total_processed'] += processed

        except Exception as e:
            logger.error(f"❌ Error procesando {filename}: {e}")
            raise
    
    def _parse_snort_csv_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parsear línea CSV de Snort"""
        try:
            import csv
            from io import StringIO
            
            reader = csv.reader(StringIO(line))
            row = next(reader)
            
            if len(row) < 8:
                return None
            
            # Formato: timestamp, message, src_ip, src_port, dst_ip, dst_port, protocol, classification
            timestamp_str = row[0]
            message = row[1]
            src_ip = row[2]
            src_port = int(row[3]) if row[3] else None
            dst_ip = row[4]
            dst_port = int(row[5]) if row[5] else None
            protocol = row[6]
            classification = row[7] if len(row) > 7 else None
            
            # Parsear timestamp
            from datetime import datetime
            timestamp = datetime.strptime(timestamp_str, "%m/%d-%H:%M:%S.%f")
            timestamp = timestamp.replace(year=timezone.now().year)
            
            return {
                'timestamp': timestamp,
                'severity': 'Medium',  # Default para CSV
                'priority': 3,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'message': message,
                'gid': 0,
                'sid': 0,
                'rev': 0,
                'classification': classification,
                'raw': line.strip()
            }
            
        except Exception as e:
            logger.warning(f"Error parseando línea CSV: {e}")
            return None
    
    def _process_eve_file(self, file_path: str, config: IDSIngestConfig):
        """Procesar archivo eve.json con manejo robusto de errores"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                if config.last_position > 0:
                    f.seek(config.last_position)
                batch = []
                batch_size = 100
                processed = 0
                line_num = 0
                while True:
                    pos_before = f.tell()
                    line = f.readline()
                    if not line:
                        break
                    line_num += 1
                    if not line.strip():
                        continue
                    try:
                        parsed = parse_suricata_eve_json(line)
                        if parsed:
                            batch.append((parsed, line))
                            processed += 1
                            if len(batch) >= batch_size:
                                self._save_eve_batch(batch)
                                batch = []
                                config.last_position = f.tell()
                                config.save()
                    except Exception as e:
                        logger.warning(f"Error parseando línea {line_num} en {file_path}: {e}")
                        continue
                if batch:
                    self._save_eve_batch(batch)
                logger.info(f"✅ EVE JSON: {processed} eventos procesados")
                self.stats['total_processed'] += processed
        except Exception as e:
            logger.error(f"❌ Error procesando eve.json: {e}")
            raise
    
    def _process_fast_file(self, file_path: str, config: IDSIngestConfig):
        """Procesar archivo fast.log"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                if config.last_position > 0:
                    f.seek(config.last_position)

                batch = []
                batch_size = 100
                processed = 0
                line_num = 0
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line_num += 1
                    if not line.strip():
                        continue
                    try:
                        parsed = parse_suricata_fast_log(line)
                        if parsed:
                            batch.append(parsed)
                            processed += 1
                            if len(batch) >= batch_size:
                                self._save_fast_batch(batch)
                                batch = []
                                config.last_position = f.tell()
                                config.save()
                    except Exception as e:
                        logger.warning(f"Error parseando línea {line_num} en {file_path}: {e}")
                        continue
                if batch:
                    self._save_fast_batch(batch)
                logger.info(f"✅ Fast Log: {processed} eventos procesados")
                self.stats['total_processed'] += processed

        except Exception as e:
            logger.error(f"❌ Error procesando fast.log: {e}")
            raise

    def _process_stats_file(self, file_path: str, config: IDSIngestConfig):
        """Procesar archivo stats.log"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                if config.last_position > 0:
                    f.seek(config.last_position)

                batch = []
                batch_size = 100
                processed = 0
                line_num = 0
                while True:
                    line = f.readline()
                    if not line:
                        break
                    line_num += 1
                    if not line.strip():
                        continue
                    try:
                        parsed = parse_suricata_stats_log(line)
                        if parsed:
                            batch.append(parsed)
                            processed += 1
                            if len(batch) >= batch_size:
                                self._save_stats_batch(batch)
                                batch = []
                                config.last_position = f.tell()
                                config.save()
                    except Exception as e:
                        logger.warning(f"Error parseando línea {line_num} en {file_path}: {e}")
                        continue
                if batch:
                    self._save_stats_batch(batch)
                logger.info(f"✅ Stats Log: {processed} eventos procesados")
                self.stats['total_processed'] += processed

        except Exception as e:
            logger.error(f"❌ Error procesando stats.log: {e}")
            raise
    
    def _process_system_file(self, file_path: str, config: IDSIngestConfig):
        """Procesar archivo suricata.log"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                if config.last_position > 0:
                    f.seek(config.last_position)
                
                batch = []
                batch_size = 100
                processed = 0
                
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue
                    
                    try:
                        parsed = parse_suricata_system_log(line)
                        if parsed:
                            batch.append(parsed)
                            processed += 1
                            
                            if len(batch) >= batch_size:
                                self._save_system_batch(batch)
                                batch = []
                                
                                config.last_position = f.tell()
                                config.save()
                                
                    except Exception as e:
                        logger.warning(f"Error parseando línea {line_num} en {file_path}: {e}")
                        continue
                
                if batch:
                    self._save_system_batch(batch)
                
                logger.info(f"✅ System Log: {processed} eventos procesados")
                self.stats['total_processed'] += processed
                
        except Exception as e:
            logger.error(f"❌ Error procesando suricata.log: {e}")
            raise
    
    @transaction.atomic
    def _save_eve_batch(self, batch: List[tuple]):
        """Guardar lote de eventos EVE en la base de datos con deduplicación"""
        eve_alerts = []
        eve_flows = []
        eve_stats = []
        for parsed, raw_line in batch:
            if parsed.get('event_type') == 'alert':
                alert = SuricataEveAlert(
                    timestamp=parsed['timestamp'],
                    event_type=parsed['event_type'],
                    src_ip=parsed['src_ip'],
                    dest_ip=parsed['dest_ip'],
                    src_port=parsed.get('src_port'),
                    dest_port=parsed.get('dest_port'),
                    proto=parsed['proto'],
                    signature_id=parsed['signature_id'],
                    signature_rev=parsed['signature_rev'],
                    category=parsed.get('category'),
                    action=parsed.get('action', 'alert'),
                    severity=parsed['severity'],
                    message=parsed['message'],
                    raw_data=parsed['raw_data']
                )
                alert.log_hash = alert.generate_hash()
                eve_alerts.append(alert)
            elif parsed.get('event_type') == 'flow':
                flow = SuricataFlow(
                    timestamp=parsed['timestamp'],
                    src_ip=parsed['src_ip'],
                    dest_ip=parsed['dest_ip'],
                    src_port=parsed['src_port'],
                    dest_port=parsed['dest_port'],
                    proto=parsed['proto'],
                    app_proto=parsed.get('app_proto'),
                    state=parsed.get('state'),
                    pkts_toserver=parsed.get('pkts_toserver', 0),
                    pkts_toclient=parsed.get('pkts_toclient', 0),
                    bytes_toserver=parsed.get('bytes_toserver', 0),
                    bytes_toclient=parsed.get('bytes_toclient', 0),
                    start_time=parsed.get('start_time'),
                    end_time=parsed.get('end_time'),
                    age=parsed.get('age', 0),
                    raw_data=parsed['raw_data']
                )
                flow.log_hash = flow.generate_hash()
                eve_flows.append(flow)
            elif parsed.get('event_type') == 'stats':
                stats = SuricataStats(
                    timestamp=parsed['timestamp'],
                    uptime=parsed.get('uptime', 0),
                    total_packets=parsed.get('total_packets', 0),
                    total_bytes=parsed.get('total_bytes', 0),
                    packets_per_second=parsed.get('packets_per_second', 0.0),
                    bytes_per_second=parsed.get('bytes_per_second', 0.0),
                    total_flows=parsed.get('total_flows', 0),
                    total_alerts=parsed.get('total_alerts', 0),
                    total_drops=parsed.get('total_drops', 0),
                    memory_usage=parsed.get('memory_usage', 0.0),
                    cpu_usage=parsed.get('cpu_usage', 0.0),
                    rules_loaded=parsed.get('rules_loaded', 0),
                    rules_failed=parsed.get('rules_failed', 0),
                    raw_data=parsed['raw_data']
                )
                stats.log_hash = stats.generate_hash()
                eve_stats.append(stats)
        # Crear registros en lotes con manejo de duplicados
        if eve_alerts:
            try:
                SuricataEveAlert.objects.bulk_create(eve_alerts, ignore_conflicts=True)
                logger.info(f"✅ {len(eve_alerts)} alertas EVE procesadas (duplicados ignorados)")
            except Exception as e:
                logger.warning(f"⚠️ Error guardando alertas EVE: {e}")
        if eve_flows:
            try:
                SuricataFlow.objects.bulk_create(eve_flows, ignore_conflicts=True)
                logger.info(f"✅ {len(eve_flows)} flujos EVE procesados (duplicados ignorados)")
            except Exception as e:
                logger.warning(f"⚠️ Error guardando flujos EVE: {e}")
        if eve_stats:
            try:
                SuricataStats.objects.bulk_create(eve_stats, ignore_conflicts=True)
                logger.info(f"✅ {len(eve_stats)} estadísticas EVE procesadas (duplicados ignorados)")
            except Exception as e:
                logger.warning(f"⚠️ Error guardando estadísticas EVE: {e}")
    
    @transaction.atomic
    def _save_fast_batch(self, batch: List[Dict[str, Any]]):
        """Guardar lote de eventos fast.log con deduplicación"""
        logs = []
        for parsed in batch:
            log = SuricataLog(
                timestamp=parsed['timestamp'],
                severity=parsed['severity'],
                priority=parsed['priority'],
                src_ip=parsed['src_ip'],
                dst_ip=parsed['dest_ip'],
                src_port=parsed['src_port'],
                dst_port=parsed['dest_port'],
                protocol=parsed['protocol'],
                message=parsed['message'],
                gid=0,
                sid=parsed['signature_id'],
                rev=parsed['signature_rev'],
                classification=parsed.get('classification'),
                raw=parsed['raw']
            )
            log.log_hash = log.generate_hash()
            logs.append(log)
        
        if logs:
            try:
                SuricataLog.objects.bulk_create(logs, ignore_conflicts=True)
                logger.info(f"✅ {len(logs)} logs fast procesados (duplicados ignorados)")
            except Exception as e:
                logger.warning(f"⚠️ Error guardando logs fast: {e}")
    
    @transaction.atomic
    def _save_stats_batch(self, batch: List[Dict[str, Any]]):
        """Guardar lote de estadísticas con deduplicación"""
        stats = []
        for parsed in batch:
            stat = SuricataStats(
                timestamp=parsed['timestamp'],
                uptime=parsed.get('uptime', 0),
                total_packets=parsed.get('total_packets', 0),
                total_bytes=parsed.get('total_bytes', 0),
                packets_per_second=parsed.get('packets_per_second', 0.0),
                bytes_per_second=parsed.get('bytes_per_second', 0.0),
                total_flows=parsed.get('total_flows', 0),
                total_alerts=parsed.get('total_alerts', 0),
                total_drops=parsed.get('total_drops', 0),
                memory_usage=parsed.get('memory_usage', 0.0),
                cpu_usage=parsed.get('cpu_usage', 0.0),
                rules_loaded=parsed.get('rules_loaded', 0),
                rules_failed=parsed.get('rules_failed', 0),
                raw_data=parsed['raw_data']
            )
            stat.log_hash = stat.generate_hash()
            stats.append(stat)
        
        if stats:
            try:
                SuricataStats.objects.bulk_create(stats, ignore_conflicts=True)
                logger.info(f"✅ {len(stats)} estadísticas procesadas (duplicados ignorados)")
            except Exception as e:
                logger.warning(f"⚠️ Error guardando estadísticas: {e}")
    
    @transaction.atomic
    def _save_system_batch(self, batch: List[Dict[str, Any]]):
        """Guardar lote de logs del sistema con deduplicación"""
        logs = []
        for parsed in batch:
            log = SuricataSystemLog(
                timestamp=parsed['timestamp'],
                level=parsed['level'],
                component=parsed.get('component'),
                message=parsed['message'],
                raw_line=parsed['raw_line']
            )
            log.log_hash = log.generate_hash()
            logs.append(log)
        
        if logs:
            try:
                SuricataSystemLog.objects.bulk_create(logs, ignore_conflicts=True)
                logger.info(f"✅ {len(logs)} logs del sistema procesados (duplicados ignorados)")
            except Exception as e:
                logger.warning(f"⚠️ Error guardando logs del sistema: {e}")
    
    @transaction.atomic
    def _save_snort_batch(self, batch: List[Dict[str, Any]]):
        """Guardar lote de logs de Snort con deduplicación"""
        logs = []
        for parsed in batch:
            # Determinar severidad basada en priority
            priority = parsed.get('priority', 3)
            if priority <= 1:
                severity = 'Critical'
            elif priority <= 2:
                severity = 'High'
            elif priority <= 3:
                severity = 'Medium'
            else:
                severity = 'Low'
            
            log = SnortLog(
                timestamp=parsed['timestamp'],
                severity=severity,
                priority=priority,
                src_ip=parsed['src_ip'],
                dst_ip=parsed['dst_ip'],
                src_port=parsed.get('src_port'),
                dst_port=parsed.get('dst_port'),
                protocol=parsed.get('protocol', 'TCP'),
                message=parsed['message'],
                gid=parsed.get('gid', 0),
                sid=parsed.get('sid', 0),
                rev=parsed.get('rev', 0),
                classification=parsed.get('classification'),
                raw=parsed.get('raw_line', parsed.get('raw', '')),
                # Campos específicos de Snort
                ttl=parsed.get('ttl'),
                tos=parsed.get('tos'),
                packet_id=parsed.get('packet_id'),
                ip_len=parsed.get('ip_len'),
                dgm_len=parsed.get('dgm_len'),
                flags=parsed.get('flags'),
                seq=parsed.get('seq'),
                ack=parsed.get('ack'),
                win=parsed.get('win'),
                tcp_len=parsed.get('tcp_len')
            )
            log.log_hash = log.generate_hash()
            logs.append(log)
        
        if logs:
            try:
                SnortLog.objects.bulk_create(logs, ignore_conflicts=True)
                logger.info(f"✅ {len(logs)} logs de Snort procesados (duplicados ignorados)")
            except Exception as e:
                logger.warning(f"⚠️ Error guardando logs de Snort: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Obtener estado del servicio"""
        return {
            'running': self.running,
            'active_threads': len([t for t in self.threads.values() if t.is_alive()]),
            'total_threads': len(self.threads),
            'stats': self.stats,
            'queues': {k: v.qsize() for k, v in self.queues.items()}
        }

# Instancia global del servicio
ingest_service = IngestService()
