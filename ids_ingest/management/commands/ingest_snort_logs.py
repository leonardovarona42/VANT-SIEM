import os
import json
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from ids_ingest.parsers import (
    parse_snort_alert_full, parse_snort_alert_block, get_snort_log_type
)
from ids_ingest.models import SnortLog

class Command(BaseCommand):
    help = 'Ingiere logs de Snort desde el directorio especificado'

    def add_arguments(self, parser):
        parser.add_argument(
            '--log-dir',
            type=str,
            default='snort-logs',
            help='Directorio donde están los logs de Snort'
        )
        parser.add_argument(
            '--file-type',
            type=str,
            choices=['alert_full', 'alert_fast', 'alerts_csv', 'all'],
            default='all',
            help='Tipo de archivo a procesar'
        )
        parser.add_argument(
            '--max-lines',
            type=int,
            default=1000,
            help='Número máximo de líneas a procesar por archivo'
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=100,
            help='Tamaño del lote para inserción en base de datos'
        )

    def handle(self, *args, **options):
        log_dir = options['log_dir']
        file_type = options['file_type']
        max_lines = options['max_lines']
        batch_size = options['batch_size']
        
        if not os.path.exists(log_dir):
            self.stdout.write(
                self.style.ERROR(f'Directorio no existe: {log_dir}')
            )
            return
        
        self.stdout.write(f'Procesando logs de Snort desde: {log_dir}')
        
        # Procesar archivos según el tipo especificado
        if file_type == 'all' or file_type == 'alert_full':
            self.process_alert_full(log_dir, max_lines, batch_size)
        
        if file_type == 'all' or file_type == 'alert_fast':
            self.process_alert_fast(log_dir, max_lines, batch_size)
        
        if file_type == 'all' or file_type == 'alerts_csv':
            self.process_alerts_csv(log_dir, max_lines, batch_size)
        
        self.stdout.write(
            self.style.SUCCESS('Ingesta de logs de Snort completada')
        )

    def process_alert_full(self, log_dir, max_lines, batch_size):
        """Procesar archivo alert.full con información detallada"""
        alert_file = os.path.join(log_dir, 'alert.full')
        if not os.path.exists(alert_file):
            self.stdout.write(f'Archivo alert.full no encontrado en {log_dir}')
            return
        
        self.stdout.write('Procesando alert.full...')
        processed = 0
        errors = 0
        batch = []
        
        try:
            with open(alert_file, 'r', encoding='utf-8', errors='ignore') as f:
                current_block = []
                line_count = 0
                
                for line in f:
                    line_count += 1
                    if line_count > max_lines:
                        break
                    
                    line = line.strip()
                    
                    # Si la línea está vacía, procesar el bloque actual
                    if not line:
                        if current_block:
                            try:
                                parsed = parse_snort_alert_block(current_block)
                                if parsed:
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
                                    
                                    log_data = {
                                        'timestamp': parsed['timestamp'],
                                        'severity': severity,
                                        'priority': priority,
                                        'src_ip': parsed['src_ip'],
                                        'dst_ip': parsed['dst_ip'],
                                        'src_port': parsed.get('src_port'),
                                        'dst_port': parsed.get('dst_port'),
                                        'protocol': parsed.get('protocol', 'TCP'),
                                        'message': parsed['message'],
                                        'gid': parsed['gid'],
                                        'sid': parsed['sid'],
                                        'rev': parsed['rev'],
                                        'classification': parsed.get('classification'),
                                        'raw': parsed['raw_line'],
                                        # Campos específicos de Snort alert.full
                                        'ttl': parsed.get('ttl'),
                                        'tos': parsed.get('tos'),
                                        'packet_id': parsed.get('packet_id'),
                                        'ip_len': parsed.get('ip_len'),
                                        'dgm_len': parsed.get('dgm_len'),
                                        'flags': parsed.get('flags'),
                                        'seq': parsed.get('seq'),
                                        'ack': parsed.get('ack'),
                                        'win': parsed.get('win'),
                                        'tcp_len': parsed.get('tcp_len')
                                    }
                                    
                                    batch.append(log_data)
                                    processed += 1
                                    
                                    # Procesar lote cuando alcance el tamaño
                                    if len(batch) >= batch_size:
                                        self.save_batch(batch)
                                        batch = []
                                        
                            except Exception as e:
                                errors += 1
                                if errors <= 5:
                                    self.stdout.write(f'Error procesando bloque: {e}')
                            finally:
                                current_block = []
                        continue
                    
                    # Agregar línea al bloque actual
                    current_block.append(line)
                
                # Procesar último bloque si existe
                if current_block:
                    try:
                        parsed = parse_snort_alert_block(current_block)
                        if parsed:
                            priority = parsed.get('priority', 3)
                            if priority <= 1:
                                severity = 'Critical'
                            elif priority <= 2:
                                severity = 'High'
                            elif priority <= 3:
                                severity = 'Medium'
                            else:
                                severity = 'Low'
                            
                            log_data = {
                                'timestamp': parsed['timestamp'],
                                'severity': severity,
                                'priority': priority,
                                'src_ip': parsed['src_ip'],
                                'dst_ip': parsed['dst_ip'],
                                'src_port': parsed.get('src_port'),
                                'dst_port': parsed.get('dst_port'),
                                'protocol': parsed.get('protocol', 'TCP'),
                                'message': parsed['message'],
                                'gid': parsed['gid'],
                                'sid': parsed['sid'],
                                'rev': parsed['rev'],
                                'classification': parsed.get('classification'),
                                'raw': parsed['raw_line'],
                                'ttl': parsed.get('ttl'),
                                'tos': parsed.get('tos'),
                                'packet_id': parsed.get('packet_id'),
                                'ip_len': parsed.get('ip_len'),
                                'dgm_len': parsed.get('dgm_len'),
                                'flags': parsed.get('flags'),
                                'seq': parsed.get('seq'),
                                'ack': parsed.get('ack'),
                                'win': parsed.get('win'),
                                'tcp_len': parsed.get('tcp_len')
                            }
                            
                            batch.append(log_data)
                            processed += 1
                    except Exception as e:
                        errors += 1
                        if errors <= 5:
                            self.stdout.write(f'Error procesando bloque final: {e}')
                
                # Guardar lote final
                if batch:
                    self.save_batch(batch)
            
            self.stdout.write(
                f'Alert Full: {processed} procesados, {errors} errores'
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error procesando alert.full: {e}')
            )

    def process_alert_fast(self, log_dir, max_lines, batch_size):
        """Procesar archivo alert.fast o alerts.fast"""
        fast_files = ['alert.fast', 'alerts.fast']
        processed_total = 0
        errors_total = 0
        
        for fast_file in fast_files:
            file_path = os.path.join(log_dir, fast_file)
            if not os.path.exists(file_path):
                continue
            
            self.stdout.write(f'Procesando {fast_file}...')
            processed = 0
            errors = 0
            batch = []
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        if line_num > max_lines:
                            break
                        
                        if not line.strip():
                            continue
                        
                        try:
                            parsed = parse_snort_alert_full(line)
                            if parsed:
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
                                
                                log_data = {
                                    'timestamp': parsed['timestamp'],
                                    'severity': severity,
                                    'priority': priority,
                                    'src_ip': parsed['src_ip'],
                                    'dst_ip': parsed['dst_ip'],
                                    'src_port': parsed.get('src_port'),
                                    'dst_port': parsed.get('dst_port'),
                                    'protocol': parsed.get('protocol', 'TCP'),
                                    'message': parsed['message'],
                                    'gid': parsed['gid'],
                                    'sid': parsed['sid'],
                                    'rev': parsed['rev'],
                                    'classification': parsed.get('classification'),
                                    'raw': parsed.get('raw_line', line.strip()),
                                    'ttl': parsed.get('ttl'),
                                    'tos': parsed.get('tos'),
                                    'packet_id': parsed.get('packet_id'),
                                    'ip_len': parsed.get('ip_len'),
                                    'dgm_len': parsed.get('dgm_len'),
                                    'flags': parsed.get('flags'),
                                    'seq': parsed.get('seq'),
                                    'ack': parsed.get('ack'),
                                    'win': parsed.get('win'),
                                    'tcp_len': parsed.get('tcp_len')
                                }
                                
                                batch.append(log_data)
                                processed += 1
                                
                                if len(batch) >= batch_size:
                                    self.save_batch(batch)
                                    batch = []
                            else:
                                errors += 1
                        except Exception as e:
                            errors += 1
                            if errors <= 5:
                                self.stdout.write(f'Error en línea {line_num}: {e}')
                
                if batch:
                    self.save_batch(batch)
                
                self.stdout.write(
                    f'{fast_file}: {processed} procesados, {errors} errores'
                )
                processed_total += processed
                errors_total += errors
                
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error procesando {fast_file}: {e}')
                )
        
        if processed_total > 0:
            self.stdout.write(
                f'Alert Fast Total: {processed_total} procesados, {errors_total} errores'
            )

    def process_alerts_csv(self, log_dir, max_lines, batch_size):
        """Procesar archivo alerts.csv"""
        csv_file = os.path.join(log_dir, 'alerts.csv')
        if not os.path.exists(csv_file):
            self.stdout.write(f'Archivo alerts.csv no encontrado en {log_dir}')
            return
        
        self.stdout.write('Procesando alerts.csv...')
        processed = 0
        errors = 0
        batch = []
        
        try:
            import csv
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                csv_reader = csv.reader(f)
                for line_num, row in enumerate(csv_reader, 1):
                    if line_num > max_lines:
                        break
                    
                    if len(row) < 8:  # Mínimo de campos esperados
                        errors += 1
                        continue
                    
                    try:
                        # Formato CSV: timestamp, message, src_ip, src_port, dst_ip, dst_port, protocol, classification
                        timestamp_str = row[0]
                        message = row[1]
                        src_ip = row[2]
                        src_port = int(row[3]) if row[3] else None
                        dst_ip = row[4]
                        dst_port = int(row[5]) if row[5] else None
                        protocol = row[6]
                        classification = row[7] if len(row) > 7 else None
                        
                        # Parsear timestamp
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%m/%d-%H:%M:%S.%f")
                            timestamp = timestamp.replace(year=timezone.now().year)
                        except ValueError:
                            errors += 1
                            continue
                        
                        log_data = {
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
                            'raw': ','.join(row)
                        }
                        
                        batch.append(log_data)
                        processed += 1
                        
                        if len(batch) >= batch_size:
                            self.save_batch(batch)
                            batch = []
                            
                    except Exception as e:
                        errors += 1
                        if errors <= 5:
                            self.stdout.write(f'Error en línea {line_num}: {e}')
            
            if batch:
                self.save_batch(batch)
            
            self.stdout.write(
                f'Alerts CSV: {processed} procesados, {errors} errores'
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error procesando alerts.csv: {e}')
            )

    def save_batch(self, batch):
        """Guardar lote de logs en la base de datos con deduplicación y creación automática de reportes"""
        if not batch:
            return

        try:
            # Crear objetos SnortLog
            logs = []
            high_priority_logs = []
            for log_data in batch:
                log = SnortLog(**log_data)
                log.log_hash = log.generate_hash()
                logs.append(log)

                # Identificar logs de alta prioridad (High o Critical)
                if log_data.get('severity') in ['High', 'Critical']:
                    high_priority_logs.append(log_data)

            # Insertar en lote con manejo de duplicados
            SnortLog.objects.bulk_create(logs, ignore_conflicts=True)
            self.stdout.write(f'✅ {len(logs)} logs de Snort guardados (duplicados ignorados)')

            # Crear reportes automáticos para alertas de alta prioridad
            if high_priority_logs:
                self.create_auto_reports(high_priority_logs)

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error guardando lote: {e}')
            )

    def create_auto_reports(self, high_priority_logs):
        """Crear reportes automáticos para alertas de alta prioridad"""
        try:
            from EVENT_M.models import Area, Responsable, Reporte

            # Obtener área de IA
            ai_area = Area.objects.filter(nombre='VANT-SIEM-AI-Analitic').first()
            if not ai_area:
                self.stdout.write(
                    self.style.WARNING('Área VANT-SIEM-AI-Analitic no encontrada, omitiendo creación de reportes automáticos')
                )
                return

            reports_created = 0
            for log_data in high_priority_logs:
                try:
                    # Crear descripción del reporte
                    descripcion = f"""ALERTA DE ALTA PRIORIDAD DETECTADA POR SISTEMA IDS

Severidad: {log_data.get('severity', 'Unknown')}
Mensaje: {log_data.get('message', 'N/A')}
IP Origen: {log_data.get('src_ip', 'N/A')}
IP Destino: {log_data.get('dst_ip', 'N/A')}
Protocolo: {log_data.get('protocol', 'N/A')}
Puerto Origen: {log_data.get('src_port', 'N/A')}
Puerto Destino: {log_data.get('dst_port', 'N/A')}
Clasificación: {log_data.get('classification', 'N/A')}

Esta alerta fue generada automáticamente por el sistema VANT-SIEM basado en logs de Snort.
Requiere revisión inmediata por parte del equipo de seguridad."""

                    # Crear reporte
                    reporte = Reporte.objects.create(
                        nombre_informante='Sistema VANT-SIEM AI',
                        email_informante='ai@vantsiem.local',
                        area=ai_area,
                        descripcion=descripcion,
                        estado_solucion='Nuevo'  # Estado por defecto
                    )

                    reports_created += 1

                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(f'Error creando reporte automático: {e}')
                    )

            if reports_created > 0:
                self.stdout.write(
                    self.style.SUCCESS(f'📋 {reports_created} reportes automáticos creados para alertas de alta prioridad')
                )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error en creación automática de reportes: {e}')
            )
