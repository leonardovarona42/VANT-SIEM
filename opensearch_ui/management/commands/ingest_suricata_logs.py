import os
import json
from datetime import datetime
from django.core.management.base import BaseCommand
from django.utils import timezone
from opensearch_ui.parsers import (
    parse_suricata_eve_json, parse_suricata_fast_log, 
    parse_suricata_stats_log, parse_suricata_system_log,
    get_suricata_log_type
)
from opensearch_ui.models import (
    SuricataEveAlert, SuricataFlow, SuricataStats, SuricataSystemLog
)

class Command(BaseCommand):
    help = 'Ingiere logs de Suricata desde el directorio especificado'

    def add_arguments(self, parser):
        parser.add_argument(
            '--log-dir',
            type=str,
            default='suricata-log',
            help='Directorio donde están los logs de Suricata'
        )
        parser.add_argument(
            '--file-type',
            type=str,
            choices=['eve', 'fast', 'stats', 'system', 'all'],
            default='all',
            help='Tipo de archivo a procesar'
        )
        parser.add_argument(
            '--max-lines',
            type=int,
            default=1000,
            help='Número máximo de líneas a procesar por archivo'
        )

    def handle(self, *args, **options):
        log_dir = options['log_dir']
        file_type = options['file_type']
        max_lines = options['max_lines']
        
        if not os.path.exists(log_dir):
            self.stdout.write(
                self.style.ERROR(f'Directorio no existe: {log_dir}')
            )
            return
        
        self.stdout.write(f'Procesando logs de Suricata desde: {log_dir}')
        
        # Procesar archivos según el tipo especificado
        if file_type == 'all' or file_type == 'eve':
            self.process_eve_json(log_dir, max_lines)
        
        if file_type == 'all' or file_type == 'fast':
            self.process_fast_log(log_dir, max_lines)
        
        if file_type == 'all' or file_type == 'stats':
            self.process_stats_log(log_dir, max_lines)
        
        if file_type == 'all' or file_type == 'system':
            self.process_system_log(log_dir, max_lines)
        
        self.stdout.write(
            self.style.SUCCESS('Ingesta de logs completada')
        )

    def process_eve_json(self, log_dir, max_lines):
        """Procesar archivo eve.json"""
        eve_file = os.path.join(log_dir, 'eve.json')
        if not os.path.exists(eve_file):
            self.stdout.write(f'Archivo eve.json no encontrado en {log_dir}')
            return
        
        self.stdout.write('Procesando eve.json...')
        processed = 0
        errors = 0
        
        try:
            with open(eve_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > max_lines:
                        break
                    
                    if not line.strip():
                        continue
                    
                    try:
                        parsed = parse_suricata_eve_json(line)
                        if parsed:
                            if parsed.get('event_type') == 'alert':
                                self.create_eve_alert(parsed)
                            elif parsed.get('event_type') == 'flow':
                                self.create_eve_flow(parsed)
                            elif parsed.get('event_type') == 'stats':
                                self.create_eve_stats(parsed)
                            processed += 1
                        else:
                            errors += 1
                    except Exception as e:
                        errors += 1
                        if errors <= 5:  # Solo mostrar los primeros 5 errores
                            self.stdout.write(f'Error en línea {line_num}: {e}')
            
            self.stdout.write(
                f'EVE JSON: {processed} procesados, {errors} errores'
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error procesando eve.json: {e}')
            )

    def process_fast_log(self, log_dir, max_lines):
        """Procesar archivo fast.log"""
        fast_file = os.path.join(log_dir, 'fast.log')
        if not os.path.exists(fast_file):
            self.stdout.write(f'Archivo fast.log no encontrado en {log_dir}')
            return
        
        self.stdout.write('Procesando fast.log...')
        processed = 0
        errors = 0
        
        try:
            with open(fast_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > max_lines:
                        break
                    
                    if not line.strip():
                        continue
                    
                    try:
                        parsed = parse_suricata_fast_log(line)
                        if parsed:
                            # Crear registro en el modelo original SuricataLog
                            from opensearch_ui.models import SuricataLog
                            SuricataLog.objects.create(
                                timestamp=parsed['timestamp'],
                                severity=parsed['severity'],
                                priority=parsed['priority'],
                                src_ip=parsed['src_ip'],
                                dst_ip=parsed['dest_ip'],
                                src_port=parsed['src_port'],
                                dst_port=parsed['dest_port'],
                                protocol=parsed['protocol'],
                                message=parsed['message'],
                                gid=0,  # No disponible en fast.log
                                sid=parsed['signature_id'],
                                rev=parsed['signature_rev'],
                                classification=parsed.get('classification'),
                                raw=parsed['raw']
                            )
                            processed += 1
                        else:
                            errors += 1
                    except Exception as e:
                        errors += 1
                        if errors <= 5:
                            self.stdout.write(f'Error en línea {line_num}: {e}')
            
            self.stdout.write(
                f'Fast Log: {processed} procesados, {errors} errores'
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error procesando fast.log: {e}')
            )

    def process_stats_log(self, log_dir, max_lines):
        """Procesar archivo stats.log"""
        stats_file = os.path.join(log_dir, 'stats.log')
        if not os.path.exists(stats_file):
            self.stdout.write(f'Archivo stats.log no encontrado en {log_dir}')
            return
        
        self.stdout.write('Procesando stats.log...')
        processed = 0
        errors = 0
        
        try:
            with open(stats_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > max_lines:
                        break
                    
                    if not line.strip():
                        continue
                    
                    try:
                        parsed = parse_suricata_stats_log(line)
                        if parsed:
                            self.create_stats_record(parsed)
                            processed += 1
                        else:
                            errors += 1
                    except Exception as e:
                        errors += 1
                        if errors <= 5:
                            self.stdout.write(f'Error en línea {line_num}: {e}')
            
            self.stdout.write(
                f'Stats Log: {processed} procesados, {errors} errores'
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error procesando stats.log: {e}')
            )

    def process_system_log(self, log_dir, max_lines):
        """Procesar archivo suricata.log"""
        system_file = os.path.join(log_dir, 'suricata.log')
        if not os.path.exists(system_file):
            self.stdout.write(f'Archivo suricata.log no encontrado en {log_dir}')
            return
        
        self.stdout.write('Procesando suricata.log...')
        processed = 0
        errors = 0
        
        try:
            with open(system_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > max_lines:
                        break
                    
                    if not line.strip():
                        continue
                    
                    try:
                        parsed = parse_suricata_system_log(line)
                        if parsed:
                            self.create_system_log_record(parsed)
                            processed += 1
                        else:
                            errors += 1
                    except Exception as e:
                        errors += 1
                        if errors <= 5:
                            self.stdout.write(f'Error en línea {line_num}: {e}')
            
            self.stdout.write(
                f'System Log: {processed} procesados, {errors} errores'
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error procesando suricata.log: {e}')
            )

    def create_eve_alert(self, parsed_data):
        """Crear registro de alerta EVE y reporte automático si es de alta prioridad"""
        # Crear el registro de alerta
        alert = SuricataEveAlert.objects.create(
            timestamp=parsed_data['timestamp'],
            event_type=parsed_data['event_type'],
            src_ip=parsed_data['src_ip'],
            dest_ip=parsed_data['dest_ip'],
            src_port=parsed_data.get('src_port'),
            dest_port=parsed_data.get('dest_port'),
            proto=parsed_data['proto'],
            signature_id=parsed_data['signature_id'],
            signature_rev=parsed_data['signature_rev'],
            category=parsed_data.get('category'),
            action=parsed_data.get('action', 'alert'),
            severity=parsed_data['severity'],
            message=parsed_data['message'],
            raw_data=parsed_data['raw_data']
        )

        # Crear reporte automático si es de alta prioridad
        severity = parsed_data.get('severity', 3)
        if severity <= 2:  # 1 = Critical, 2 = High
            self.create_auto_report_from_suricata(parsed_data)

    def create_eve_flow(self, parsed_data):
        """Crear registro de flujo EVE"""
        SuricataFlow.objects.create(
            timestamp=parsed_data['timestamp'],
            src_ip=parsed_data['src_ip'],
            dest_ip=parsed_data['dest_ip'],
            src_port=parsed_data['src_port'],
            dest_port=parsed_data['dest_port'],
            proto=parsed_data['proto'],
            app_proto=parsed_data.get('app_proto'),
            state=parsed_data.get('state'),
            pkts_toserver=parsed_data.get('pkts_toserver', 0),
            pkts_toclient=parsed_data.get('pkts_toclient', 0),
            bytes_toserver=parsed_data.get('bytes_toserver', 0),
            bytes_toclient=parsed_data.get('bytes_toclient', 0),
            start_time=parsed_data.get('start_time', parsed_data['timestamp']),
            end_time=parsed_data.get('end_time', parsed_data['timestamp']),
            age=parsed_data.get('age', 0),
            raw_data=parsed_data['raw_data']
        )

    def create_eve_stats(self, parsed_data):
        """Crear registro de estadísticas EVE"""
        SuricataStats.objects.create(
            timestamp=parsed_data['timestamp'],
            uptime=parsed_data.get('uptime', 0),
            total_packets=parsed_data.get('total_packets', 0),
            total_bytes=parsed_data.get('total_bytes', 0),
            packets_per_second=parsed_data.get('packets_per_second', 0.0),
            bytes_per_second=parsed_data.get('bytes_per_second', 0.0),
            total_flows=parsed_data.get('total_flows', 0),
            total_alerts=parsed_data.get('total_alerts', 0),
            total_drops=parsed_data.get('total_drops', 0),
            memory_usage=parsed_data.get('memory_usage', 0.0),
            cpu_usage=parsed_data.get('cpu_usage', 0.0),
            rules_loaded=parsed_data.get('rules_loaded', 0),
            rules_failed=parsed_data.get('rules_failed', 0),
            raw_data=parsed_data['raw_data']
        )

    def create_stats_record(self, parsed_data):
        """Crear registro de estadísticas"""
        SuricataStats.objects.create(
            timestamp=parsed_data['timestamp'],
            uptime=parsed_data.get('uptime', 0),
            total_packets=parsed_data.get('total_packets', 0),
            total_bytes=parsed_data.get('total_bytes', 0),
            packets_per_second=parsed_data.get('packets_per_second', 0.0),
            bytes_per_second=parsed_data.get('bytes_per_second', 0.0),
            total_flows=parsed_data.get('total_flows', 0),
            total_alerts=parsed_data.get('total_alerts', 0),
            total_drops=parsed_data.get('total_drops', 0),
            memory_usage=parsed_data.get('memory_usage', 0.0),
            cpu_usage=parsed_data.get('cpu_usage', 0.0),
            rules_loaded=parsed_data.get('rules_loaded', 0),
            rules_failed=parsed_data.get('rules_failed', 0),
            raw_data=parsed_data['raw_data']
        )

    def create_system_log_record(self, parsed_data):
        """Crear registro de log del sistema"""
        SuricataSystemLog.objects.create(
            timestamp=parsed_data['timestamp'],
            level=parsed_data['level'],
            component=parsed_data.get('component'),
            message=parsed_data['message'],
            raw_line=parsed_data['raw_line']
        )

    def create_auto_report_from_suricata(self, parsed_data):
        """Crear reporte automático para alertas de alta prioridad de Suricata"""
        try:
            from EVENT_M.models import Area, Reporte

            # Obtener área de IA
            ai_area = Area.objects.filter(nombre='VANT-SIEM-AI-Analitic').first()
            if not ai_area:
                return

            # Crear descripción del reporte
            descripcion = f"""ALERTA DE ALTA PRIORIDAD DETECTADA POR SURICATA

Severidad: {parsed_data.get('severity', 'Unknown')}
Mensaje: {parsed_data.get('message', 'N/A')}
IP Origen: {parsed_data.get('src_ip', 'N/A')}
IP Destino: {parsed_data.get('dest_ip', 'N/A')}
Protocolo: {parsed_data.get('proto', 'N/A')}
Puerto Origen: {parsed_data.get('src_port', 'N/A')}
Puerto Destino: {parsed_data.get('dest_port', 'N/A')}
Categoría: {parsed_data.get('category', 'N/A')}
Signature ID: {parsed_data.get('signature_id', 'N/A')}

Esta alerta fue generada automáticamente por el sistema VANT-SIEM basado en logs de Suricata.
Requiere revisión inmediata por parte del equipo de seguridad."""

            # Crear reporte
            reporte = Reporte.objects.create(
                nombre_informante='Sistema VANT-SIEM AI',
                email_informante='ai@vantsiem.local',
                area=ai_area,
                descripcion=descripcion,
                estado_solucion='Nuevo'
            )

            self.stdout.write(
                self.style.SUCCESS(f'📋 Reporte automático creado para alerta Suricata: {parsed_data.get("message", "")[:50]}...')
            )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error creando reporte automático de Suricata: {e}')
            )

