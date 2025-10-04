import re
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from django.utils import timezone

logger = logging.getLogger(__name__)

# Patrones de regex para diferentes formatos de Suricata
SURICATA_PATTERNS = [
    # Formato estándar de Suricata
    re.compile(
        r'(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Classification:\s+(?P<classification>.*?)\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)'
    ),
    # Formato alternativo de Suricata (sin clasificación)
    re.compile(
        r'(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)'
    ),
    # Formato JSON de Suricata
    re.compile(
        r'{"timestamp":"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)","flow_id":\d+,"pcap_cnt":\d+,"event_type":"alert","src_ip":"(?P<src_ip>[\d\.]+)","src_port":(?P<src_port>\d+),"dest_ip":"(?P<dst_ip>[\d\.]+)","dest_port":(?P<dst_port>\d+),"proto":"(?P<protocol>\w+)","alert":{"action":"\w+","gid":(?P<gid>\d+),"signature_id":(?P<sid>\d+),"rev":(?P<rev>\d+),"signature":"(?P<message>.*?)","category":"\w+","severity":(?P<priority>\d+)}'
    )
]

# Patrones de regex para diferentes formatos de Snort
SNORT_PATTERNS = [
    # Formato estándar de Snort (alert.full)
    re.compile(
        r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Classification:\s+(?P<classification>.*?)\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)\s+(?P<protocol>\w+)\s+TTL:(?P<ttl>\d+)\s+TOS:(?P<tos>0x[0-9a-fA-F]+)\s+ID:(?P<id>\d+)\s+IpLen:(?P<iplen>\d+)\s+DgmLen:(?P<dgmlen>\d+)\s+(?P<flags>.*?)\s+Seq:\s+(?P<seq>0x[0-9a-fA-F]+)\s+Ack:\s+(?P<ack>0x[0-9a-fA-F]+)\s+Win:\s+(?P<win>0x[0-9a-fA-F]+)\s+TcpLen:\s+(?P<tcplen>\d+)'
    ),
    # Formato alternativo de Snort (sin clasificación)
    re.compile(
        r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)\s+(?P<protocol>\w+)\s+TTL:(?P<ttl>\d+)\s+TOS:(?P<tos>0x[0-9a-fA-F]+)\s+ID:(?P<id>\d+)\s+IpLen:(?P<iplen>\d+)\s+DgmLen:(?P<dgmlen>\d+)\s+(?P<flags>.*?)\s+Seq:\s+(?P<seq>0x[0-9a-fA-F]+)\s+Ack:\s+(?P<ack>0x[0-9a-fA-F]+)\s+Win:\s+(?P<win>0x[0-9a-fA-F]+)\s+TcpLen:\s+(?P<tcplen>\d+)'
    ),
    # Formato simplificado de Snort
    re.compile(
        r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)\s+(?P<protocol>\w+)\s+TTL:(?P<ttl>\d+)\s+TOS:(?P<tos>0x[0-9a-fA-F]+)\s+ID:(?P<id>\d+)\s+IpLen:(?P<iplen>\d+)\s+DgmLen:(?P<dgmlen>\d+)\s+(?P<flags>.*?)\s+Seq:\s+(?P<seq>0x[0-9a-fA-F]+)\s+Ack:\s+(?P<ack>0x[0-9a-fA-F]+)\s+Win:\s+(?P<win>0x[0-9a-fA-F]+)\s+TcpLen:\s+(?P<tcplen>\d+)'
    ),
    # Formato alerts.fast (NUEVO) - con clasificación
    re.compile(
        r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Classification:\s+(?P<classification>.*?)\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+)(?::(?P<src_port>\d+))?\s+->\s+(?P<dst_ip>[\d\.]+)(?::(?P<dst_port>\d+))?'
    ),
    # Formato alerts.fast sin clasificación (NUEVO)
    re.compile(
        r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+)(?::(?P<src_port>\d+))?\s+->\s+(?P<dst_ip>[\d\.]+)(?::(?P<dst_port>\d+))?'
    ),
    # Formato alerts.csv (NUEVO) - ajustado para espacios después del timestamp
    re.compile(
        r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s*,\s*"(?P<message>.*?)",,,(?P<src_port>\d+),(?P<dst_port>\d+),(?P<protocol>\w+),,'
    )
]

def parse_timestamp(timestamp_str: str, format_type: str) -> Optional[datetime]:
    """Parse timestamp string to timezone-aware datetime object with error handling."""
    try:
        if format_type == 'suricata':
            # Formato: MM/DD/YYYY-HH:MM:SS.microseconds
            dt = datetime.strptime(timestamp_str, "%m/%d/%Y-%H:%M:%S.%f")
            return timezone.make_aware(dt)
        elif format_type == 'snort':
            # CORRECCIÓN: Formato: MM/DD-HH:MM:SS.microseconds (año actual)
            dt = datetime.strptime(timestamp_str, "%m/%d-%H:%M:%S.%f")
            dt = dt.replace(year=timezone.now().year)
            return timezone.make_aware(dt)
        elif format_type == 'suricata_json':
            # Formato ISO: YYYY-MM-DDTHH:MM:SS.microseconds±HHMM
            # Remover la Z si existe y manejar timezone offset
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            elif timestamp_str.endswith(('+0000', '-0000')):
                # Convertir formato ±HHMM a ±HH:MM
                tz_offset = timestamp_str[-5:]
                timestamp_str = timestamp_str[:-5] + tz_offset[:3] + ':' + tz_offset[3:]
            dt = datetime.fromisoformat(timestamp_str)
            # Si ya tiene timezone info, devolverlo; si no, hacerlo aware
            if dt.tzinfo is None:
                return timezone.make_aware(dt)
            return dt
    except ValueError as e:
        logger.warning(f"Error parsing timestamp '{timestamp_str}': {e}")
        return None
    return None

def extract_ip_port(ip_port_str: str) -> tuple:
    """Extract IP and port from string like '192.168.1.1:80' or '192.168.1.1'."""
    if ':' in ip_port_str:
        ip, port = ip_port_str.rsplit(':', 1)
        try:
            return ip, int(port)
        except ValueError:
            return ip, None
    return ip_port_str, None

def parse_suricata_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse Suricata log line with multiple format support."""
    if not line or not line.strip():
        return None
    
    line = line.strip()
    
    # Try each pattern until one matches
    for i, pattern in enumerate(SURICATA_PATTERNS):
        match = pattern.match(line)
        if match:
            try:
                # Determine format type based on pattern index
                if i == 2:  # JSON format
                    format_type = 'suricata_json'
                else:
                    format_type = 'suricata'
                
                # Parse timestamp
                timestamp = parse_timestamp(match.group('timestamp'), format_type)
                if not timestamp:
                    continue
                
                # Extract IPs and ports
                src_ip = match.group('src_ip')
                dst_ip = match.group('dst_ip')
                src_port = match.group('src_port') if 'src_port' in match.groupdict() else None
                dst_port = match.group('dst_port') if 'dst_port' in match.groupdict() else None
                
                # Handle IP:port format if needed
                if ':' in src_ip:
                    src_ip, src_port = extract_ip_port(src_ip)
                if ':' in dst_ip:
                    dst_ip, dst_port = extract_ip_port(dst_ip)
                
                # Convert ports to integers
                if src_port:
                    try:
                        src_port = int(src_port)
                    except ValueError:
                        src_port = None
                if dst_port:
                    try:
                        dst_port = int(dst_port)
                    except ValueError:
                        dst_port = None
                
                # Determine severity level based on priority
                priority = int(match.group('priority'))
                if priority <= 1:
                    severity = 'Critical'
                elif priority <= 2:
                    severity = 'High'
                elif priority <= 3:
                    severity = 'Medium'
                else:
                    severity = 'Low'
                
                return {
                    'timestamp': timestamp,
                    'severity': severity,
                    'priority': priority,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': match.group('protocol'),
                    'message': match.group('message'),
                    'gid': int(match.group('gid')),
                    'sid': int(match.group('sid')),
                    'rev': int(match.group('rev')),
                    'classification': match.group('classification') if 'classification' in match.groupdict() else None,
                    'raw': line
                }
            except (ValueError, KeyError) as e:
                logger.warning(f"Error parsing Suricata line with pattern {i}: {e}")
                continue
    
    logger.debug(f"No pattern matched for Suricata line: {line[:100]}...")
    return None

def parse_snort_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse Snort log line with multiple format support."""
    if not line or not line.strip():
        return None
    
    line = line.strip()
    
    # Try each pattern until one matches
    for i, pattern in enumerate(SNORT_PATTERNS):
        match = pattern.match(line)
        if match:
            try:
                # Parse timestamp
                timestamp = parse_timestamp(match.group('timestamp'), 'snort')
                if not timestamp:
                    continue
                
                # Extract IPs and ports
                src_ip = match.group('src_ip')
                dst_ip = match.group('dst_ip')
                src_port = match.group('src_port') if 'src_port' in match.groupdict() else None
                dst_port = match.group('dst_port') if 'dst_port' in match.groupdict() else None
                
                # Handle IP:port format if needed
                if ':' in src_ip:
                    src_ip, src_port = extract_ip_port(src_ip)
                if ':' in dst_ip:
                    dst_ip, dst_port = extract_ip_port(dst_ip)
                
                # Convert ports to integers
                if src_port:
                    try:
                        src_port = int(src_port)
                    except ValueError:
                        src_port = None
                if dst_port:
                    try:
                        dst_port = int(dst_port)
                    except ValueError:
                        dst_port = None
                
                # Determine severity level based on priority
                priority = int(match.group('priority'))
                if priority <= 1:
                    severity = 'Critical'
                elif priority <= 2:
                    severity = 'High'
                elif priority <= 3:
                    severity = 'Medium'
                else:
                    severity = 'Low'
                
                return {
                    'timestamp': timestamp,
                    'severity': severity,
                    'priority': priority,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': match.group('protocol'),
                    'message': match.group('message'),
                    'gid': int(match.group('gid')),
                    'sid': int(match.group('sid')),
                    'rev': int(match.group('rev')),
                    'classification': match.group('classification') if 'classification' in match.groupdict() else None,
                    'raw': line
                }
            except (ValueError, KeyError) as e:
                logger.warning(f"Error parsing Snort line with pattern {i}: {e}")
                continue
    
    logger.debug(f"No pattern matched for Snort line: {line[:100]}...")
    return None

def validate_log_line(line: str, ids_type: str) -> bool:
    """Validate if a log line is likely to be from the specified IDS type."""
    if not line or not line.strip():
        return False

    line = line.strip()

    if ids_type == 'suricata':
        # Check for Suricata-specific patterns
        return any(pattern.search(line) for pattern in SURICATA_PATTERNS)
    elif ids_type == 'snort':
        # Check for Snort-specific patterns (incluyendo los nuevos formatos)
        return any(pattern.search(line) for pattern in SNORT_PATTERNS)

    return False

def get_log_statistics(log_path: str, ids_type: str) -> Dict[str, Any]:
    """Get statistics about a log file."""
    stats = {
        'total_lines': 0,
        'parsed_lines': 0,
        'error_lines': 0,
        'last_timestamp': None,
        'first_timestamp': None,
        'severity_counts': {},
        'protocol_counts': {}
    }
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                stats['total_lines'] += 1
                
                if ids_type == 'suricata':
                    parsed = parse_suricata_line(line)
                elif ids_type == 'snort':
                    parsed = parse_snort_line(line)
                else:
                    continue
                
                if parsed:
                    stats['parsed_lines'] += 1
                    
                    # Update timestamp range
                    if not stats['first_timestamp'] or parsed['timestamp'] < stats['first_timestamp']:
                        stats['first_timestamp'] = parsed['timestamp']
                    if not stats['last_timestamp'] or parsed['timestamp'] > stats['last_timestamp']:
                        stats['last_timestamp'] = parsed['timestamp']
                    
                    # Count severities
                    severity = parsed['severity']
                    stats['severity_counts'][severity] = stats['severity_counts'].get(severity, 0) + 1
                    
                    # Count protocols
                    protocol = parsed['protocol']
                    stats['protocol_counts'][protocol] = stats['protocol_counts'].get(protocol, 0) + 1
                else:
                    stats['error_lines'] += 1
                    
                # Limit processing for very large files
                if line_num > 10000:
                    break
                    
    except Exception as e:
        logger.error(f"Error reading log file {log_path}: {e}")
        stats['error'] = str(e)
    
    return stats

# Parsers específicos para diferentes tipos de logs de Suricata

def parse_suricata_eve_json(line: str) -> Optional[Dict[str, Any]]:
    """Parse Suricata EVE JSON log line"""
    try:
        data = json.loads(line.strip())
        
        # Parse timestamp - formato real: "2024-07-16T20:00:44.105400-0600"
        timestamp_str = data.get('timestamp', '')
        if timestamp_str:
            try:
                # El formato real es válido, solo necesitamos manejar casos edge
                timestamp_str = timestamp_str.replace('Z', '+00:00')
                
                # Manejar formato sin segundos en zona horaria (-0600 -> -06:00)
                if re.search(r'[+-]\d{4}$', timestamp_str):
                    timestamp_str = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', timestamp_str)
                
                timestamp = datetime.fromisoformat(timestamp_str)
            except ValueError as e:
                logger.warning(f"Error parsing timestamp '{timestamp_str}': {e}")
                return None
        else:
            return None
        
        event_type = data.get('event_type', '')
        
        # Handle different event types
        if event_type == 'alert':
            alert_data = data.get('alert', {})
            return {
                'timestamp': timestamp,
                'event_type': event_type,
                'src_ip': data.get('src_ip', ''),
                'dest_ip': data.get('dest_ip', ''),
                'src_port': data.get('src_port'),
                'dest_port': data.get('dest_port'),
                'proto': data.get('proto', ''),
                'signature_id': alert_data.get('signature_id', 0),
                'signature_rev': alert_data.get('rev', 0),
                'category': alert_data.get('category', ''),
                'action': alert_data.get('action', 'alert'),
                'severity': alert_data.get('severity', 1),
                'message': alert_data.get('signature', ''),
                'raw_data': data
            }
        elif event_type == 'flow':
            flow_data = data.get('flow', {})
            
            # Parsear timestamps de flow con manejo de errores
            start_time = timestamp
            end_time = timestamp
            
            if flow_data.get('start'):
                try:
                    start_str = flow_data.get('start', '')
                    if start_str:
                        start_str = start_str.replace('Z', '+00:00')
                        if re.search(r'[+-]\d{4}$', start_str):
                            start_str = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', start_str)
                        start_time = datetime.fromisoformat(start_str)
                except (ValueError, TypeError):
                    start_time = timestamp
            
            if flow_data.get('end'):
                try:
                    end_str = flow_data.get('end', '')
                    if end_str:
                        end_str = end_str.replace('Z', '+00:00')
                        if re.search(r'[+-]\d{4}$', end_str):
                            end_str = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', end_str)
                        end_time = datetime.fromisoformat(end_str)
                except (ValueError, TypeError):
                    end_time = timestamp
            
            return {
                'timestamp': timestamp,
                'event_type': event_type,
                'src_ip': data.get('src_ip', ''),
                'dest_ip': data.get('dest_ip', ''),
                'src_port': data.get('src_port', 0),
                'dest_port': data.get('dest_port', 0),
                'proto': data.get('proto', ''),
                'app_proto': data.get('app_proto', ''),
                'state': flow_data.get('state', ''),
                'pkts_toserver': flow_data.get('pkts_toserver', 0),
                'pkts_toclient': flow_data.get('pkts_toclient', 0),
                'bytes_toserver': flow_data.get('bytes_toserver', 0),
                'bytes_toclient': flow_data.get('bytes_toclient', 0),
                'start_time': start_time,
                'end_time': end_time,
                'age': flow_data.get('age', 0),
                'raw_data': data
            }
        elif event_type == 'stats':
            stats_data = data.get('stats', {})
            return {
                'timestamp': timestamp,
                'uptime': stats_data.get('uptime', 0),
                'total_packets': stats_data.get('total_packets', 0),
                'total_bytes': stats_data.get('total_bytes', 0),
                'packets_per_second': stats_data.get('packets_per_second', 0.0),
                'bytes_per_second': stats_data.get('bytes_per_second', 0.0),
                'total_flows': stats_data.get('total_flows', 0),
                'total_alerts': stats_data.get('total_alerts', 0),
                'total_drops': stats_data.get('total_drops', 0),
                'memory_usage': stats_data.get('memory_usage', 0.0),
                'cpu_usage': stats_data.get('cpu_usage', 0.0),
                'rules_loaded': stats_data.get('rules_loaded', 0),
                'rules_failed': stats_data.get('rules_failed', 0),
                'raw_data': data
            }
        elif event_type in ['http', 'dns', 'tls', 'ssh', 'fileinfo']:
            # Handle protocol-specific events
            return {
                'timestamp': timestamp,
                'event_type': event_type,
                'src_ip': data.get('src_ip', ''),
                'dest_ip': data.get('dest_ip', ''),
                'src_port': data.get('src_port'),
                'dest_port': data.get('dest_port'),
                'proto': data.get('proto', ''),
                'raw_data': data
            }
        
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        logger.warning(f"Error parsing EVE JSON line: {e}")
        return None
    
    return None

def parse_suricata_fast_log(line: str) -> Optional[Dict[str, Any]]:
    """Parse Suricata fast.log line"""
    if not line or not line.strip():
        return None
    
    line = line.strip()
    
    # Pattern for fast.log format: MM/DD/YYYY-HH:MM:SS.microseconds  [**] [gid:sid:rev] message [**] [Classification: classification] [Priority: priority] {protocol} src_ip:src_port -> dest_ip:dest_port
    pattern = re.compile(
        r'(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<message>.*?)\s+\[\*\*\]\s+\[Classification:\s+(?P<classification>.*?)\]\s+\[Priority:\s+(?P<priority>\d+)\]\s+\{(?P<protocol>\w+)\}\s+(?P<src_ip>[\d\.]+):(?P<src_port>\d+)\s+->\s+(?P<dest_ip>[\d\.]+):(?P<dest_port>\d+)'
    )

    match = pattern.match(line)
    if match:
        try:
            timestamp = parse_timestamp(match.group('timestamp'), 'suricata')
            if not timestamp:
                logger.warning(f"[fast.log] Ignorado: timestamp inválido en línea: {line}")
                return None

            priority = int(match.group('priority'))
            if priority <= 1:
                severity = 'Critical'
            elif priority <= 2:
                severity = 'High'
            elif priority <= 3:
                severity = 'Medium'
            else:
                severity = 'Low'

            # Permitir puertos en 0 y tolerar espacios extra
            try:
                src_port = int(match.group('src_port'))
            except Exception:
                src_port = 0
            try:
                dest_port = int(match.group('dest_port'))
            except Exception:
                dest_port = 0

            return {
                'timestamp': timestamp,
                'severity': severity,
                'priority': priority,
                'src_ip': match.group('src_ip'),
                'dest_ip': match.group('dest_ip'),
                'src_port': src_port,
                'dest_port': dest_port,
                'protocol': match.group('protocol'),
                'message': match.group('message'),
                'signature_id': int(match.group('sid')),
                'signature_rev': int(match.group('rev')),
                'classification': match.group('classification'),
                'raw': line
            }
        except (ValueError, KeyError) as e:
            logger.warning(f"[fast.log] Error parsing línea: {e} | Línea: {line}")
            return None
    else:
        logger.warning(f"[fast.log] Línea ignorada (no matchea regex): {line}")
    return None

def parse_suricata_stats_log(line: str) -> Optional[Dict[str, Any]]:
    """Parse Suricata stats.log line"""
    if not line or not line.strip():
        return None
    
    line = line.strip()
    
    # Pattern for stats.log format: Date: MM/DD/YYYY -- HH:MM:SS (uptime: Xd, XXh XXm XXs)
    # Skip separator lines and header lines
    if line.startswith('---') or line.startswith('Counter') or line.startswith('Date:'):
        return None
    
    # Pattern for counter lines: Counter Name | TM Name | Value
    pattern = re.compile(r'(?P<counter_name>[^|]+)\s*\|\s*(?P<tm_name>[^|]+)\s*\|\s*(?P<value>[\d\.]+)')
    
    match = pattern.match(line)
    if match:
        try:
            counter_name = match.group('counter_name').strip()
            tm_name = match.group('tm_name').strip()
            value = float(match.group('value'))
            
            # Extract timestamp from previous lines if available
            # For now, use current time as we don't have timestamp in counter lines
            timestamp = timezone.now()
            
            # Map counter names to our fields
            stats = {
                'timestamp': timestamp,
                'uptime': 0,
                'total_packets': 0,
                'total_bytes': 0,
                'packets_per_second': 0.0,
                'bytes_per_second': 0.0,
                'total_flows': 0,
                'total_alerts': 0,
                'total_drops': 0,
                'memory_usage': 0.0,
                'cpu_usage': 0.0,
                'rules_loaded': 0,
                'rules_failed': 0,
                'raw_data': {'counter_name': counter_name, 'tm_name': tm_name, 'value': value}
            }
            
            # Map specific counters
            if 'flow.mgr.rows_per_sec' in counter_name:
                stats['packets_per_second'] = value
            elif 'flow.spare' in counter_name:
                stats['total_flows'] = value
            elif 'tcp.memuse' in counter_name:
                stats['memory_usage'] = value / 1024 / 1024  # Convert to MB
            elif 'flow.memuse' in counter_name:
                stats['memory_usage'] = value / 1024 / 1024  # Convert to MB
            
            return stats
            
        except (ValueError, KeyError) as e:
            logger.warning(f"Error parsing stats.log line: {e}")
            return None
    
    return None

def parse_suricata_system_log(line: str) -> Optional[Dict[str, Any]]:
    """Parse Suricata system log line"""
    if not line or not line.strip():
        return None
    
    line = line.strip()
    
    # Pattern for suricata.log format: [timestamp] <level> [component] message
    pattern = re.compile(r'\[(?P<timestamp>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)\]\s+<(?P<level>\w+)>\s+(?:\[(?P<component>[^\]]+)\]\s+)?(?P<message>.*)')
    
    match = pattern.match(line)
    if match:
        try:
            timestamp = parse_timestamp(match.group('timestamp'), 'suricata')
            if not timestamp:
                return None
            
            level = match.group('level').upper()
            component = match.group('component') if match.group('component') else None
            message = match.group('message')
            
            return {
                'timestamp': timestamp,
                'level': level,
                'component': component,
                'message': message,
                'raw_line': line
            }
            
        except (ValueError, KeyError) as e:
            logger.warning(f"Error parsing system log line: {e}")
            return None
    
    return None

def get_suricata_log_type(file_path: str) -> str:
    """Determine the type of Suricata log file based on filename"""
    filename = file_path.lower()
    
    if 'eve.json' in filename:
        return 'eve_json'
    elif 'fast.log' in filename:
        return 'fast_log'
    elif 'stats.log' in filename:
        return 'stats_log'
    elif 'suricata.log' in filename:
        return 'system_log'
    else:
        return 'unknown'

def parse_suricata_log_by_type(line: str, log_type: str) -> Optional[Dict[str, Any]]:
    """Parse Suricata log line based on log type"""
    if log_type == 'eve_json':
        return parse_suricata_eve_json(line)
    elif log_type == 'fast_log':
        return parse_suricata_fast_log(line)
    elif log_type == 'stats_log':
        return parse_suricata_stats_log(line)
    elif log_type == 'system_log':
        return parse_suricata_system_log(line)
    else:
        return None

def parse_snort_alert_full(line: str) -> Optional[Dict[str, Any]]:
    """Parse Snort alert.full log line"""
    if not line or not line.strip():
        return None
    
    line = line.strip()
    
    # Try each pattern until one matches
    for pattern in SNORT_PATTERNS:
        match = pattern.match(line)
        if match:
            try:
                # Extract basic fields
                gid = int(match.group('gid'))
                sid = int(match.group('sid'))
                rev = int(match.group('rev'))
                message = match.group('message')
                priority = int(match.group('priority'))
                timestamp_str = match.group('timestamp')
                src_ip = match.group('src_ip')
                dst_ip = match.group('dst_ip')
                src_port = int(match.group('src_port'))
                dst_port = int(match.group('dst_port'))
                protocol = match.group('protocol')
                
                # Parse timestamp
                timestamp = parse_timestamp(timestamp_str, 'snort')
                if not timestamp:
                    logger.warning(f"Could not parse timestamp: {timestamp_str}")
                    continue
                
                # Extract additional fields if available
                classification = match.group('classification') if 'classification' in match.groupdict() else None
                ttl = int(match.group('ttl')) if 'ttl' in match.groupdict() else None
                tos = match.group('tos') if 'tos' in match.groupdict() else None
                packet_id = int(match.group('id')) if 'id' in match.groupdict() else None
                ip_len = int(match.group('iplen')) if 'iplen' in match.groupdict() else None
                dgm_len = int(match.group('dgmlen')) if 'dgmlen' in match.groupdict() else None
                flags = match.group('flags') if 'flags' in match.groupdict() else None
                seq = match.group('seq') if 'seq' in match.groupdict() else None
                ack = match.group('ack') if 'ack' in match.groupdict() else None
                win = match.group('win') if 'win' in match.groupdict() else None
                tcp_len = int(match.group('tcplen')) if 'tcplen' in match.groupdict() else None
                
                return {
                    'timestamp': timestamp,
                    'gid': gid,
                    'sid': sid,
                    'rev': rev,
                    'message': message,
                    'priority': priority,
                    'classification': classification,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'ttl': ttl,
                    'tos': tos,
                    'packet_id': packet_id,
                    'ip_len': ip_len,
                    'dgm_len': dgm_len,
                    'flags': flags,
                    'seq': seq,
                    'ack': ack,
                    'win': win,
                    'tcp_len': tcp_len,
                    'raw_line': line
                }
                
            except (ValueError, KeyError) as e:
                logger.warning(f"Error parsing Snort alert line: {e}")
                continue
    
    # If no pattern matches, try to extract basic info from the line
    logger.debug(f"No pattern matched for Snort line: {line[:100]}...")
    return None

def parse_snort_alert_block(lines: List[str]) -> Optional[Dict[str, Any]]:
    """Parsea un bloque multi-línea de alert.full (Snort) y devuelve un dict normalizado.
    Un bloque típico contiene:
      1) Línea con [**] [gid:sid:rev] mensaje [**]
      2) Línea de clasificación/prioridad
      3) Línea con timestamp e IPs y puertos
      4) Línea con detalles de protocolo (TTL, TOS, ID, IpLen, DgmLen, flags, Seq, Ack, Win, TcpLen)
    Algunas variantes pueden omitir campos o usar PROTO: para no-TCP.
    """
    if not lines:
        return None
    # Limpiar líneas vacías finales/iniciales
    content = [l.strip() for l in lines if l.strip()]
    if not content:
        return None

    # Unir contenido para facilitar algunos matches pero mantener líneas
    header = content[0] if len(content) > 0 else ''
    classprio = content[1] if len(content) > 1 else ''
    time_ip = content[2] if len(content) > 2 else ''
    proto_line = content[3] if len(content) > 3 else ''

    # Extraer cabecera [**] [gid:sid:rev] message [**]
    m_header = re.search(r"\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<message>.*?)\s*\[\*\*\]", header)
    if not m_header:
        return None
    gid = int(m_header.group('gid'))
    sid = int(m_header.group('sid'))
    rev = int(m_header.group('rev'))
    message = m_header.group('message')

    # Extraer clasificación/prioridad si existe
    classification = None
    priority = 3
    m_cp = re.search(r"Classification:\s*(?P<classification>[^\]]+)\]\s*\[Priority:\s*(?P<priority>\d+)\]", classprio)
    if m_cp:
        classification = m_cp.group('classification').strip()
        try:
            priority = int(m_cp.group('priority'))
        except ValueError:
            priority = 3

    # Extraer timestamp e IPs/puertos: MM/DD-HH:MM:SS.micro IP:port -> IP:port o sin puertos
    m_time = re.search(r"(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+(?P<src>[^\s]+)\s*->\s*(?P<dst>[^\s]+)", time_ip)
    timestamp = None
    src_ip = dst_ip = ''
    src_port = dst_port = None
    if m_time:
        timestamp = parse_timestamp(m_time.group('timestamp'), 'snort')
        s_src = m_time.group('src')
        s_dst = m_time.group('dst')
        src_ip, src_port = extract_ip_port(s_src)
        dst_ip, dst_port = extract_ip_port(s_dst)

    # Extraer protocolo y campos TCP si están presentes
    protocol = None
    ttl = None
    tos = None
    packet_id = None
    ip_len = None
    dgm_len = None
    flags = None
    seq = None
    ack = None
    win = None
    tcp_len = None

    # Casos TCP: línea con 'TCP TTL:' etc.
    if proto_line.startswith('TCP'):
        protocol = 'TCP'
        # TTL
        m = re.search(r"TTL:(?P<ttl>\d+)", proto_line)
        if m:
            ttl = int(m.group('ttl'))
        # TOS
        m = re.search(r"TOS:(?P<tos>0x[0-9a-fA-F]+)", proto_line)
        if m:
            tos = m.group('tos')
        # ID
        m = re.search(r"ID:(?P<id>\d+)", proto_line)
        if m:
            packet_id = int(m.group('id'))
        # IpLen
        m = re.search(r"IpLen:(?P<iplen>\d+)", proto_line)
        if m:
            ip_len = int(m.group('iplen'))
        # DgmLen
        m = re.search(r"DgmLen:(?P<dgmlen>\d+)", proto_line)
        if m:
            dgm_len = int(m.group('dgmlen'))
        # Flags (***AP*** etc.)
        m = re.search(r"(\*+\w*\*+)", proto_line)
        if m:
            flags = m.group(1)
        # Seq / Ack / Win / TcpLen pueden estar en la misma o siguiente línea
        rest = ' '.join(content[3:])
        m = re.search(r"Seq:\s*(?P<seq>0x[0-9a-fA-F]+)", rest)
        if m:
            seq = m.group('seq')
        m = re.search(r"Ack:\s*(?P<ack>0x[0-9a-fA-F]+)", rest)
        if m:
            ack = m.group('ack')
        m = re.search(r"Win:\s*(?P<win>0x[0-9a-fA-F]+|\d+)", rest)
        if m:
            win = m.group('win')
        m = re.search(r"TcpLen:\s*(?P<tcplen>\d+)", rest)
        if m:
            tcp_len = int(m.group('tcplen'))
    else:
        # No TCP: intentar detectar protocolo en la línea (e.g., PROTO:254)
        m_proto = re.search(r"^([A-Z]+)|PROTO:(?P<proto>\d+)", proto_line)
        if m_proto:
            protocol = m_proto.group(1) or f"PROTO:{m_proto.group('proto')}"

    if not timestamp:
        return None

    return {
        'timestamp': timestamp,
        'gid': gid,
        'sid': sid,
        'rev': rev,
        'message': message,
        'priority': priority,
        'classification': classification,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol or 'TCP',
        'ttl': ttl,
        'tos': tos,
        'packet_id': packet_id,
        'ip_len': ip_len,
        'dgm_len': dgm_len,
        'flags': flags,
        'seq': seq,
        'ack': ack,
        'win': win,
        'tcp_len': tcp_len,
        'raw_line': '\n'.join(content)
    }

def parse_snort_csv_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse Snort alerts.csv log line"""
    if not line or not line.strip():
        return None

    line = line.strip()

    # Pattern for alerts.csv format: timestamp ,"message",,,src_port,dst_port,protocol,,
    pattern = re.compile(
        r'(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s*,\s*"(?P<message>.*?)",,,(?P<src_port>\d+),(?P<dst_port>\d+),(?P<protocol>\w+),,'
    )

    match = pattern.match(line)
    if match:
        try:
            timestamp = parse_timestamp(match.group('timestamp'), 'snort')
            if not timestamp:
                logger.warning(f"[alerts.csv] Timestamp inválido en línea: {line}")
                return None

            # Para CSV, no tenemos IPs, GID, SID, etc. - usar valores por defecto
            return {
                'timestamp': timestamp,
                'severity': 'Medium',  # Default para CSV
                'priority': 3,  # Default para CSV
                'src_ip': '0.0.0.0',  # No disponible en CSV
                'dst_ip': '0.0.0.0',  # No disponible en CSV
                'src_port': int(match.group('src_port')),
                'dst_port': int(match.group('dst_port')),
                'protocol': match.group('protocol'),
                'message': match.group('message'),
                'gid': 1,  # Default
                'sid': 0,  # Default
                'rev': 0,  # Default
                'classification': None,  # No disponible en CSV
                'raw': line
            }
        except (ValueError, KeyError) as e:
            logger.warning(f"[alerts.csv] Error parsing línea: {e} | Línea: {line}")
            return None
    else:
        logger.warning(f"[alerts.csv] Línea ignorada (no matchea regex): {line}")
    return None

def get_snort_log_type(file_path: str) -> str:
    """Determine the type of Snort log file based on filename"""
    filename = file_path.lower()

    if 'alert.full' in filename:
        return 'alert_full'
    elif 'alert.fast' in filename:
        return 'alert_fast'
    elif 'alerts.csv' in filename:
        return 'alerts_csv'
    else:
        return 'unknown'

def parse_snort_log_by_type(line: str, log_type: str) -> Optional[Dict[str, Any]]:
    """Parse Snort log line based on log type"""
    if log_type == 'alert_full':
        return parse_snort_alert_full(line)
    elif log_type == 'alert_fast':
        return parse_snort_line(line)  # Usar parser principal con patrón alerts.fast
    elif log_type == 'alerts_csv':
        return parse_snort_csv_line(line)
    else:
        logger.warning(f"Unsupported Snort log type: {log_type}")
        return None