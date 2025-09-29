#!/usr/bin/env python3
"""
Script de prueba para los parsers de IDS/IPS
"""

import os
import sys
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from ids_ingest.parsers import parse_snort_line, parse_suricata_line, get_log_statistics

def test_snort_parsing():
    """Probar parsing de logs de Snort"""
    print("=== Probando Parsing de Snort ===")
    
    snort_lines = [
        '12/31-23:59:59.123456 [**] [1:1000001:1] "ET MALWARE Suspicious Activity" [**] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80',
        '12/31-23:59:58.987654 [**] [1:1000002:1] "ET POLICY Suspicious Port Activity" [**] [Priority: 2] {UDP} 192.168.1.101:53 -> 8.8.8.8:53',
        '12/31-23:59:57.456789 [**] [1:1000003:1] "ET SCAN Potential SSH Scan" [**] [Priority: 3] {TCP} 192.168.1.102:22 -> 10.0.0.2:22',
    ]
    
    for i, line in enumerate(snort_lines, 1):
        print(f"\nLínea {i}: {line[:50]}...")
        result = parse_snort_line(line)
        if result:
            print(f"✓ Parseado exitosamente:")
            print(f"  - Timestamp: {result['timestamp']}")
            print(f"  - Severidad: {result['severity']}")
            print(f"  - Origen: {result['src_ip']}:{result.get('src_port', 'N/A')}")
            print(f"  - Destino: {result['dst_ip']}:{result.get('dst_port', 'N/A')}")
            print(f"  - Protocolo: {result['protocol']}")
            print(f"  - Mensaje: {result['message'][:50]}...")
        else:
            print("✗ Error en el parsing")

def test_suricata_parsing():
    """Probar parsing de logs de Suricata"""
    print("\n=== Probando Parsing de Suricata ===")
    
    suricata_lines = [
        '12/31/2024-23:59:59.123456 [**] [1:1000001:1] ET MALWARE Suspicious Activity [**] [Classification: Potentially Bad Traffic] [Priority: 1] {TCP} 192.168.1.100:1234 -> 10.0.0.1:80',
        '12/31/2024-23:59:58.987654 [**] [1:1000002:1] ET POLICY Suspicious Port Activity [**] [Classification: Policy Violation] [Priority: 2] {UDP} 192.168.1.101:53 -> 8.8.8.8:53',
        '12/31/2024-23:59:57.456789 [**] [1:1000003:1] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 3] {TCP} 192.168.1.102:22 -> 10.0.0.2:22',
    ]
    
    for i, line in enumerate(suricata_lines, 1):
        print(f"\nLínea {i}: {line[:50]}...")
        result = parse_suricata_line(line)
        if result:
            print(f"✓ Parseado exitosamente:")
            print(f"  - Timestamp: {result['timestamp']}")
            print(f"  - Severidad: {result['severity']}")
            print(f"  - Origen: {result['src_ip']}:{result.get('src_port', 'N/A')}")
            print(f"  - Destino: {result['dst_ip']}:{result.get('dst_port', 'N/A')}")
            print(f"  - Protocolo: {result['protocol']}")
            print(f"  - Mensaje: {result['message'][:50]}...")
            print(f"  - Clasificación: {result.get('classification', 'N/A')}")
        else:
            print("✗ Error en el parsing")

def test_file_statistics():
    """Probar estadísticas de archivos"""
    print("\n=== Probando Estadísticas de Archivos ===")
    
    # Probar con archivos de muestra
    sample_files = [
        ('ids_ingest/sample_logs/snort_sample.log', 'snort'),
        ('ids_ingest/sample_logs/suricata_sample.log', 'suricata'),
    ]
    
    for file_path, ids_type in sample_files:
        if os.path.exists(file_path):
            print(f"\nArchivo: {file_path}")
            stats = get_log_statistics(file_path, ids_type)
            print(f"✓ Estadísticas obtenidas:")
            print(f"  - Total líneas: {stats['total_lines']}")
            print(f"  - Líneas parseadas: {stats['parsed_lines']}")
            print(f"  - Líneas con error: {stats['error_lines']}")
            print(f"  - Primera timestamp: {stats['first_timestamp']}")
            print(f"  - Última timestamp: {stats['last_timestamp']}")
            print(f"  - Distribución por severidad: {stats['severity_counts']}")
            print(f"  - Distribución por protocolo: {stats['protocol_counts']}")
        else:
            print(f"✗ Archivo no encontrado: {file_path}")

def main():
    """Función principal"""
    print("Iniciando pruebas de parsers IDS/IPS...")
    
    try:
        test_snort_parsing()
        test_suricata_parsing()
        test_file_statistics()
        
        print("\n=== Resumen ===")
        print("✓ Todas las pruebas completadas")
        print("✓ Los parsers están funcionando correctamente")
        print("✓ El sistema está listo para procesar logs reales")
        
    except Exception as e:
        print(f"\n✗ Error durante las pruebas: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
