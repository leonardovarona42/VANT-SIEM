#!/usr/bin/env python3
"""
Script para verificar el estado de los datos en la base de datos
"""
import os
import sys
import django

# Setup Django
sys.path.append('.')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from ids_ingest.models import SnortLog, SuricataEveAlert
from EVENT_M.models import Reporte, Incidente, Involucrado, Medida, MedidaIncidente
from django.db.models import Count

print('=== ESTADO ACTUAL DE LOS DATOS ===')
print(f'Snort Logs: {SnortLog.objects.count()}')
print(f'Suricata Alerts: {SuricataEveAlert.objects.count()}')
print(f'Reportes: {Reporte.objects.count()}')
print(f'Incidentes: {Incidente.objects.count()}')
print(f'Involucrados: {Involucrado.objects.count()}')
print(f'Medidas: {Medida.objects.count()}')
print(f'Medidas Aplicadas: {MedidaIncidente.objects.count()}')

print('\n=== TOP 10 IPs MÁS FRECUENTES EN SNORT ===')
for ip_data in SnortLog.objects.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10]:
    print(f'{ip_data["src_ip"]}: {ip_data["count"]}')

print('\n=== TOP 10 IPs MÁS FRECUENTES EN SURICATA ===')
for ip_data in SuricataEveAlert.objects.values('src_ip').annotate(count=Count('src_ip')).order_by('-count')[:10]:
    print(f'{ip_data["src_ip"]}: {ip_data["count"]}')

print('\n=== INCIDENTES POR ESTADO ===')
for estado_data in Incidente.objects.values('estado_solucion').annotate(count=Count('estado_solucion')).order_by('-count'):
    print(f'{estado_data["estado_solucion"]}: {estado_data["count"]}')

print('\n=== MUESTRA DE LOGS RECIENTES ===')
for log in SnortLog.objects.all()[:5]:
    print(f'Snort: {log.timestamp} - {log.src_ip}:{log.src_port} -> {log.dst_ip}:{log.dst_port} - {log.message[:50]}...')

for alert in SuricataEveAlert.objects.all()[:5]:
    print(f'Suricata: {alert.timestamp} - {alert.src_ip}:{alert.src_port} -> {alert.dest_ip}:{alert.dest_port} - {alert.message[:50]}...')