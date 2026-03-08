#!/usr/bin/env python
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from opensearch_ui.services import ingest_service
from opensearch_ui.models import IDSIngestConfig, SnortLog, SuricataEveAlert, SuricataLog
from django.utils import timezone
from datetime import timedelta

print("=== ANÁLISIS DE INGESTIÓN EN TIEMPO REAL ===")

# 1. Verificar configuraciones
configs = IDSIngestConfig.objects.all()
print(f"\n1. CONFIGURACIONES ({configs.count()}):")
for config in configs:
    print(f"   {config.ids_type.upper()}: {config.log_path} (activa: {config.active})")
    print(f"   Última ejecución: {config.last_run}")
    print(f"   Última posición: {config.last_position}")

# 2. Verificar datos en BD
print(f"\n2. DATOS EN BASE DE DATOS:")
snort_count = SnortLog.objects.count()
suricata_count = SuricataLog.objects.count()
suricata_eve_count = SuricataEveAlert.objects.count()

print(f"   SnortLog: {snort_count} registros")
print(f"   SuricataLog: {suricata_count} registros")
print(f"   SuricataEveAlert: {suricata_eve_count} registros")

# 3. Verificar logs recientes (últimos 5 minutos)
now = timezone.now()
recent_time = now - timedelta(minutes=5)

recent_snort = SnortLog.objects.filter(timestamp__gte=recent_time).count()
recent_suricata = SuricataLog.objects.filter(timestamp__gte=recent_time).count()
recent_eve = SuricataEveAlert.objects.filter(timestamp__gte=recent_time).count()

print(f"\n3. LOGS RECIENTES (últimos 5 min):")
print(f"   SnortLog: {recent_snort}")
print(f"   SuricataLog: {recent_suricata}")
print(f"   SuricataEveAlert: {recent_eve}")

# 4. Verificar último log de cada tipo
print(f"\n4. ÚLTIMOS LOGS:")
last_snort = SnortLog.objects.order_by('-timestamp').first()
if last_snort:
    print(f"   Último Snort: {last_snort.timestamp} - {last_snort.message[:50]}")
else:
    print("   No hay logs de Snort")

last_suricata = SuricataLog.objects.order_by('-timestamp').first()
if last_suricata:
    print(f"   Último SuricataLog: {last_suricata.timestamp} - {last_suricata.message[:50]}")
else:
    print("   No hay logs de SuricataLog")

last_eve = SuricataEveAlert.objects.order_by('-timestamp').first()
if last_eve:
    print(f"   Último SuricataEveAlert: {last_eve.timestamp} - {last_eve.message[:50]}")
else:
    print("   No hay logs de SuricataEveAlert")

# 5. Estado del servicio
print(f"\n5. ESTADO DEL SERVICIO:")
status = ingest_service.get_status()
print(f"   Ejecutándose: {status['running']}")
print(f"   Hilos activos: {status['active_threads']}")
print(f"   Estadísticas: {status['stats']}")

# 6. Ejecutar ingestión manual
print(f"\n6. EJECUTANDO INGESTIÓN MANUAL...")
try:
    for config in configs.filter(active=True):
        print(f"   Procesando {config.ids_type}...")
        ingest_service._process_config(config)
        print(f"   ✓ {config.ids_type} procesado")
except Exception as e:
    print(f"   ✗ Error: {e}")

# 7. Verificar nuevos datos
print(f"\n7. VERIFICACIÓN POST-INGESTIÓN:")
new_snort_count = SnortLog.objects.count()
new_suricata_count = SuricataLog.objects.count()
new_eve_count = SuricataEveAlert.objects.count()

print(f"   SnortLog: {snort_count} → {new_snort_count} (+{new_snort_count - snort_count})")
print(f"   SuricataLog: {suricata_count} → {new_suricata_count} (+{new_suricata_count - suricata_count})")
print(f"   SuricataEveAlert: {suricata_eve_count} → {new_eve_count} (+{new_eve_count - suricata_eve_count})")
