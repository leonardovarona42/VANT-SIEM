import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from datetime import datetime, timedelta
from random import randint, choice
from django.utils import timezone
from EVENT_M.models import Incidente, Reporte, Servicio, Area, Subcategoria

reportes = list(Reporte.objects.filter(estado_solucion__in=['Atendido', 'Resuelto']))
if not reportes:
    print("No hay reportes disponibles. Crea algunos primero.")
    exit(1)

servicios = list(Servicio.objects.all())
areas = list(Area.objects.all())
subcategorias = list(Subcategoria.objects.all())

estados = Incidente.ESTADO_SOLUCION_CHOICES
now = timezone.now()
count = 0

for i in range(15):
    reporte = choice(reportes)
    if Incidente.objects.filter(reporte=reporte).exists():
        continue

    estado = choice(estados)[0]
    fecha = reporte.fecha_hora

    inc = Incidente.objects.create(
        nombre_incidente=f'Incidente simulado #{count+1}',
        descripcion=f'Incidente de prueba generado automaticamente para validar metricas',
        reporte=reporte,
        estado_solucion=estado,
        notificado_osri=choice(['si', 'no']),
        fecha_hora=fecha,
    )

    if servicios:
        inc.servicios.add(choice(servicios))
    if areas:
        inc.areas.add(choice(areas))
    if subcategorias:
        inc.subcategorias.add(choice(subcategorias))

    if estado != 'nuevo':
        inc.fecha_atencion = fecha + timedelta(hours=randint(1, 12))
        inc.save(update_fields=['fecha_atencion'])

    if estado == 'cerrado':
        inc.fecha_solucion = fecha + timedelta(hours=randint(12, 96))
        inc.save(update_fields=['fecha_solucion'])

    count += 1
    print(f'  Creado #{inc.id}: {estado} | {fecha.strftime("%d/%m/%Y %H:%M")} | Atencion: {inc.fecha_atencion} | Solucion: {inc.fecha_solucion}')

print(f'\nIncidentes creados: {count}')
print(f'Total: {Incidente.objects.count()}')
