import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from datetime import datetime, timedelta
from random import randint, choice
from django.utils import timezone
from EVENT_M.models import Reporte, Area

areas = list(Area.objects.all())
if not areas:
    print("No hay areas. Creando algunas de prueba...")
    areas = [
        Area.objects.create(nombre="TI"),
        Area.objects.create(nombre="RH"),
        Area.objects.create(nombre="Finanzas"),
        Area.objects.create(nombre="Operaciones"),
        Area.objects.create(nombre="Legal"),
    ]

estados = ['Abierto', 'En Proceso', 'Atendido', 'Resuelto', 'Rechazado']
nombres = ['Ana Lopez', 'Carlos Ruiz', 'Maria Garcia', 'Jorge Perez', 'Laura Diaz', 'Pedro Martinez', 'Sofia Torres', 'Diego Flores']

now = timezone.now()

for i in range(1, 26):
    fecha = now - timedelta(days=randint(0, 90), hours=randint(0, 23), minutes=randint(0, 59))
    estado = choice(estados)

    kwargs = {
        'nombre_informante': choice(nombres),
        'email_informante': f'user{i}@example.com',
        'area': choice(areas),
        'descripcion': f'Reporte de prueba #{i} - Incidente simulado para validacion de widgets',
        'estado_solucion': estado,
        'fecha_hora': fecha,
    }

    if estado in ['Atendido', 'Resuelto']:
        kwargs['fecha_atencion'] = fecha + timedelta(hours=randint(1, 24))

    if estado == 'Resuelto':
        if 'fecha_atencion' not in kwargs:
            kwargs['fecha_atencion'] = fecha + timedelta(hours=randint(1, 12))
        kwargs['fecha_solucion'] = kwargs['fecha_atencion'] + timedelta(hours=randint(4, 72))

    r = Reporte.objects.create(**kwargs)
    print(f'  Creado reporte #{r.id}: {estado} | Fecha: {fecha.strftime("%d/%m/%Y %H:%M")} | Atencion: {r.fecha_atencion} | Solucion: {r.fecha_solucion}')

print(f'\nTotal reportes: {Reporte.objects.count()}')
print('  Abiertos:', Reporte.objects.filter(estado_solucion='Abierto').count())
print('  En Proceso:', Reporte.objects.filter(estado_solucion='En Proceso').count())
print('  Atendidos:', Reporte.objects.filter(estado_solucion='Atendido').count())
print('  Resueltos:', Reporte.objects.filter(estado_solucion='Resuelto').count())
print('  Rechazados:', Reporte.objects.filter(estado_solucion='Rechazado').count())
