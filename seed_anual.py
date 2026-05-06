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
count = 0

for month in range(1, 13):
    for report_num in range(3):
        day = randint(1, 28)
        hour = randint(0, 23)
        minute = randint(0, 59)
        fecha = now.replace(month=month, day=day, hour=hour, minute=minute, second=0, microsecond=0)
        # Para meses futuros ajustar al ultimo dia del mes actual
        if fecha > now:
            continue

        estado = choice(estados)
        idx = randint(33, 99)

        kwargs = {
            'nombre_informante': choice(nombres),
            'email_informante': f'seed_user_{count}@example.com',
            'area': choice(areas),
            'descripcion': f'Reporte anual #{count+1} - Mes {month}',
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
        count += 1
        print(f'  Creado #{r.id}: {estado} | {fecha.strftime("%d/%m/%Y %H:%M")}')

print(f'\nNuevos reportes creados: {count}')
print(f'Total acumulado: {Reporte.objects.count()}')
