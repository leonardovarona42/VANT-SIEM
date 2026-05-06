import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from django.utils import timezone
from EVENT_M.models import Reporte

now = timezone.now()
fixed = 0

for r in Reporte.objects.all():
    needs_save = False

    if r.fecha_atencion and r.fecha_atencion < r.fecha_hora:
        r.fecha_atencion = r.fecha_hora + timezone.timedelta(hours=2)
        needs_save = True

    if r.fecha_solucion and r.fecha_solucion < r.fecha_hora:
        r.fecha_solucion = r.fecha_hora + timezone.timedelta(hours=24)
        needs_save = True

    if r.fecha_solucion and r.fecha_atencion and r.fecha_solucion < r.fecha_atencion:
        r.fecha_solucion = r.fecha_atencion + timezone.timedelta(hours=12)
        needs_save = True

    if needs_save:
        r.save()
        fixed += 1
        print(f'  Corregido #{r.id}: atencion={r.fecha_atencion}, solucion={r.fecha_solucion}')

print(f'\nRegistros corregidos: {fixed}')
