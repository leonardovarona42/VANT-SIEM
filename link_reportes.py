import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from EVENT_M.models import Incidente, Reporte

reportes_atendidos = list(Reporte.objects.filter(estado_solucion__in=['Atendido', 'Resuelto']))

for inc in Incidente.objects.all():
    if inc.reportes.exists():
        continue
    
    if reportes_atendidos:
        import random
        num_reportes = random.randint(1, min(3, len(reportes_atendidos)))
        selected = random.sample(reportes_atendidos, num_reportes)
        inc.reportes.set(selected)
        print(f'  Incidente #{inc.id}: vinculados {[r.nombre_informante for r in selected]}')

print(f'\nTotal incidentes con reportes: {Incidente.objects.filter(reportes__isnull=False).distinct().count()}')
