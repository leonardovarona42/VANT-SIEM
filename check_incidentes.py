import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from EVENT_M.models import Incidente

for inc in Incidente.objects.all():
    print(f'Incidente #{inc.id}: {inc.nombre_incidente} - reportes: {list(inc.reportes.all())}')

print(f'\nTotal incidentes: {Incidente.objects.count()}')
