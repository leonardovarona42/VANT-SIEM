import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from EVENT_M.models import Servicio, ServicioIP
from django.utils import timezone

now = timezone.now()

# Crear servicios de tipo red/subred
redes_data = [
    {
        'nombre': 'VLAN 100 - Servidores',
        'descripcion': 'Subred principal para servidores virtuales y fisicos',
        'tipo': 'subred',
        'network': '10.10.0.0',
        'subnet_mask': '/24',
        'gateway': '10.10.0.1',
        'red_tipo': 'servidores',
        'vlan_id': 100,
        'dns_primario': '10.10.0.1',
        'dhcp_activo': True,
        'dhcp_rango_inicio': '10.10.0.50',
        'dhcp_rango_fin': '10.10.0.200',
        'nivel_red': 0,
    },
    {
        'nombre': 'VLAN 10 - Usuarios',
        'descripcion': 'Subred para estaciones de trabajo de usuarios',
        'tipo': 'subred',
        'network': '10.10.10.0',
        'subnet_mask': '/24',
        'gateway': '10.10.10.1',
        'red_tipo': 'usuarios',
        'vlan_id': 10,
        'dns_primario': '10.10.10.1',
        'dhcp_activo': True,
        'dhcp_rango_inicio': '10.10.10.50',
        'dhcp_rango_fin': '10.10.10.200',
        'nivel_red': 2,
    },
    {
        'nombre': 'VLAN 99 - Gestion',
        'descripcion': 'Subred de administracion y gestion de red',
        'tipo': 'subred',
        'network': '10.99.0.0',
        'subnet_mask': '/24',
        'gateway': '10.99.0.1',
        'red_tipo': 'gestion',
        'vlan_id': 99,
        'nivel_red': 1,
    },
    {
        'nombre': 'Segmento DMZ',
        'descripcion': 'DMZ para servicios expuestos a internet',
        'tipo': 'segmento',
        'network': '172.16.0.0',
        'subnet_mask': '/24',
        'gateway': '172.16.0.1',
        'red_tipo': 'dmz',
        'nivel_red': 1,
    },
    {
        'nombre': 'VLAN 20 - Piso 2',
        'descripcion': 'Subred para usuarios Piso 2',
        'tipo': 'subred',
        'network': '10.10.20.0',
        'subnet_mask': '/24',
        'gateway': '10.10.20.1',
        'red_tipo': 'usuarios',
        'vlan_id': 20,
        'dns_primario': '10.10.20.1',
        'dhcp_activo': True,
        'dhcp_rango_inicio': '10.10.20.50',
        'dhcp_rango_fin': '10.10.20.200',
        'nivel_red': 2,
    },
    {
        'nombre': 'Red IoT',
        'descripcion': 'Subred para dispositivos IoT y sensores',
        'tipo': 'subred',
        'network': '10.50.0.0',
        'subnet_mask': '/24',
        'gateway': '10.50.0.1',
        'red_tipo': 'iot',
        'vlan_id': 150,
        'nivel_red': 2,
    },
    {
        'nombre': 'Red VPN',
        'descripcion': 'Subred para conexiones VPN remotas',
        'tipo': 'subred',
        'network': '10.200.0.0',
        'subnet_mask': '/24',
        'gateway': '10.200.0.1',
        'red_tipo': 'vpn',
        'nivel_red': 1,
    },
    {
        'nombre': 'Red Backup',
        'descripcion': 'Subred para almacenamiento y backup',
        'tipo': 'subred',
        'network': '10.30.0.0',
        'subnet_mask': '/24',
        'gateway': '10.30.0.1',
        'red_tipo': 'backup',
        'nivel_red': 1,
    },
]

for r in redes_data:
    r.setdefault('dhcp_activo', False)
    defaults = dict(r)
    nombre = defaults.pop('nombre')
    s, created = Servicio.objects.get_or_create(
        nombre=nombre,
        defaults=defaults
    )
    
    # Update network if not set
    if not s.network:
        s.network = r['network']
        s.save(update_fields=['network'])
    
    # Agregar IPs a la red
    if r['dhcp_activo']:
        start = int(r['dhcp_rango_inicio'].split('.')[-1])
        end = int(r['dhcp_rango_fin'].split('.')[-1])
        for i in range(start, start + 5):
            ip = f"{r['network'].rsplit('.', 1)[0]}.{i}"
            ServicioIP.objects.get_or_create(
                servicio=s,
                ip_address=ip,
                defaults={
                    'hostname': f'device-{i}',
                    'estado': 'activo',
                    'monitorear': False,
                    'ultima_actividad': now,
                }
            )
        for i in range(end - 5, end):
            ip = f"{r['network'].rsplit('.', 1)[0]}.{i}"
            ServicioIP.objects.get_or_create(
                servicio=s,
                ip_address=ip,
                defaults={
                    'hostname': f'reserved-{i}',
                    'estado': 'reservado',
                    'monitorear': False,
                }
            )
    else:
        if r.get('gateway'):
            ServicioIP.objects.get_or_create(
                servicio=s,
                ip_address=r['gateway'],
                defaults={
                    'hostname': 'gateway',
                    'estado': 'activo',
                    'monitorear': True,
                    'ultima_actividad': now,
                }
            )
        for i in range(1, 4):
            ip = f"{r['network'].rsplit('.', 1)[0]}.{int(r['network'].split('.')[-1]) + i}"
            ServicioIP.objects.get_or_create(
                servicio=s,
                ip_address=ip,
                defaults={
                    'hostname': f'srv-{i}',
                    'estado': 'activo',
                    'monitorear': i <= 2,
                    'ultima_actividad': now,
                }
            )
    
    status = 'Creada' if created else 'Existente'
    print(f'  [{status}] {s.nombre} ({s.network}{s.subnet_mask}) - {s.total_dispositivos_activos()} activos')

# Actualizar algunos servicios existentes para que tengan mejor estructura
for s in Servicio.objects.filter(tipo='host', monitorear=True):
    s.ultima_actividad = now
    s.estado_monitoreo = True
    s.save(update_fields=['ultima_actividad', 'estado_monitoreo'])

print(f'\nTotal servicios: {Servicio.objects.count()}')
print(f'Total IPs: {ServicioIP.objects.filter(servicio__isnull=False).count()}')
print(f'Total redes: {Servicio.objects.filter(tipo__in=["subred", "red", "segmento", "vlan"]).count()}')
