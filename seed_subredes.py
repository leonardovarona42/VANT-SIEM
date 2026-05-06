import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from datetime import datetime, timedelta
from django.utils import timezone
from EVENT_M.models import Subred, Servicio, ServicioIP

now = timezone.now()

# Subredes
subredes_data = [
    ('VLAN 100 - Servidores', 'Subred principal para servidores virtuales y fisicos', '10.10.0.0', '/24', '10.10.0.1', 'servidores', 100, '10.10.0.1', True, '10.10.0.50', '10.10.0.200'),
    ('VLAN 10 - Usuarios', 'Subred para estaciones de trabajo de usuarios', '10.10.10.0', '/24', '10.10.10.1', 'usuarios', 10, '10.10.10.1', True, '10.10.10.50', '10.10.10.200'),
    ('VLAN 99 - Gestion', 'Subred de administracion y gestion de red', '10.99.0.0', '/24', '10.99.0.1', 'gestion', 99, None, False, None, None),
    ('Segmento DMZ', 'DMZ para servicios expuestos a internet', '172.16.0.0', '/24', '172.16.0.1', 'dmz', 50, None, False, None, None),
    ('VLAN 20 - Piso 2', 'Subred para usuarios Piso 2', '10.10.20.0', '/24', '10.10.20.1', 'usuarios', 20, '10.10.20.1', True, '10.10.20.50', '10.10.20.200'),
    ('Red IoT', 'Subred para dispositivos IoT y sensores', '10.50.0.0', '/24', '10.50.0.1', 'iot', 150, None, False, None, None),
    ('Red VPN', 'Subred para conexiones VPN remotas', '10.200.0.0', '/24', '10.200.0.1', 'vpn', None, None, False, None, None),
    ('Red Backup', 'Subred para almacenamiento y backup', '10.30.0.0', '/24', '10.30.0.1', 'backup', None, None, False, None, None),
]

for nombre, desc, network, mask, gw, tipo, vlan, dns, dhcp, dhcp_start, dhcp_end in subredes_data:
    servicio = Servicio.objects.filter(vlan_id=vlan).first() if vlan else None
    sr, created = Subred.objects.get_or_create(
        network=network,
        defaults={
            'nombre': nombre,
            'descripcion': desc,
            'subnet_mask': mask,
            'gateway': gw,
            'tipo': tipo,
            'vlan_id': vlan,
            'dns_primario': dns,
            'dhcp_activo': dhcp or False,
            'dhcp_rango_inicio': dhcp_start,
            'dhcp_rango_fin': dhcp_end,
            'servicio': servicio,
        }
    )
    
    # Add IPs to subred
    start_num = int(network.split('.')[-1]) + 1
    if dhcp:
        dhcp_start_num = int(dhcp_start.split('.')[-1])
        dhcp_end_num = int(dhcp_end.split('.')[-1])
        # Add some active devices
        for i in range(dhcp_start_num, dhcp_start_num + 5):
            ip = f"{network.rsplit('.', 1)[0]}.{i}"
            ServicioIP.objects.get_or_create(
                subred=sr,
                ip_address=ip,
                defaults={
                    'hostname': f'device-{i}',
                    'estado': 'activo',
                    'monitorear': False,
                    'ultima_actividad': now - timedelta(minutes=i),
                }
            )
        # Add some reserved
        for i in range(dhcp_end_num - 5, dhcp_end_num):
            ip = f"{network.rsplit('.', 1)[0]}.{i}"
            ServicioIP.objects.get_or_create(
                subred=sr,
                ip_address=ip,
                defaults={
                    'hostname': f'reserved-{i}',
                    'estado': 'reservado',
                    'monitorear': False,
                }
            )
    else:
        # Add gateway and some IPs
        if gw:
            ServicioIP.objects.get_or_create(
                subred=sr,
                ip_address=gw,
                defaults={
                    'hostname': 'gateway',
                    'estado': 'activo',
                    'monitorear': True,
                    'ultima_actividad': now,
                }
            )
        for i in range(1, 4):
            ip = f"{network.rsplit('.', 1)[0]}.{start_num + i}"
            ServicioIP.objects.get_or_create(
                subred=sr,
                ip_address=ip,
                defaults={
                    'hostname': f'srv-{i}',
                    'estado': 'activo',
                    'monitorear': i <= 2,
                    'ultima_actividad': now - timedelta(hours=i),
                }
            )
    
    status = 'Creada' if created else 'Existente'
    print(f'  [{status}] {sr.nombre} ({sr.network}{sr.subnet_mask}) - {sr.total_dispositivos_activos()} activos')

# Update service ultima_actividad
for s in Servicio.objects.filter(monitorear=True):
    s.ultima_actividad = now - timedelta(minutes=s.id * 2)
    s.estado_monitoreo = True
    s.save(update_fields=['ultima_actividad', 'estado_monitoreo'])
    print(f'  [Update] {s.nombre} - Ultima actividad: {s.ultima_actividad.strftime("%H:%M")}')

print(f'\nTotal subredes: {Subred.objects.count()}')
print(f'Total IPs en subredes: {ServicioIP.objects.filter(subred__isnull=False).count()}')
