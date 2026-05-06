import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from EVENT_M.models import Servicio, ServicioIP, PuertoDispositivo, ConexionTopologica

print("=== Seed: Topologia de Red ===\n")

# 1. Core Router
core_router = Servicio.objects.create(
    nombre='Core Router - Cisco ISR 4451',
    descripcion='Router principal de la red corporativa, gateway hacia internet',
    tipo='dispositivo_red',
    host='10.0.0.1',
    dispositivo_tipo='router',
    num_puertos=8,
    modelo='ISR 4451',
    fabricante='Cisco',
    numero_serie='FDO2543A123',
    firmware='IOS-XE 17.09',
    monitorear=True,
    protocolo_monitoreo='icmp',
    ubicacion_fisica='Rack Principal, U1',
    rack='RACK-01',
    posicion_rack=1,
    edificio='Edificio Central',
    piso='PB',
    coordenadas_x=400,
    coordenadas_y=50,
    coordenadas_logicas_x=500,
    coordenadas_logicas_y=50,
    nivel_red=0,
)
print(f'[Nivel 0] Core Router: {core_router.nombre} ({core_router.host})')

# 2. Firewall Principal
firewall = Servicio.objects.create(
    nombre='Firewall Fortinet FG-200E',
    descripcion='Firewall perimetral con IPS/IDS integrado',
    tipo='dispositivo_red',
    host='10.0.0.2',
    dispositivo_tipo='firewall',
    num_puertos=16,
    modelo='FortiGate 200E',
    fabricante='Fortinet',
    numero_serie='FG200ETK23000456',
    firmware='FortiOS 7.4.2',
    monitorear=True,
    protocolo_monitoreo='icmp',
    ubicacion_fisica='Rack Principal, U2',
    rack='RACK-01',
    posicion_rack=2,
    edificio='Edificio Central',
    piso='PB',
    coordenadas_x=400,
    coordenadas_y=150,
    coordenadas_logicas_x=500,
    coordenadas_logicas_y=150,
    nivel_red=0,
)
print(f'[Nivel 0] Firewall: {firewall.nombre} ({firewall.host})')

# 3. Proxmox Cluster
proxmox_cluster = Servicio.objects.create(
    nombre='Cluster Proxmox VE',
    descripcion='Cluster de virtualizacion con 3 nodos para servidores internos',
    tipo='cluster',
    host='10.10.0.1',
    plataforma='proxmox',
    vlan_id=100,
    subnet_mask='/24',
    monitorear=True,
    protocolo_monitoreo='http',
    puerto_monitoreo=8006,
    ubicacion_fisica='Rack Servidores, U10-U12',
    rack='RACK-02',
    posicion_rack=10,
    edificio='Edificio Central',
    piso='PB',
    coordenadas_x=200,
    coordenadas_y=300,
    coordenadas_logicas_x=200,
    coordenadas_logicas_y=300,
    nivel_red=1,
)
print(f'[Nivel 1] Cluster Proxmox: {proxmox_cluster.nombre} ({proxmox_cluster.host})')

# 4. Core Switch 48 puertos
core_switch = Servicio.objects.create(
    nombre='Core Switch - Cisco Catalyst 9300',
    descripcion='Switch de distribucion principal 48 puertos 10G',
    tipo='dispositivo_red',
    host='10.0.0.10',
    dispositivo_tipo='switch',
    num_puertos=48,
    modelo='Catalyst 9300-48T',
    fabricante='Cisco',
    numero_serie='FCW2543L001',
    firmware='IOS-XE 17.06',
    vlan_id=1,
    monitorear=True,
    protocolo_monitoreo='snmp',
    ubicacion_fisica='Rack Principal, U5',
    rack='RACK-01',
    posicion_rack=5,
    edificio='Edificio Central',
    piso='PB',
    coordenadas_x=400,
    coordenadas_y=250,
    coordenadas_logicas_x=500,
    coordenadas_logicas_y=250,
    nivel_red=1,
)
print(f'[Nivel 1] Core Switch: {core_switch.nombre} ({core_switch.host})')

# 5. Access Switch Piso 1
access_sw_p1 = Servicio.objects.create(
    nombre='Access Switch - Piso 1',
    descripcion='Switch de acceso para Piso 1 - 24 puertos',
    tipo='dispositivo_red',
    host='10.0.0.21',
    dispositivo_tipo='switch',
    num_puertos=24,
    modelo='Catalyst 9200-24T',
    fabricante='Cisco',
    numero_serie='FCW2543L021',
    vlan_id=10,
    monitorear=True,
    protocolo_monitoreo='snmp',
    ubicacion_fisica='Rack Piso 1, U3',
    rack='RACK-P1',
    posicion_rack=3,
    edificio='Edificio Central',
    piso='Piso 1',
    coordenadas_x=200,
    coordenadas_y=400,
    coordenadas_logicas_x=200,
    coordenadas_logicas_y=400,
    nivel_red=2,
)
print(f'[Nivel 2] Access Switch P1: {access_sw_p1.nombre} ({access_sw_p1.host})')

# 6. Access Switch Piso 2
access_sw_p2 = Servicio.objects.create(
    nombre='Access Switch - Piso 2',
    descripcion='Switch de acceso para Piso 2 - 24 puertos',
    tipo='dispositivo_red',
    host='10.0.0.22',
    dispositivo_tipo='switch',
    num_puertos=24,
    modelo='Catalyst 9200-24T',
    fabricante='Cisco',
    numero_serie='FCW2543L022',
    vlan_id=20,
    monitorear=True,
    protocolo_monitoreo='snmp',
    ubicacion_fisica='Rack Piso 2, U3',
    rack='RACK-P2',
    posicion_rack=3,
    edificio='Edificio Central',
    piso='Piso 2',
    coordenadas_x=600,
    coordenadas_y=400,
    coordenadas_logicas_x=600,
    coordenadas_logicas_y=400,
    nivel_red=2,
)
print(f'[Nivel 2] Access Switch P2: {access_sw_p2.nombre} ({access_sw_p2.host})')

# 7. VLAN Servidores
vlan_servers = Servicio.objects.create(
    nombre='VLAN 100 - Servidores',
    descripcion='VLAN dedicada para servidores virtuales y fisicos',
    tipo='vlan',
    host='10.10.0.1',
    vlan_id=100,
    subnet_mask='/24',
    ip_range_start='10.10.0.1',
    ip_range_end='10.10.0.254',
    monitorear=True,
    protocolo_monitoreo='icmp',
    coordenadas_x=100,
    coordenadas_y=300,
    coordenadas_logicas_x=100,
    coordenadas_logicas_y=300,
    nivel_red=1,
)
print(f'[VLAN] VLAN Servidores: {vlan_servers.nombre}')

# 8. VLAN Usuarios
vlan_users = Servicio.objects.create(
    nombre='VLAN 10 - Usuarios',
    descripcion='VLAN para estaciones de trabajo de usuarios',
    tipo='vlan',
    host='10.10.10.1',
    vlan_id=10,
    subnet_mask='/24',
    ip_range_start='10.10.10.1',
    ip_range_end='10.10.10.254',
    monitorear=True,
    protocolo_monitoreo='icmp',
    coordenadas_x=200,
    coordenadas_y=500,
    coordenadas_logicas_x=200,
    coordenadas_logicas_y=500,
    nivel_red=2,
)
print(f'[VLAN] VLAN Usuarios: {vlan_users.nombre}')

# 9. VLAN Administracion
vlan_admin = Servicio.objects.create(
    nombre='VLAN 99 - Administracion',
    descripcion='VLAN de gestion y administracion de red',
    tipo='vlan',
    host='10.99.0.1',
    vlan_id=99,
    subnet_mask='/24',
    ip_range_start='10.99.0.1',
    ip_range_end='10.99.0.254',
    monitorear=True,
    protocolo_monitoreo='icmp',
    coordenadas_x=400,
    coordenadas_y=350,
    coordenadas_logicas_x=400,
    coordenadas_logicas_y=350,
    nivel_red=1,
)
print(f'[VLAN] VLAN Admin: {vlan_admin.nombre}')

# 10. Segmento DMZ
dmz_segment = Servicio.objects.create(
    nombre='Segmento DMZ',
    descripcion='Segmento de red para servicios expuestos a internet',
    tipo='segmento',
    host='172.16.0.1',
    vlan_id=50,
    subnet_mask='/24',
    ip_range_start='172.16.0.1',
    ip_range_end='172.16.0.254',
    monitorear=True,
    protocolo_monitoreo='icmp',
    coordenadas_x=600,
    coordenadas_y=150,
    coordenadas_logicas_x=700,
    coordenadas_logicas_y=150,
    nivel_red=0,
)
print(f'[Segmento] DMZ: {dmz_segment.nombre}')

# 11. Servidor Web (VM en Proxmox)
web_server = Servicio.objects.create(
    nombre='Web Server - Apache',
    descripcion='Servidor web principal con Apache y aplicacion VANT-SIEM',
    tipo='host',
    host='10.10.0.10',
    vlan_id=100,
    subnet_mask='/24',
    servicio_padre=proxmox_cluster,
    monitorear=True,
    protocolo_monitoreo='http',
    puerto_monitoreo=443,
    ubicacion_fisica='Proxmox Node 1 - VM 100',
    rack='RACK-02',
    edificio='Edificio Central',
    piso='PB',
    coordenadas_x=100,
    coordenadas_y=300,
    coordenadas_logicas_x=100,
    coordenadas_logicas_y=300,
    nivel_red=1,
)
print(f'[Host] Web Server: {web_server.nombre} ({web_server.host})')

# 12. Servidor Base de Datos
db_server = Servicio.objects.create(
    nombre='DB Server - PostgreSQL',
    descripcion='Servidor de base de datos PostgreSQL para VANT-SIEM',
    tipo='host',
    host='10.10.0.11',
    vlan_id=100,
    subnet_mask='/24',
    servicio_padre=proxmox_cluster,
    monitorear=True,
    protocolo_monitoreo='tcp',
    puerto_monitoreo=5432,
    ubicacion_fisica='Proxmox Node 1 - VM 101',
    rack='RACK-02',
    edificio='Edificio Central',
    piso='PB',
    coordenadas_x=100,
    coordenadas_y=350,
    coordenadas_logicas_x=100,
    coordenadas_logicas_y=350,
    nivel_red=1,
)
print(f'[Host] DB Server: {db_server.nombre} ({db_server.host})')

# 13. Servidor Monitoreo
monitor_server = Servicio.objects.create(
    nombre='Monitor Server - Zabbix',
    descripcion='Servidor de monitoreo con Zabbix y Grafana',
    tipo='host',
    host='10.10.0.12',
    vlan_id=100,
    subnet_mask='/24',
    servicio_padre=proxmox_cluster,
    monitorear=True,
    protocolo_monitoreo='http',
    puerto_monitoreo=80,
    ubicacion_fisica='Proxmox Node 2 - VM 102',
    rack='RACK-02',
    edificio='Edificio Central',
    piso='PB',
    coordenadas_x=100,
    coordenadas_y=400,
    coordenadas_logicas_x=100,
    coordenadas_logicas_y=400,
    nivel_red=1,
)
print(f'[Host] Monitor Server: {monitor_server.nombre} ({monitor_server.host})')

# 14. Servicio Externo - DNS
dns_ext = Servicio.objects.create(
    nombre='DNS Externo - Cloudflare',
    descripcion='Servicio DNS externo de Cloudflare',
    tipo='servicio_externo',
    url_servicio='https://1.1.1.1',
    puerto_servicio=53,
    monitorear=True,
    protocolo_monitoreo='tcp',
    puerto_monitoreo=53,
    coordenadas_x=700,
    coordenadas_y=50,
    coordenadas_logicas_x=800,
    coordenadas_logicas_y=50,
    nivel_red=0,
)
print(f'[Externo] DNS: {dns_ext.nombre}')

# 15. Servicio Externo - SIEM Cloud
siem_cloud = Servicio.objects.create(
    nombre='SIEM Cloud - Sentinel',
    descripcion='Microsoft Sentinel para analisis de amenazas en la nube',
    tipo='servicio_externo',
    url_servicio='https://portal.azure.com',
    puerto_servicio=443,
    monitorear=True,
    protocolo_monitoreo='http',
    puerto_monitoreo=443,
    coordenadas_x=700,
    coordenadas_y=100,
    coordenadas_logicas_x=800,
    coordenadas_logicas_y=100,
    nivel_red=0,
)
print(f'[Externo] SIEM Cloud: {siem_cloud.nombre}')

# 16. AP Piso 1
ap_p1 = Servicio.objects.create(
    nombre='AP - Piso 1',
    descripcion='Access Point WiFi para Piso 1',
    tipo='dispositivo_red',
    host='10.0.0.51',
    dispositivo_tipo='access_point',
    modelo='Cisco Aironet 9120',
    fabricante='Cisco',
    vlan_id=10,
    monitorear=True,
    protocolo_monitoreo='icmp',
    ubicacion_fisica='Techo Piso 1 - Zona Norte',
    edificio='Edificio Central',
    piso='Piso 1',
    coordenadas_x=100,
    coordenadas_y=500,
    coordenadas_logicas_x=100,
    coordenadas_logicas_y=500,
    nivel_red=2,
)
print(f'[AP] AP P1: {ap_p1.nombre} ({ap_p1.host})')

# IPs para VLAN Servidores
for ip_num in range(10, 20):
    ServicioIP.objects.get_or_create(
        servicio=vlan_servers,
        ip_address=f'10.10.0.{ip_num}',
        defaults={
            'hostname': f'srv-{ip_num-10}',
            'estado': 'activo' if ip_num < 15 else 'reservado',
            'monitorear': ip_num < 13,
        }
    )
print(f'\n[IPs] {vlan_servers.ips.count()} IPs en VLAN Servidores')

# IPs para VLAN Usuarios
for ip_num in range(1, 21):
    ServicioIP.objects.get_or_create(
        servicio=vlan_users,
        ip_address=f'10.10.10.{ip_num}',
        defaults={
            'hostname': f'ws-{ip_num}',
            'estado': 'activo' if ip_num <= 15 else 'reservado',
        }
    )
print(f'[IPs] {vlan_users.ips.count()} IPs en VLAN Usuarios')

# Puertos para Core Switch
for port in range(1, 9):
    PuertoDispositivo.objects.get_or_create(
        dispositivo=core_switch,
        numero_puerto=port,
        defaults={
            'etiqueta': f'Gi1/0/{port}',
            'vlan_asignada': 1 if port <= 4 else 100,
            'velocidad': '10g',
            'estado': 'activo' if port <= 6 else 'reservado',
        }
    )
print(f'[Puertos] {core_switch.puertos.count()} puertos en Core Switch')

# Puertos para Access Switch P1
for port in range(1, 13):
    PuertoDispositivo.objects.get_or_create(
        dispositivo=access_sw_p1,
        numero_puerto=port,
        defaults={
            'etiqueta': f'Gi0/{port}',
            'vlan_asignada': 10 if port <= 10 else 99,
            'velocidad': '1g',
            'estado': 'activo' if port <= 10 else 'reservado',
        }
    )
print(f'[Puertos] {access_sw_p1.puertos.count()} puertos en Access Switch P1')

# Puertos para Access Switch P2
for port in range(1, 13):
    PuertoDispositivo.objects.get_or_create(
        dispositivo=access_sw_p2,
        numero_puerto=port,
        defaults={
            'etiqueta': f'Gi0/{port}',
            'vlan_asignada': 20 if port <= 8 else 99,
            'velocidad': '1g',
            'estado': 'activo' if port <= 8 else 'reservado',
        }
    )
print(f'[Puertos] {access_sw_p2.puertos.count()} puertos en Access Switch P2')

# Conexiones Fisicas
connections = [
    (core_router, firewall, 'fisica', 'fibra', '10Gbps'),
    (firewall, core_switch, 'fisica', 'fibra', '10Gbps'),
    (core_switch, access_sw_p1, 'fisica', 'fibra', '1Gbps'),
    (core_switch, access_sw_p2, 'fisica', 'fibra', '1Gbps'),
    (access_sw_p1, ap_p1, 'fisica', 'cobre', '1Gbps'),
    (core_switch, proxmox_cluster, 'fisica', 'fibra', '10Gbps'),
    (firewall, dmz_segment, 'fisica', 'fibra', '1Gbps'),
    (core_router, dns_ext, 'logica', 'wireless', 'N/A'),
    (core_router, siem_cloud, 'logica', 'wireless', 'N/A'),
    (vlan_servers, proxmox_cluster, 'virtual', 'virtual', 'N/A'),
    (vlan_servers, web_server, 'virtual', 'virtual', 'N/A'),
    (vlan_servers, db_server, 'virtual', 'virtual', 'N/A'),
    (vlan_servers, monitor_server, 'virtual', 'virtual', 'N/A'),
    (vlan_users, access_sw_p1, 'virtual', 'virtual', 'N/A'),
    (vlan_users, access_sw_p2, 'virtual', 'virtual', 'N/A'),
    (vlan_admin, core_switch, 'virtual', 'virtual', 'N/A'),
]

for origen, destino, tipo, medio, ancho in connections:
    ConexionTopologica.objects.get_or_create(
        origen=origen,
        destino=destino,
        tipo=tipo,
        defaults={
            'medio': medio,
            'ancho_banda': ancho,
            'descripcion': f'Conexion {tipo} entre {origen.nombre} y {destino.nombre}',
            'activa': True,
        }
    )
print(f'\n[Conexiones] {ConexionTopologica.objects.count()} conexiones topologicas')

print(f'\n=== Total: {Servicio.objects.count()} servicios ===')
print('=== Seed completado ===')
