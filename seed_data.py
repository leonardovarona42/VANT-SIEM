#!/usr/bin/env python
"""Seed script to populate VANT-SIEM database with sample data."""

import os, sys, django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')
django.setup()

from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta, date
from EVENT_M.models import Categoria, Subcategoria, Servicio, Responsable, Area, Medida, Reporte, Incidente, Involucrado, InvolucradoIncidente, MedidaIncidente

admin_user, _ = User.objects.get_or_create(
    username='admin',
    defaults={'email': 'admin@vant.local', 'first_name': 'Admin', 'last_name': 'General', 'is_staff': True, 'is_superuser': True}
)
if admin_user:
    admin_user.set_password('admin123')
    admin_user.save()
print('User: admin')

# Create responsables first (needed by Area)
resp_data = [
    {'nombres': 'Carlos', 'apellidos': 'Rodriguez', 'email': 'carlos@vant.local', 'telefono_particular': '555-0001', 'telefono_corp': '555-1001', 'tipo': 'Cuadro Centro', 'descripcion': 'Responsable principal del centro de operaciones'},
    {'nombres': 'Maria', 'apellidos': 'Garcia', 'email': 'maria@vant.local', 'telefono_particular': '555-0002', 'telefono_corp': '555-1002', 'tipo': 'RSI', 'descripcion': 'Responsable de Seguridad de la Informacion'},
    {'nombres': 'Juan', 'apellidos': 'Perez', 'email': 'juan@vant.local', 'telefono_particular': '555-0003', 'telefono_corp': '555-1003', 'tipo': 'Admin', 'descripcion': 'Administrador de sistemas'},
]
responsables = []
for rd in resp_data:
    r, c = Responsable.objects.get_or_create(nombres=rd['nombres'], apellidos=rd['apellidos'], defaults=rd)
    if c: print(f'Responsable created: {r}')
    responsables.append(r)

# Create categorias
cat_data = [
    {'nombre': 'Intrusion', 'descripcion': 'Acceso no autorizado a sistemas o redes'},
    {'nombre': 'Malware', 'descripcion': 'Software malicioso detectado en la red'},
    {'nombre': 'Phishing', 'descripcion': 'Intento de suplantacion de identidad'},
    {'nombre': 'DDoS', 'descripcion': 'Ataque de denegacion de servicio distribuido'},
    {'nombre': 'Fuga de Datos', 'descripcion': 'Exfiltracion de informacion sensible'},
    {'nombre': 'Politica Violada', 'descripcion': 'Incumplimiento de politicas de seguridad'},
]
categorias = []
for cd in cat_data:
    c, created = Categoria.objects.get_or_create(nombre=cd['nombre'], defaults=cd)
    if created: print(f'Categoria created: {c.nombre}')
    categorias.append(c)

# Create subcategorias
sub_data = [
    ('Escaneo de puertos', 'Escaneo no autorizado de puertos de red', 4, categorias[0]),
    ('Fuerza bruta', 'Intento de acceso por fuerza bruta', 6, categorias[0]),
    ('Acceso no autorizado', 'Acceso a recursos sin autorizacion', 8, categorias[0]),
    ('Ransomware', 'Cifrado de archivos con demanda de rescate', 10, categorias[1]),
    ('Troyano', 'Software espia oculto en aplicaciones', 7, categorias[1]),
    ('Gusano', 'Malware autoreplicante en la red', 6, categorias[1]),
    ('Email phishing', 'Correos fraudulentos con enlaces maliciosos', 5, categorias[2]),
    ('Spear phishing', 'Ataque dirigido a usuario especifico', 7, categorias[2]),
    ('SYN Flood', 'Ataque de inundacion SYN', 8, categorias[3]),
    ('HTTP Flood', 'Ataque de inundacion HTTP', 7, categorias[3]),
]
for sn, sd, nivel, cat in sub_data:
    s, c = Subcategoria.objects.get_or_create(nombre=sn, defaults={'descripcion': sd, 'nivel_peligrosidad': nivel, 'categoria': cat})
    if c: print(f'Subcategoria created: {s.nombre}')

# Create servicios
serv_data = [
    {'nombre': 'Servidor Principal', 'descripcion': 'Servidor central de aplicaciones', 'host': '192.168.1.10', 'monitorear': True},
    {'nombre': 'Firewall Perimetral', 'descripcion': 'Firewall de borde de la red', 'host': '192.168.1.1', 'monitorear': True},
    {'nombre': 'IDS/IPS', 'descripcion': 'Sistema de deteccion y prevencion de intrusiones', 'host': '192.168.1.2', 'monitorear': True},
    {'nombre': 'Proxy Web', 'descripcion': 'Proxy de filtrado web', 'host': '192.168.1.5', 'monitorear': True},
    {'nombre': 'DNS Interno', 'descripcion': 'Servidor DNS de la red interna', 'host': '192.168.1.3', 'monitorear': True},
    {'nombre': 'Correo Electronico', 'descripcion': 'Servidor de correo corporativo', 'host': '192.168.1.8', 'monitorear': True},
    {'nombre': 'Base de Datos', 'descripcion': 'Servidor de base de datos principal', 'host': '192.168.1.15', 'monitorear': True},
]
servicios = []
for sd in serv_data:
    s, c = Servicio.objects.get_or_create(nombre=sd['nombre'], defaults=sd)
    if c: print(f'Servicio created: {s.nombre}')
    servicios.append(s)

# Create areas
area_data = [
    {'nombre': 'Tecnologia de la Informacion', 'acronimo': 'TI', 'cuadro_centro': responsables[0], 'rsi': responsables[1], 'admin': responsables[2]},
    {'nombre': 'Ciberseguridad', 'acronimo': 'CS', 'cuadro_centro': responsables[1], 'rsi': responsables[2], 'admin': responsables[0]},
    {'nombre': 'Infraestructura de Red', 'acronimo': 'IR', 'cuadro_centro': responsables[2], 'rsi': responsables[0], 'admin': responsables[1]},
]
areas = []
for ad in area_data:
    a, c = Area.objects.get_or_create(nombre=ad['nombre'], defaults=ad)
    if c: print(f'Area created: {a.nombre}')
    areas.append(a)

# Create medidas
med_data = [
    {'nombre': 'Bloquear IP en Firewall', 'descripcion': 'Agregar regla de bloqueo en el firewall perimetral'},
    {'nombre': 'Aislar endpoint', 'descripcion': 'Desconectar el equipo afectado de la red'},
    {'nombre': 'Resetear credenciales', 'descripcion': 'Cambiar las credenciales del usuario comprometido'},
    {'nombre': 'Escanear sistema', 'descripcion': 'Ejecutar escaneo completo con antivirus'},
    {'nombre': 'Aplicar parche', 'descripcion': 'Instalar actualizaciones de seguridad pendientes'},
    {'nombre': 'Notificar autoridades', 'descripcion': 'Enviar reporte a las autoridades competentes'},
    {'nombre': 'Cambiar reglas firewall', 'descripcion': 'Modificar reglas de acceso del firewall'},
]
medidas = []
for md in med_data:
    m, c = Medida.objects.get_or_create(nombre=md['nombre'], defaults=md)
    if c: print(f'Medida created: {m.nombre}')
    medidas.append(m)

# Create reportes
rep_data = [
    {'nombre_informante': 'Ana Martinez', 'email_informante': 'ana@vant.local', 'area': areas[0], 'descripcion': 'Detecte actividad inusual en el servidor de base de datos. Múltiples intentos de acceso desde una IP externa no reconocida.', 'estado_solucion': 'Nuevo'},
    {'nombre_informante': 'Luis Hernandez', 'email_informante': 'luis@vant.local', 'area': areas[1], 'descripcion': 'El sistema IDS ha detectado patrones de escaneo de puertos provenientes de la red 10.0.0.0/24.', 'estado_solucion': 'Atendido'},
    {'nombre_informante': 'Carmen Diaz', 'email_informante': 'carmen@vant.local', 'area': areas[2], 'descripcion': 'Varios empleados reportaron correos sospechosos solicitando credenciales de acceso.', 'estado_solucion': 'Nuevo'},
    {'nombre_informante': 'Pedro Gomez', 'email_informante': 'pedro@vant.local', 'area': areas[0], 'descripcion': 'Se identifico un archivo ejecutable desconocido en la carpeta compartida del departamento de finanzas.', 'estado_solucion': 'Rechazado'},
    {'nombre_informante': 'Rosa Silva', 'email_informante': 'rosa@vant.local', 'area': areas[1], 'descripcion': 'El firewall bloqueo multiples intentos de conexion desde paises no autorizados en las ultimas 48 horas.', 'estado_solucion': 'Atendido'},
    {'nombre_informante': 'Miguel Torres', 'email_informante': 'miguel@vant.local', 'area': areas[2], 'descripcion': 'Latencia inusual detectada en los servicios de red, posible indicio de ataque DDoS.', 'estado_solucion': 'Nuevo'},
    {'nombre_informante': 'Laura Vega', 'email_informante': 'laura@vant.local', 'area': areas[0], 'descripcion': 'Un usuario reporto que su equipo fue cifrado y aparece un mensaje exigiendo pago en criptomonedas.', 'estado_solucion': 'Atendido'},
]
reportes = []
for i, rd in enumerate(rep_data):
    r = Reporte(**rd)
    r.fecha_hora = timezone.now() - timedelta(days=i, hours=i*3)
    r.save()
    print(f'Reporte created: {r.nombre_informante} - {r.estado_solucion}')
    reportes.append(r)

# Create incidentes (each linked to a reporte)
inc_data = [
    {'nombre_incidente': 'Ataque de fuerza bruta al servidor principal', 'descripcion': 'Se detectaron más de 1000 intentos de login fallidos en el servidor principal desde la IP 203.0.113.50.', 'estado_solucion': 'nuevo', 'notificado_osri': 'si'},
    {'nombre_incidente': 'Escaneo de puertos desde red externa', 'descripcion': 'El IDS detecto un escaneo completo de puertos desde la red externa hacia nuestros servidores.', 'estado_solucion': 'abierto', 'notificado_osri': 'si'},
    {'nombre_incidente': 'Campaña de phishing corporativo', 'descripcion': 'Mas de 20 empleados recibieron correos phishing con links maliciosos aparentemente internos.', 'estado_solucion': 'investigacion', 'notificado_osri': 'si'},
    {'nombre_incidente': 'Troyano detectado en endpoint', 'descripcion': 'Se encontro un troyano de tipo RAT en el equipo del departamento de finanzas.', 'estado_solucion': 'mitigacion', 'notificado_osri': 'no'},
    {'nombre_incidente': 'Ataque DDoS a servicios web', 'descripcion': 'Los servicios web experimentaron una degradacion significativa debido a un ataque DDoS volumetrico.', 'estado_solucion': 'cerrado', 'notificado_osri': 'si'},
    {'nombre_incidente': 'Ransomware en red interna', 'descripcion': 'Un ransomware se propago por la red interna afectando 5 estaciones de trabajo del area de contabilidad.', 'estado_solucion': 'investigacion', 'notificado_osri': 'si'},
    {'nombre_incidente': 'Fuga de datos por USB', 'descripcion': 'Se detecto transferencia no autorizada de archivos confidenciales a un dispositivo USB externo.', 'estado_solucion': 'nuevo', 'notificado_osri': 'no'},
]
incidentes = []
for i, ind in enumerate(inc_data):
    inc = Incidente(
        reporte=reportes[i],
        **ind
    )
    inc.fecha_hora = timezone.now() - timedelta(days=i)
    inc.save()
    # Add many-to-many relations
    inc.servicios.add(servicios[i % len(servicios)])
    inc.areas.add(areas[i % len(areas)])
    inc.subcategorias.add(Subcategoria.objects.all()[i % Subcategoria.objects.count()])
    print(f'Incidente created: {inc.nombre_incidente} - {inc.estado_solucion}')
    incidentes.append(inc)

# Create involucrados
inv_data = [
    {'nombres': 'Roberto', 'apellidos': 'Diaz', 'usuario': 'rdiaz', 'ip': '192.168.1.100', 'mac': 'AA:BB:CC:DD:EE:01', 'tipo': 'Interno'},
    {'nombres': 'Patricia', 'apellidos': 'Lopez', 'usuario': 'plopez', 'ip': '192.168.1.101', 'mac': 'AA:BB:CC:DD:EE:02', 'tipo': 'Interno'},
    {'nombres': 'Desconocido', 'apellidos': 'Externo', 'usuario': 'unknown1', 'ip': '203.0.113.50', 'mac': '00:00:00:00:00:00', 'tipo': 'Externo'},
    {'nombres': 'Fernando', 'apellidos': 'Ruiz', 'usuario': 'fruiz', 'ip': '192.168.1.105', 'mac': 'AA:BB:CC:DD:EE:05', 'tipo': 'Interno'},
]
involucrados = []
for id_data in inv_data:
    inv, c = Involucrado.objects.get_or_create(ip=id_data['ip'], defaults=id_data)
    if c: print(f'Involucrado created: {inv.nombres} {inv.apellidos}')
    involucrados.append(inv)

# Create InvolucradoIncidente
for i, inv in enumerate(involucrados[:3]):
    inc_inv = InvolucradoIncidente.objects.create(
        incidente=incidentes[i],
        involucrado=inv,
        descripcion=f'Persona involucrada en el incidente #{i+1}',
        medida_impuesta=medidas[i % len(medidas)],
        fecha_inicio=date.today() - timedelta(days=i+1),
        fecha_fin=date.today() + timedelta(days=30)
    )
    print(f'InvolucradoIncidente created: {inc_inv}')

# Create MedidaIncidente
for i, inc in enumerate(incidentes[:4]):
    mi = MedidaIncidente.objects.create(
        incidente=inc,
        medida=medidas[i % len(medidas)],
        responsable=responsables[i % len(responsables)],
        fecha_cumplimiento=date.today() + timedelta(days=7),
        estado_cumplimiento=(i < 2),
        observaciones=f'Medida aplicada al incidente {inc.nombre_incidente}'
    )
    print(f'MedidaIncidente created: {mi}')

print('\n=== SAMPLE DATA POPULATED SUCCESSFULLY ===')
print(f'Users: {User.objects.count()}')
print(f'Responsables: {Responsable.objects.count()}')
print(f'Categorias: {Categoria.objects.count()}')
print(f'Subcategorias: {Subcategoria.objects.count()}')
print(f'Servicios: {Servicio.objects.count()}')
print(f'Areas: {Area.objects.count()}')
print(f'Medidas: {Medida.objects.count()}')
print(f'Reportes: {Reporte.objects.count()}')
print(f'Incidentes: {Incidente.objects.count()}')
print(f'Involucrados: {Involucrado.objects.count()}')
print(f'InvolucradoIncidente: {InvolucradoIncidente.objects.count()}')
print(f'MedidaIncidente: {MedidaIncidente.objects.count()}')
