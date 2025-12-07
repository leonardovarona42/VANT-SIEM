from django.core.management.base import BaseCommand
from EVENT_M.models import (
    Categoria, Subcategoria, Servicio, Responsable, Area, Medida,
    Reporte, Incidente, MedidaIncidente, Involucrado, InvolucradoIncidente,
    MonitoreoServicio, ConfiguracionMonitoreo
)
from django.utils import timezone
from datetime import date, datetime, timedelta
import random

class Command(BaseCommand):
    help = 'Poblar todas las tablas de EVENT_M con datos extensos de ejemplo'

    def handle(self, *args, **options):
        # Poblar Servicios adicionales
        servicios_data = [
            {'nombre': 'Servidor Web Principal', 'descripcion': 'Servidor Apache principal', 'host': '192.168.1.10', 'monitorear': True},
            {'nombre': 'Base de Datos PostgreSQL', 'descripcion': 'Base de datos principal', 'host': '192.168.1.11', 'monitorear': True},
            {'nombre': 'Servidor de Correo', 'descripcion': 'Servidor SMTP/IMAP', 'host': '192.168.1.12', 'monitorear': True},
            {'nombre': 'Firewall Principal', 'descripcion': 'Firewall de red', 'host': '192.168.1.1', 'monitorear': True},
            {'nombre': 'Servidor DNS', 'descripcion': 'Servidor de nombres de dominio', 'host': '192.168.1.13', 'monitorear': False},
            {'nombre': 'Servidor de Aplicaciones', 'descripcion': 'Servidor de aplicaciones Java', 'host': '192.168.1.14', 'monitorear': True},
            {'nombre': 'Servidor de Archivos', 'descripcion': 'Servidor NAS para almacenamiento', 'host': '192.168.1.15', 'monitorear': True},
            {'nombre': 'VPN Gateway', 'descripcion': 'Gateway para conexiones VPN', 'host': '192.168.1.16', 'monitorear': True},
            {'nombre': 'Servidor de Backup', 'descripcion': 'Servidor de respaldos automáticos', 'host': '192.168.1.17', 'monitorear': False},
            {'nombre': 'Servidor de Monitoreo', 'descripcion': 'Servidor Nagios/Zabbix', 'host': '192.168.1.18', 'monitorear': True},
        ]

        servicios = []
        for data in servicios_data:
            servicio, created = Servicio.objects.get_or_create(
                nombre=data['nombre'],
                defaults=data
            )
            servicios.append(servicio)
            if created:
                self.stdout.write(f'Creado servicio: {servicio.nombre}')

        # Poblar Responsables adicionales
        responsables_data = [
            {'nombres': 'Juan', 'apellidos': 'Pérez', 'email': 'juan.perez@empresa.cu', 'telefono_particular': '+53-555-0101', 'telefono_corp': '+53-555-0202', 'tipo': 'Técnico', 'descripcion': 'Especialista en ciberseguridad'},
            {'nombres': 'María', 'apellidos': 'González', 'email': 'maria.gonzalez@empresa.cu', 'telefono_particular': '+53-555-0103', 'telefono_corp': '+53-555-0204', 'tipo': 'Administrador', 'descripcion': 'Administradora de sistemas'},
            {'nombres': 'Carlos', 'apellidos': 'Rodríguez', 'email': 'carlos.rodriguez@empresa.cu', 'telefono_particular': '+53-555-0105', 'telefono_corp': '+53-555-0206', 'tipo': 'Gerente', 'descripcion': 'Gerente de TI'},
            {'nombres': 'Ana', 'apellidos': 'Martínez', 'email': 'ana.martinez@empresa.cu', 'telefono_particular': '+53-555-0107', 'telefono_corp': '+53-555-0208', 'tipo': 'Analista', 'descripcion': 'Analista de seguridad'},
            {'nombres': 'Pedro', 'apellidos': 'López', 'email': 'pedro.lopez@empresa.cu', 'telefono_particular': '+53-555-0109', 'telefono_corp': '+53-555-0210', 'tipo': 'Operador', 'descripcion': 'Operador de sistemas'},
            {'nombres': 'Luis', 'apellidos': 'Fernández', 'email': 'luis.fernandez@empresa.cu', 'telefono_particular': '+53-555-0111', 'telefono_corp': '+53-555-0212', 'tipo': 'Especialista', 'descripcion': 'Especialista en redes'},
            {'nombres': 'Carmen', 'apellidos': 'García', 'email': 'carmen.garcia@empresa.cu', 'telefono_particular': '+53-555-0113', 'telefono_corp': '+53-555-0214', 'tipo': 'Consultor', 'descripcion': 'Consultora de ciberseguridad'},
            {'nombres': 'Miguel', 'apellidos': 'Torres', 'email': 'miguel.torres@empresa.cu', 'telefono_particular': '+53-555-0115', 'telefono_corp': '+53-555-0216', 'tipo': 'Auditor', 'descripcion': 'Auditor de seguridad'},
            {'nombres': 'Isabel', 'apellidos': 'Ruiz', 'email': 'isabel.ruiz@empresa.cu', 'telefono_particular': '+53-555-0117', 'telefono_corp': '+53-555-0218', 'tipo': 'Investigador', 'descripcion': 'Investigadora de incidentes'},
            {'nombres': 'Roberto', 'apellidos': 'Jiménez', 'email': 'roberto.jimenez@empresa.cu', 'telefono_particular': '+53-555-0119', 'telefono_corp': '+53-555-0220', 'tipo': 'Coordinador', 'descripcion': 'Coordinador de respuesta a incidentes'},
        ]

        responsables = []
        for data in responsables_data:
            responsable, created = Responsable.objects.get_or_create(
                email=data['email'],
                defaults=data
            )
            responsables.append(responsable)
            if created:
                self.stdout.write(f'Creado responsable: {responsable}')

        # Poblar Áreas adicionales
        areas_data = [
            {'nombre': 'Centro de Datos', 'acronimo': 'CD', 'cuadro_centro': responsables[0], 'rsi': responsables[1], 'admin': responsables[2]},
            {'nombre': 'Redes y Comunicaciones', 'acronimo': 'RC', 'cuadro_centro': responsables[1], 'rsi': responsables[2], 'admin': responsables[3]},
            {'nombre': 'Sistemas de Información', 'acronimo': 'SI', 'cuadro_centro': responsables[2], 'rsi': responsables[3], 'admin': responsables[4]},
            {'nombre': 'Seguridad Informática', 'acronimo': 'SEG', 'cuadro_centro': responsables[3], 'rsi': responsables[4], 'admin': responsables[5]},
            {'nombre': 'Desarrollo de Software', 'acronimo': 'DEV', 'cuadro_centro': responsables[4], 'rsi': responsables[5], 'admin': responsables[6]},
        ]

        areas = []
        for data in areas_data:
            area, created = Area.objects.get_or_create(
                nombre=data['nombre'],
                defaults=data
            )
            areas.append(area)
            if created:
                self.stdout.write(f'Creada área: {area.nombre}')

        # Poblar Medidas adicionales
        medidas_data = [
            {'nombre': 'Bloqueo de IP', 'descripcion': 'Bloquear dirección IP maliciosa en firewall'},
            {'nombre': 'Cambio de contraseñas', 'descripcion': 'Forzar cambio de contraseñas comprometidas'},
            {'nombre': 'Actualización de software', 'descripcion': 'Aplicar parches de seguridad'},
            {'nombre': 'Desconexión de red', 'descripcion': 'Aislar sistema comprometido'},
            {'nombre': 'Análisis forense', 'descripcion': 'Realizar análisis forense del incidente'},
            {'nombre': 'Notificación a autoridades', 'descripcion': 'Reportar incidente a OSRI'},
            {'nombre': 'Restauración de backups', 'descripcion': 'Restaurar datos desde backup limpio'},
            {'nombre': 'Monitoreo adicional', 'descripcion': 'Implementar monitoreo intensivo'},
            {'nombre': 'Segmentación de red', 'descripcion': 'Implementar segmentación de red adicional'},
            {'nombre': 'Entrenamiento de usuarios', 'descripcion': 'Capacitar usuarios en seguridad'},
            {'nombre': 'Auditoría de logs', 'descripcion': 'Revisar logs de seguridad'},
            {'nombre': 'Implementación de MFA', 'descripcion': 'Implementar autenticación multifactor'},
            {'nombre': 'Cifrado de datos', 'descripcion': 'Aplicar cifrado a datos sensibles'},
            {'nombre': 'Actualización de políticas', 'descripcion': 'Revisar y actualizar políticas de seguridad'},
            {'nombre': 'Pruebas de penetración', 'descripcion': 'Realizar pruebas de seguridad'},
        ]

        medidas = []
        for data in medidas_data:
            medida, created = Medida.objects.get_or_create(
                nombre=data['nombre'],
                defaults=data
            )
            medidas.append(medida)
            if created:
                self.stdout.write(f'Creada medida: {medida.nombre}')

        # Poblar Reportes adicionales
        reportes_data = [
            {'nombre_informante': 'Usuario Anónimo', 'email_informante': 'anonimo@empresa.cu', 'area': areas[0], 'descripcion': 'Se detectó actividad sospechosa en el servidor web'},
            {'nombre_informante': 'Administrador de Red', 'email_informante': 'admin.red@empresa.cu', 'area': areas[1], 'descripcion': 'Pérdida de conectividad en segmento de red'},
            {'nombre_informante': 'Desarrollador', 'email_informante': 'dev@empresa.cu', 'area': areas[2], 'descripcion': 'Archivo sospechoso encontrado en servidor de desarrollo'},
            {'nombre_informante': 'Analista de Seguridad', 'email_informante': 'seguridad@empresa.cu', 'area': areas[3], 'descripcion': 'Múltiples intentos de login fallidos'},
            {'nombre_informante': 'Operador de Sistemas', 'email_informante': 'operador@empresa.cu', 'area': areas[0], 'descripcion': 'Alto uso de CPU en servidor de base de datos'},
            {'nombre_informante': 'Usuario Final', 'email_informante': 'usuario@empresa.cu', 'area': areas[4], 'descripcion': 'Correo sospechoso recibido'},
            {'nombre_informante': 'Auditor Externo', 'email_informante': 'auditor@empresa.cu', 'area': areas[3], 'descripcion': 'Vulnerabilidades encontradas en escaneo'},
            {'nombre_informante': 'Consultor', 'email_informante': 'consultor@empresa.cu', 'area': areas[2], 'descripcion': 'Código malicioso en repositorio'},
        ]

        reportes = []
        for data in reportes_data:
            reporte, created = Reporte.objects.get_or_create(
                nombre_informante=data['nombre_informante'],
                email_informante=data['email_informante'],
                defaults=data
            )
            reportes.append(reporte)
            if created:
                self.stdout.write(f'Creado reporte: {reporte.nombre_informante}')

        # Poblar Involucrados adicionales
        involucrados_data = [
            {'nombres': 'Usuario', 'apellidos': 'Sospechoso', 'usuario': 'user_susp', 'ip': '192.168.1.50', 'mac': '00:11:22:33:44:55', 'tipo': 'Usuario interno'},
            {'nombres': 'Atacante', 'apellidos': 'Externo', 'usuario': 'unknown', 'ip': '203.0.113.1', 'mac': 'AA:BB:CC:DD:EE:FF', 'tipo': 'Atacante externo'},
            {'nombres': 'Empleado', 'apellidos': 'Comprometido', 'usuario': 'emp_comp', 'ip': '192.168.1.60', 'mac': '11:22:33:44:55:66', 'tipo': 'Usuario interno'},
            {'nombres': 'Contratista', 'apellidos': 'Temporal', 'usuario': 'temp_user', 'ip': '192.168.1.70', 'mac': '22:33:44:55:66:77', 'tipo': 'Usuario temporal'},
            {'nombres': 'Administrador', 'apellidos': 'Descuidado', 'usuario': 'admin_weak', 'ip': '192.168.1.80', 'mac': '33:44:55:66:77:88', 'tipo': 'Administrador'},
            {'nombres': 'Desarrollador', 'apellidos': 'Junior', 'usuario': 'dev_jr', 'ip': '192.168.1.90', 'mac': '44:55:66:77:88:99', 'tipo': 'Desarrollador'},
            {'nombres': 'Bot', 'apellidos': 'Automatizado', 'usuario': 'bot_scan', 'ip': '185.220.101.1', 'mac': 'FF:FF:FF:FF:FF:FF', 'tipo': 'Bot de escaneo'},
            {'nombres': 'Hacker', 'apellidos': 'Profesional', 'usuario': 'hacker_pro', 'ip': '45.67.89.123', 'mac': 'AA:AA:AA:AA:AA:AA', 'tipo': 'Atacante profesional'},
            {'nombres': 'Usuario', 'apellidos': 'Phishing', 'usuario': 'phished_user', 'ip': '192.168.1.100', 'mac': '55:66:77:88:99:AA', 'tipo': 'Víctima de phishing'},
            {'nombres': 'Sistema', 'apellidos': 'Comprometido', 'usuario': 'system', 'ip': '192.168.1.110', 'mac': '66:77:88:99:AA:BB', 'tipo': 'Sistema comprometido'},
        ]

        involucrados = []
        for data in involucrados_data:
            involucrado, created = Involucrado.objects.get_or_create(
                ip=data['ip'],
                defaults=data
            )
            involucrados.append(involucrado)
            if created:
                self.stdout.write(f'Creado involucrado: {involucrado}')

        # Crear reportes adicionales para incidentes nuevos
        reportes_adicionales_data = [
            {'nombre_informante': 'Soporte Técnico', 'email_informante': 'soporte@empresa.cu', 'area': areas[0], 'descripcion': 'Reporte de intento de phishing detectado'},
            {'nombre_informante': 'Equipo de Seguridad', 'email_informante': 'seguridad@empresa.cu', 'area': areas[3], 'descripcion': 'Vulnerabilidad zero-day identificada'},
            {'nombre_informante': 'Auditoría Interna', 'email_informante': 'auditoria@empresa.cu', 'area': areas[3], 'descripcion': 'Posible fuga de datos detectada'},
            {'nombre_informante': 'Desarrollo', 'email_informante': 'desarrollo@empresa.cu', 'area': areas[4], 'descripcion': 'Malware en cadena de suministro'},
            {'nombre_informante': 'Redes', 'email_informante': 'redes@empresa.cu', 'area': areas[1], 'descripcion': 'Escaneo masivo de puertos detectado'},
            {'nombre_informante': 'Web Admin', 'email_informante': 'webadmin@empresa.cu', 'area': areas[2], 'descripcion': 'Intento de inyección SQL'},
            {'nombre_informante': 'Backup Admin', 'email_informante': 'backup@empresa.cu', 'area': areas[0], 'descripcion': 'Ransomware detectado en servidor'},
        ]

        reportes_adicionales = []
        for data in reportes_adicionales_data:
            reporte, created = Reporte.objects.get_or_create(
                nombre_informante=data['nombre_informante'],
                email_informante=data['email_informante'],
                defaults=data
            )
            reportes_adicionales.append(reporte)
            if created:
                self.stdout.write(f'Creado reporte adicional: {reporte.nombre_informante}')

        # Poblar Incidentes adicionales a lo largo del año
        subcategorias = list(Subcategoria.objects.all())
        incidentes_data = [
            {'nombre_incidente': 'Intento de phishing', 'descripcion': 'Usuario reportó correo electrónico sospechoso', 'reporte': reportes_adicionales[0], 'servicios': [servicios[2]], 'areas': [areas[4]], 'subcategorias': [subcategorias[23]], 'estado_solucion': 'cerrado', 'notificado_osri': 'no', 'fecha': date(2025, 4, 5)},
            {'nombre_incidente': 'Vulnerabilidad zero-day', 'descripcion': 'Explotación de vulnerabilidad desconocida', 'reporte': reportes_adicionales[1], 'servicios': [servicios[5]], 'areas': [areas[2]], 'subcategorias': [subcategorias[19]], 'estado_solucion': 'mitigacion', 'notificado_osri': 'si', 'fecha': date(2025, 5, 12)},
            {'nombre_incidente': 'Fuga de datos', 'descripcion': 'Posible exposición de información sensible', 'reporte': reportes_adicionales[2], 'servicios': [servicios[1]], 'areas': [areas[3]], 'subcategorias': [subcategorias[16]], 'estado_solucion': 'investigacion', 'notificado_osri': 'si', 'fecha': date(2025, 6, 18)},
            {'nombre_incidente': 'Ataque de cadena de suministro', 'descripcion': 'Malware introducido a través de actualización', 'reporte': reportes_adicionales[3], 'servicios': [servicios[6]], 'areas': [areas[4]], 'subcategorias': [subcategorias[33]], 'estado_solucion': 'abierto', 'notificado_osri': 'si', 'fecha': date(2025, 7, 25)},
            {'nombre_incidente': 'Escaneo de puertos', 'descripcion': 'Detección de escaneo masivo de puertos', 'reporte': reportes_adicionales[4], 'servicios': [servicios[3]], 'areas': [areas[1]], 'subcategorias': [subcategorias[0]], 'estado_solucion': 'cerrado', 'notificado_osri': 'no', 'fecha': date(2025, 8, 8)},
            {'nombre_incidente': 'Inyección SQL', 'descripcion': 'Intento de inyección SQL en aplicación web', 'reporte': reportes_adicionales[5], 'servicios': [servicios[0]], 'areas': [areas[2]], 'subcategorias': [subcategorias[0]], 'estado_solucion': 'cerrado', 'notificado_osri': 'no', 'fecha': date(2025, 9, 14)},
            {'nombre_incidente': 'Ransomware', 'descripcion': 'Sistema infectado con ransomware', 'reporte': reportes_adicionales[6], 'servicios': [servicios[7]], 'areas': [areas[0]], 'subcategorias': [subcategorias[4]], 'estado_solucion': 'mitigacion', 'notificado_osri': 'si', 'fecha': date(2025, 10, 30)},
        ]

        incidentes = []
        for data in incidentes_data:
            incidente, created = Incidente.objects.get_or_create(
                nombre_incidente=data['nombre_incidente'],
                defaults={
                    'descripcion': data['descripcion'],
                    'reporte': data['reporte'],
                    'estado_solucion': data['estado_solucion'],
                    'notificado_osri': data['notificado_osri'],
                    'fecha_hora': datetime.combine(data['fecha'], datetime.min.time()),
                }
            )
            if created:
                incidente.servicios.set(data['servicios'])
                incidente.areas.set(data['areas'])
                incidente.subcategorias.set(data['subcategorias'])
                incidente.save()
                self.stdout.write(f'Creado incidente: {incidente.nombre_incidente}')
            incidentes.append(incidente)

        # Poblar MedidaIncidente con más medidas por incidente
        for incidente in incidentes:
            num_medidas = random.randint(2, 5)
            selected_medidas = random.sample(medidas, num_medidas)
            for medida in selected_medidas:
                medida_inc, created = MedidaIncidente.objects.get_or_create(
                    incidente=incidente,
                    medida=medida,
                    defaults={
                        'responsable': random.choice(responsables),
                        'fecha_cumplimiento': incidente.fecha_hora.date() + timedelta(days=random.randint(0, 30)),
                        'estado_cumplimiento': random.choice([True, False]),
                        'observaciones': f'Medida {medida.nombre} aplicada con resultado variable'
                    }
                )
                if created:
                    self.stdout.write(f'Creada medida-incidente: {medida_inc}')

        # Poblar InvolucradoIncidente con múltiples involucrados por incidente
        for incidente in incidentes:
            num_involucrados = random.randint(1, 3)
            selected_involucrados = random.sample(involucrados, num_involucrados)
            for involucrado in selected_involucrados:
                involucrado_inc, created = InvolucradoIncidente.objects.get_or_create(
                    incidente=incidente,
                    involucrado=involucrado,
                    defaults={
                        'descripcion': f'Involucrado en incidente {incidente.nombre_incidente}',
                        'medida_impuesta': random.choice(medidas),
                        'fecha_inicio': incidente.fecha_hora.date(),
                        'fecha_fin': incidente.fecha_hora.date() + timedelta(days=random.randint(1, 60)),
                    }
                )
                if created:
                    self.stdout.write(f'Creado involucrado-incidente: {involucrado_inc}')

        # Poblar MonitoreoServicio con datos históricos
        for servicio in servicios:
            if servicio.monitorear:
                # Crear múltiples entradas de monitoreo a lo largo del año
                for i in range(12):  # Un registro por mes
                    fecha_monitoreo = timezone.now() - timedelta(days=30*i)
                    monitoreo, created = MonitoreoServicio.objects.get_or_create(
                        servicio=servicio,
                        timestamp=fecha_monitoreo,
                        defaults={
                            'latencia': random.uniform(5.0, 50.0),
                            'estado': random.choice([True, True, True, False]),  # 75% uptime
                            'error': 'Timeout' if random.random() < 0.1 else None
                        }
                    )
                    if created:
                        self.stdout.write(f'Creado monitoreo histórico para: {servicio.nombre}')

        # Poblar ConfiguracionMonitoreo
        config, created = ConfiguracionMonitoreo.objects.get_or_create(
            defaults={
                'intervalo_segundos': 60,
                'activo': True,
                'ultima_ejecucion': timezone.now()
            }
        )
        if created:
            self.stdout.write('Creada configuración de monitoreo')

        self.stdout.write(self.style.SUCCESS('Población extensa completa de todas las tablas de EVENT_M'))