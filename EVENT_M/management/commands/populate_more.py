from django.core.management.base import BaseCommand
from EVENT_M.models import (
    Servicio, Responsable, Area, Medida, Reporte, Incidente,
    MedidaIncidente, Involucrado, InvolucradoIncidente, MonitoreoServicio, Subcategoria
)
from django.utils import timezone
from datetime import date, datetime, timedelta
import random

class Command(BaseCommand):
    help = 'Poblar aún más datos en EVENT_M'

    def handle(self, *args, **options):
        # Obtener datos existentes
        servicios = list(Servicio.objects.all())
        responsables = list(Responsable.objects.all())
        areas = list(Area.objects.all())
        medidas = list(Medida.objects.all())
        involucrados = list(Involucrado.objects.all())
        subcategorias = list(Subcategoria.objects.all())

        # Crear más servicios
        servicios_adicionales = [
            {'nombre': 'Servidor de Logs', 'descripcion': 'Servidor centralizado de logs', 'host': '192.168.1.19', 'monitorear': True},
            {'nombre': 'Proxy Inverso', 'descripcion': 'Nginx proxy reverso', 'host': '192.168.1.20', 'monitorear': True},
            {'nombre': 'Servidor de Autenticación', 'descripcion': 'LDAP/Active Directory', 'host': '192.168.1.21', 'monitorear': True},
            {'nombre': 'Servidor de Archivos Compartidos', 'descripcion': 'Samba/CIFS server', 'host': '192.168.1.22', 'monitorear': False},
            {'nombre': 'Balanceador de Carga', 'descripcion': 'HAProxy load balancer', 'host': '192.168.1.23', 'monitorear': True},
        ]

        for data in servicios_adicionales:
            servicio, created = Servicio.objects.get_or_create(
                nombre=data['nombre'],
                defaults=data
            )
            servicios.append(servicio)
            if created:
                self.stdout.write(f'Creado servicio adicional: {servicio.nombre}')

        # Crear más responsables
        responsables_adicionales = [
            {'nombres': 'Diego', 'apellidos': 'Morales', 'email': 'diego.morales@empresa.cu', 'telefono_particular': '+53-555-0121', 'telefono_corp': '+53-555-0221', 'tipo': 'Ingeniero', 'descripcion': 'Ingeniero de sistemas'},
            {'nombres': 'Laura', 'apellidos': 'Vázquez', 'email': 'laura.vazquez@empresa.cu', 'telefono_particular': '+53-555-0123', 'telefono_corp': '+53-555-0223', 'tipo': 'Coordinadora', 'descripcion': 'Coordinadora de proyectos'},
            {'nombres': 'Oscar', 'apellidos': 'Reyes', 'email': 'oscar.reyes@empresa.cu', 'telefono_particular': '+53-555-0125', 'telefono_corp': '+53-555-0225', 'tipo': 'Supervisor', 'descripcion': 'Supervisor de operaciones'},
        ]

        for data in responsables_adicionales:
            responsable, created = Responsable.objects.get_or_create(
                email=data['email'],
                defaults=data
            )
            responsables.append(responsable)
            if created:
                self.stdout.write(f'Creado responsable adicional: {responsable}')

        # Crear más medidas
        medidas_adicionales = [
            {'nombre': 'Actualización de firmware', 'descripcion': 'Actualizar firmware de dispositivos'},
            {'nombre': 'Revisión de permisos', 'descripcion': 'Auditar y corregir permisos de archivos'},
            {'nombre': 'Implementación de WAF', 'descripcion': 'Desplegar Web Application Firewall'},
            {'nombre': 'Monitoreo de integridad', 'descripcion': 'Implementar monitoreo de integridad de archivos'},
            {'nombre': 'Backup encriptado', 'descripcion': 'Asegurar que los backups estén encriptados'},
            {'nombre': 'Desarrollo de planes de contingencia', 'descripcion': 'Crear planes de respuesta a incidentes'},
            {'nombre': 'Simulacros de seguridad', 'descripcion': 'Realizar ejercicios de simulación'},
            {'nombre': 'Actualización de inventario', 'descripcion': 'Mantener inventario actualizado de activos'},
        ]

        for data in medidas_adicionales:
            medida, created = Medida.objects.get_or_create(
                nombre=data['nombre'],
                defaults=data
            )
            medidas.append(medida)
            if created:
                self.stdout.write(f'Creada medida adicional: {medida.nombre}')

        # Crear más involucrados
        involucrados_adicionales = [
            {'nombres': 'Cliente', 'apellidos': 'Externo', 'usuario': 'cliente_ext', 'ip': '203.0.113.50', 'mac': 'BB:CC:DD:EE:FF:11', 'tipo': 'Usuario externo'},
            {'nombres': 'Proveedor', 'apellidos': 'Servicio', 'usuario': 'proveedor', 'ip': '198.51.100.10', 'mac': 'CC:DD:EE:FF:11:22', 'tipo': 'Proveedor de servicios'},
            {'nombres': 'Intruso', 'apellidos': 'Desconocido', 'usuario': 'intruso', 'ip': '185.220.101.50', 'mac': 'DD:EE:FF:11:22:33', 'tipo': 'Intruso no identificado'},
            {'nombres': 'Usuario', 'apellidos': 'Remoto', 'usuario': 'user_remote', 'ip': '192.168.2.100', 'mac': 'EE:FF:11:22:33:44', 'tipo': 'Usuario VPN'},
            {'nombres': 'Dispositivo', 'apellidos': 'IoT', 'usuario': 'iot_device', 'ip': '192.168.1.150', 'mac': 'FF:11:22:33:44:55', 'tipo': 'Dispositivo IoT'},
        ]

        for data in involucrados_adicionales:
            involucrado, created = Involucrado.objects.get_or_create(
                ip=data['ip'],
                defaults=data
            )
            involucrados.append(involucrado)
            if created:
                self.stdout.write(f'Creado involucrado adicional: {involucrado}')

        # Crear más reportes e incidentes
        for i in range(15):  # Crear 15 incidentes adicionales
            # Crear reporte
            reporte_data = {
                'nombre_informante': f'Reportante {i+1}',
                'email_informante': f'reportante{i+1}@empresa.cu',
                'area': random.choice(areas),
                'descripcion': f'Reporte de incidente #{i+1} generado automáticamente'
            }
            reporte, created = Reporte.objects.get_or_create(
                nombre_informante=reporte_data['nombre_informante'],
                email_informante=reporte_data['email_informante'],
                defaults=reporte_data
            )
            if created:
                self.stdout.write(f'Creado reporte: {reporte.nombre_informante}')

            # Crear incidente
            fecha_incidente = date(2025, random.randint(1, 12), random.randint(1, 28))
            incidente_data = {
                'nombre_incidente': f'Incidente Automático #{i+1}',
                'descripcion': f'Incidente generado automáticamente para pruebas #{i+1}',
                'reporte': reporte,
                'estado_solucion': random.choice(['nuevo', 'abierto', 'investigacion', 'mitigacion', 'cerrado']),
                'notificado_osri': random.choice(['si', 'no']),
                'fecha_hora': datetime.combine(fecha_incidente, datetime.min.time()),
            }
            incidente, created = Incidente.objects.get_or_create(
                nombre_incidente=incidente_data['nombre_incidente'],
                defaults=incidente_data
            )
            if created:
                # Asignar servicios, areas, subcategorias aleatoriamente
                incidente.servicios.set(random.sample(servicios, random.randint(1, 3)))
                incidente.areas.set(random.sample(areas, random.randint(1, 2)))
                incidente.subcategorias.set(random.sample(subcategorias, random.randint(1, 2)))
                incidente.save()
                self.stdout.write(f'Creado incidente: {incidente.nombre_incidente}')

                # Crear medidas para el incidente
                num_medidas = random.randint(2, 4)
                selected_medidas = random.sample(medidas, num_medidas)
                for medida in selected_medidas:
                    medida_inc, created = MedidaIncidente.objects.get_or_create(
                        incidente=incidente,
                        medida=medida,
                        defaults={
                            'responsable': random.choice(responsables),
                            'fecha_cumplimiento': fecha_incidente + timedelta(days=random.randint(0, 30)),
                            'estado_cumplimiento': random.choice([True, False]),
                            'observaciones': f'Medida aplicada automáticamente - {random.choice(["Exitosa", "En progreso", "Pendiente"])}'
                        }
                    )

                # Crear involucrados para el incidente
                num_involucrados = random.randint(1, 3)
                selected_involucrados = random.sample(involucrados, num_involucrados)
                for involucrado in selected_involucrados:
                    involucrado_inc, created = InvolucradoIncidente.objects.get_or_create(
                        incidente=incidente,
                        involucrado=involucrado,
                        defaults={
                            'descripcion': f'Involucrado en incidente automático #{i+1}',
                            'medida_impuesta': random.choice(medidas),
                            'fecha_inicio': fecha_incidente,
                            'fecha_fin': fecha_incidente + timedelta(days=random.randint(1, 60)),
                        }
                    )

        # Crear más datos de monitoreo histórico
        for servicio in servicios:
            if servicio.monitorear:
                for i in range(24):  # Más datos históricos
                    fecha_monitoreo = timezone.now() - timedelta(hours=i)
                    monitoreo, created = MonitoreoServicio.objects.get_or_create(
                        servicio=servicio,
                        timestamp=fecha_monitoreo,
                        defaults={
                            'latencia': random.uniform(1.0, 100.0),
                            'estado': random.choice([True, True, True, False]),
                            'error': 'Timeout' if random.random() < 0.05 else None
                        }
                    )

        self.stdout.write(self.style.SUCCESS('Población adicional completada'))