import random
import uuid
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from soc_app.models import (
    Categoria, Subcategoria, Responsable, Area, Medida, Reporte,
    Incidente, MedidaIncidente, Involucrado, InvolucradoIncidente,
    DlpPolicy, DlpRule, DlpThreat, DlpScanSummary,
    Servicio, ServicioIP, PuertoDispositivo, ConexionTopologica,
    MonitoreoServicio,
)


def _random_date_in_month(year, month):
    import calendar
    last_day = calendar.monthrange(year, month)[1]
    day = random.randint(1, last_day)
    hour = random.randint(6, 22)
    minute = random.randint(0, 59)
    return timezone.datetime(year, month, day, hour, minute, tzinfo=timezone.get_current_timezone())


def _set_auto_now(model_class, obj, field_name, value):
    model_class.objects.filter(pk=obj.pk).update(**{field_name: value})
    obj.refresh_from_db()


class Command(BaseCommand):
    help = "Re-seed SOC con datos de prueba realistas distribuidos en 6 meses"

    def handle(self, *args, **options):
        now = timezone.now()

        self.stdout.write("Limpiando datos existentes...")
        MonitoreoServicio.objects.all().delete()
        ConexionTopologica.objects.all().delete()
        PuertoDispositivo.objects.all().delete()
        ServicioIP.objects.all().delete()
        Servicio.objects.all().delete()
        MedidaIncidente.objects.all().delete()
        InvolucradoIncidente.objects.all().delete()
        Involucrado.objects.all().delete()
        Incidente.objects.all().delete()
        Reporte.objects.all().delete()
        Medida.objects.all().delete()
        Area.objects.all().delete()
        Subcategoria.objects.all().delete()
        Categoria.objects.all().delete()
        Responsable.objects.all().delete()
        DlpScanSummary.objects.all().delete()
        DlpThreat.objects.all().delete()
        DlpRule.objects.all().delete()
        DlpPolicy.objects.all().delete()
        self.stdout.write("Limpieza completa.")

        # ── Responsables ──────────────────────────────────────────────
        self.stdout.write("Creando responsables...")
        responsables = []
        data_resp = [
            ("Carlos", "Garcia Lopez", "cgarcia@empresa.cu", "cuadro", "Jefe del Centro de Seguridad"),
            ("Maria", "Rodriguez Perez", "mrodriguez@empresa.cu", "rsi", "RSI Senior"),
            ("Pedro", "Martinez Fernandez", "pmartinez@empresa.cu", "rsi", "RSI Junior"),
            ("Ana", "Sanchez Torres", "asanchez@empresa.cu", "admin", "Administradora de Redes"),
            ("Luis", "Hernandez Castro", "lhernandez@empresa.cu", "cuadro", "Subjefe del Centro"),
            ("Yamila", "Diaz Morales", "ydiaz@empresa.cu", "rsi", "RSI de Incidentes DLP"),
            ("Roberto", "Lopez Vega", "rlopez@empresa.cu", "admin", "Administrador de Sistemas"),
            ("Sistema", "Automatico", "siem@empresa.cu", "sistema", "Deteccion automatica por SIEM"),
        ]
        for nom, ape, email, tipo, desc in data_resp:
            r = Responsable.objects.create(
                nombres=nom, apellidos=ape, email=email, tipo=tipo, descripcion=desc,
                telefono_corp=f"+53-5{random.randint(100,999)}-{random.randint(1000,9999)}"
            )
            responsables.append(r)

        # ── Categorias y Subcategorias ────────────────────────────────
        self.stdout.write("Creando categorias y subcategorias...")
        cats_data = {
            "Malware / Ransomware": [
                ("Ransomware cifrado", 9), ("Troyano de acceso remoto", 8),
                ("Gusano de red", 7), ("Rootkit", 9), ("Adware potencialmente no deseado", 3),
            ],
            "Phishing / Ingenieria Social": [
                ("Correo de phishing activo", 8), ("Vishing detectado", 7),
                ("Spear phishing a ejecutivos", 9), ("Smishing", 5),
            ],
            "Acceso No Autorizado": [
                ("Brute force exitoso", 8), ("Escalada de privilegios", 9),
                ("Credenciales comprometidas", 7), ("SSH no autorizado", 6),
            ],
            "Fuga de Datos / DLP": [
                ("Exfiltracion por USB", 9), ("Envio de datos a correo externo", 8),
                ("Copia a almacenamiento removible", 7), ("Subida a cloud no autorizada", 8),
            ],
            "Integridad de Datos": [
                ("Cambio no autorizado de archivos criticos", 8), ("Manipulacion de logs", 9),
                ("Corrupcion de base de datos", 7),
            ],
            "Disponibilidad": [
                ("Ataque DDoS", 8), ("Denegacion de servicio local", 5),
                ("Fallo critico de infraestructura", 7),
            ],
            "Cumplimiento / Politicas": [
                ("Uso indebido de privilegios admin", 5), ("Incumplimiento de politica de contrasenas", 4),
                ("Instalacion de software no autorizado", 5),
            ],
        }
        categorias = {}
        subcategorias = []
        for cat_nombre, subs in cats_data.items():
            cat = Categoria.objects.create(nombre=cat_nombre, descripcion=f"Grupo de amenazas: {cat_nombre.lower()}")
            categorias[cat_nombre] = cat
            for sub_nombre, peligro in subs:
                sub = Subcategoria.objects.create(
                    nombre=sub_nombre, categoria=cat,
                    nivel_peligrosidad=peligro, descripcion=f"Subcategoria de {cat_nombre}"
                )
                subcategorias.append(sub)

        # ── Areas ─────────────────────────────────────────────────────
        self.stdout.write("Creando areas...")
        areas_data = [
            ("Centro de Seguridad Informatica", "CSI", 0, 1, 3),
            ("Direccion de Tecnologias de la Informacion", "DTI", 4, 1, 3),
            ("Recursos Humanos", "RRHH", 4, 2, 6),
            ("Finanzas", "FIN", 4, 2, 6),
            ("Produccion", "PRO", 4, 2, 6),
            ("Logistica", "LOG", 4, 2, 6),
            ("Gerencia General", "GG", 0, 1, 3),
            ("Redes y Comunicaciones", "R&C", 4, 1, 3),
        ]
        areas = []
        for nombre, acr, ci, rsi, adm in areas_data:
            area = Area.objects.create(
                nombre=nombre, acronimo=acr,
                cuadro_centro=responsables[ci], rsi=responsables[rsi], admin=responsables[adm],
            )
            areas.append(area)

        # ── Medidas ───────────────────────────────────────────────────
        self.stdout.write("Creando medidas...")
        medidas_data = [
            ("Aislamiento de red", "Desconectar el equipo de la red"),
            ("Bloqueo de cuenta", "Deshabilitar cuenta de usuario"),
            ("Cambio de contrasena", "Forzar cambio de contrasena inmediato"),
            ("Eliminacion de archivo", "Eliminar archivo comprometido"),
            ("Formateo de equipo", "Reinstalacion limpia del sistema"),
            ("Captura de evidencia", "Obtener imagenes de disco y logs"),
            ("Actualizacion de parches", "Aplicar parches de seguridad pendientes"),
            ("Refuerzo de firewall", "Agregar reglas de bloqueo"),
            ("Monitoreo intensivo", "Incrementar frecuencia de monitoreo"),
            ("Notificacion a affected users", "Informar a usuarios impactados"),
            ("Revocacion de VPN", "Deshabilitar acceso VPN del usuario"),
            ("Auditoria de permisos", "Revisar y ajustar permisos de acceso"),
        ]
        medidas = []
        for nombre, desc in medidas_data:
            m = Medida.objects.create(nombre=nombre, descripcion=desc)
            medidas.append(m)

        # ── Reportes (30, spread across 6 months) ─────────────────────
        self.stdout.write("Creando reportes...")
        reportes = []
        nombres_rep = [
            ("Juan", "Perez"), ("Ana", "Gonzalez"), ("Roberto", "Silva"), ("Laura", "Fernandez"),
            ("Miguel", "Torres"), ("Carmen", "Rodriguez"), ("Fernando", "Castro"), ("Isabel", "Morales"),
            ("Diego", "Vargas"), ("Patricia", "Luna"), ("Sergio", "Reyes"), ("Monica", "Castillo"),
            ("Ricardo", "Mendoza"), ("Elena", "Vidal"), ("Andres", "Aguilar"), ("Sofia", "Delgado"),
            ("Manuel", "Ortega"), ("Lucia", "Romero"), ("Pablo", "Navarro"), ("Teresa", "Ramos"),
            ("Javier", "Guerrero"), ("Natalia", "Flores"), ("Oscar", "Jimenez"), ("Diana", "Herrera"),
            ("Rafael", "Pena"), ("Cristina", "Campos"), ("Enrique", "Rios"), ("Valeria", "Soto"),
            ("Hector", "Medina"), ("Adriana", "Cruz"),
        ]
        descripciones = [
            "Equipo presentando comportamiento anormal, posible infeccion por malware",
            "Correo sospechoso recibido con enlace a sitio desconocido",
            "Usuario no puede acceder a sus archivos, posible ransomware",
            "Actividad inusual en la cuenta fuera del horario laboral",
            "Dispositivo USB encontrado conectado sin autorizacion",
            "Servidor con carga inusual de CPU y memoria",
            "Intento de acceso remoto desde IP externa no autorizada",
            "Archivo confidencial encontrado en escritorio compartido",
            "Alerta de intrusion en segmento de red DMZ",
            "Fuga de datos detectada por el sistema DLP",
            "Correos masivos enviados desde cuenta corporativa sospechosamente",
            "Actualizaciones de seguridad bloqueadas en varios equipos",
            "Vulnerabilidad critica sin parchar en servidor de produccion",
            "Software no autorizado instalado en equipo administrativo",
            "Credenciales de administrador compartidas en canal de chat",
            "Certificado SSL expirado en portal de clientes",
            "Dispositivo de red respondiendo con firmware desactualizado",
            "Escaneo de puertos detectado desde red interna",
            "Copia masiva de archivos a dispositivo de almacenamiento externo",
            "Sesion remota activa fuera del horario laboral detectada",
            "Configuracion de firewall modificada sin cambio registrado",
            "Base de datos accesible desde segmento de usuarios generales",
            "VPN activa desde ubicacion geografica anomala",
            "Servicio critico sin monitoreo configurado",
            "Contrasena de servicio compartida entre multiples administradores",
            "Log de auditoria manipulado o eliminado parcialmente",
            "Dispositivo IoT sin segmentacion conectado a red de servidores",
            "Certificado autofirmado detectado en servicio de produccion",
            "Transferencia FTP de archivos clasificados a servidor externo",
            "Cuenta de servicio con privilegios excesivos detectada",
        ]
        meses = [(2026, 2), (2026, 3), (2026, 4), (2026, 5), (2026, 6), (2026, 7)]
        for i in range(30):
            year, month = meses[i % 6]
            fecha = _random_date_in_month(year, month)
            estado = random.choice(["nuevo", "nuevo", "atendido", "atendido", "atendido", "rechazado"])
            r = Reporte.objects.create(
                nombre_informante=f"{nombres_rep[i][0]} {nombres_rep[i][1]}",
                email_informante=f"{nombres_rep[i][0].lower()}@empresa.cu",
                area=random.choice(areas),
                descripcion=descripciones[i],
                estado_solucion=estado,
            )
            _set_auto_now(Reporte, r, "fecha_hora", fecha)
            if estado == "atendido":
                fecha_atencion = fecha + timedelta(hours=random.uniform(0.5, 8))
                fecha_solucion = fecha + timedelta(hours=random.uniform(4, 72))
                Reporte.objects.filter(pk=r.pk).update(fecha_atencion=fecha_atencion, fecha_solucion=fecha_solucion)
                r.refresh_from_db()
            elif estado == "rechazado":
                fecha_atencion = fecha + timedelta(hours=random.uniform(0.5, 4))
                Reporte.objects.filter(pk=r.pk).update(fecha_atencion=fecha_atencion)
                r.refresh_from_db()
            reportes.append(r)

        # ── Servicios ─────────────────────────────────────────────────
        self.stdout.write("Creando servicios...")
        servicios_data = [
            ("Core-Switch-01", "switch", "Cisco Catalyst 9300", "Cisco", "192.168.12.1", "Core"),
            ("Router-Edge-01", "router", "MikroTik CCR1036", "MikroTik", "192.168.12.2", "Core"),
            ("FW-Principal", "firewall", "Fortinet FortiGate 60F", "Fortinet", "192.168.12.3", "Core"),
            ("Dist-Switch-01", "switch", "Cisco Catalyst 2960", "Cisco", "192.168.12.10", "Distribucion"),
            ("Dist-Switch-02", "switch", "Cisco Catalyst 2960", "Cisco", "192.168.12.11", "Distribucion"),
            ("AP-Torre-01", "access_point", "Ubiquiti UniFi AP AC Pro", "Ubiquiti", "192.168.12.20", "Acceso"),
            ("AP-Torre-02", "access_point", "Ubiquiti UniFi AP AC Pro", "Ubiquiti", "192.168.12.21", "Acceso"),
            ("SV-DC-01", "host", "Dell PowerEdge R740", "Dell", "192.168.12.40", "Servidores"),
            ("SV-DC-02", "host", "Dell PowerEdge R740", "Dell", "192.168.12.41", "Servidores"),
            ("SV-Web-01", "host", "HP ProLiant DL380", "HP", "192.168.12.42", "Servidores"),
            ("SV-Testing", "host", "Dell PowerEdge R640", "Dell", "192.168.12.43", "Servidores"),
            ("SV-BD-01", "host", "Dell PowerEdge R740", "Dell", "192.168.12.44", "Servidores"),
            ("NAS-Backup-01", "storage", "Synology DS1621+", "Synology", "192.168.12.50", "Backup"),
            ("UPS-Rack-01", "ups", "APC Smart-UPS 3000", "APC", "192.168.12.60", "Servidores"),
            ("VLAN-Admin", "vlan", "", "", "10.10.1.0", "Gestion"),
            ("VLAN-Servidores", "vlan", "", "", "192.168.12.0", "Servidores"),
            ("VLAN-Usuarios", "vlan", "", "", "172.24.249.0", "Usuarios"),
            ("VLAN-DMZ", "vlan", "", "", "10.0.0.0", "DMZ"),
            ("Red-Corporativa", "red", "", "", "192.168.0.0", "Interna"),
            ("Plataforma-SIEM", "plataforma", "", "", "192.168.12.100", "Servidores"),
        ]
        servicios = []
        for i, (nombre, tipo, modelo, fab, host, red_tipo) in enumerate(servicios_data):
            s = Servicio.objects.create(
                nombre=nombre, tipo=tipo, modelo=modelo, fabricante=fab,
                host=host, red_tipo=red_tipo,
                vlan_id=random.randint(10, 200) if tipo in ("vlan", "switch") else None,
                nivel_red=[0, 0, 0, 1, 1, 2, 2, 0, 0, 1, 1, 0, 2, 2, 1, 0, 2, 1, 0, 1][i] if [0, 0, 0, 1, 1, 2, 2, 0, 0, 1, 1, 0, 2, 2, 1, 0, 2, 1, 0, 1][i] is not None else None,
                responsable=random.choice(responsables[:6]),
                monitorear=tipo in ("host", "switch", "router", "firewall"),
                estado_monitoreo=random.choice(["up", "up", "up", "down"]),
                ubicacion_fisica="Sala de servidores Torre A" if tipo in ("host", "switch", "router", "firewall", "storage", "ups") else "",
                coordenadas_logicas_x=100 + (i % 5) * 200,
                coordenadas_logicas_y=80 + (i // 5) * 120,
            )
            servicios.append(s)

        # ── IPs ───────────────────────────────────────────────────────
        self.stdout.write("Creando IPs...")
        for s in servicios[:15]:
            if s.host:
                ServicioIP.objects.create(
                    servicio=s, ip_address=s.host,
                    hostname=s.nombre.lower().replace("_", "-"),
                    estado="activo", descripcion=f"IP principal de {s.nombre}",
                )

        # ── Puertos ───────────────────────────────────────────────────
        self.stdout.write("Creando puertos...")
        for s in servicios[:7]:
            if s.tipo in ("switch", "router", "firewall"):
                n = 24 if s.tipo == "switch" else 8
                for p in range(1, n + 1):
                    PuertoDispositivo.objects.create(
                        dispositivo=s, numero_puerto=p, etiqueta=f"Eth{p}",
                        velocidad=random.choice(["1g", "1g", "10g"]),
                        estado=random.choice(["activo", "activo", "activo", "inactivo"]),
                        vlan_asignada=random.choice([10, 20, 30, 40, 50]) if s.tipo == "switch" else None,
                    )

        # ── Conexiones ────────────────────────────────────────────────
        self.stdout.write("Creando conexiones...")
        conexiones = [
            (0, 1, "fisica", "cobre", "1 Gbps"), (0, 2, "fisica", "cobre", "1 Gbps"),
            (0, 3, "fisica", "fibra", "10 Gbps"), (3, 4, "fisica", "cobre", "1 Gbps"),
            (3, 7, "fisica", "fibra", "10 Gbps"), (4, 5, "fisica", "cobre", "1 Gbps"),
            (4, 6, "wireless", "wireless", ""), (7, 8, "logica", "virtual", ""),
            (7, 9, "fisica", "cobre", "1 Gbps"), (7, 11, "fisica", "fibra", "10 Gbps"),
            (7, 10, "fisica", "cobre", "1 Gbps"), (9, 12, "logica", "virtual", ""),
            (1, 13, "logica", "virtual", ""), (14, 15, "logica", "virtual", ""),
            (15, 16, "logica", "virtual", ""), (16, 17, "logica", "virtual", ""),
        ]
        for o, d, tipo, medio, banda in conexiones:
            if o < len(servicios) and d < len(servicios):
                ConexionTopologica.objects.create(
                    origen=servicios[o], destino=servicios[d], tipo=tipo,
                    medio=medio, ancho_banda=banda,
                    descripcion=f"Conexion {tipo} entre {servicios[o].nombre} y {servicios[d].nombre}",
                )

        # ── Monitoreo ─────────────────────────────────────────────────
        self.stdout.write("Creando registros de monitoreo...")
        bulk = []
        for s in servicios[:12]:
            if s.monitorear:
                for h in range(48):
                    t = now - timedelta(hours=h)
                    bulk.append(MonitoreoServicio(
                        servicio=s, timestamp=t,
                        latencia=round(random.uniform(1, 50), 2),
                        estado=random.random() > 0.05,
                    ))
        MonitoreoServicio.objects.bulk_create(bulk)

        # ── Incidentes (25, spread across 6 months, varied states) ───
        self.stdout.write("Creando incidentes...")
        incidentes_spec = [
            # (nombre, desc, estado, osri, t_atencion_h, t_solucion_h, n_reportes, n_servicios, n_areas, n_subcats)
            ("Ransomware en estacion de trabajo", "Cifrado de archivos en equipo de Finanzas. Actividad de cifrado masivo detectada.", "investigacion", "si", 1.5, None, 2, 2, 1, 2),
            ("Compromiso de cuenta de administrador", "Cuenta admin comprometida via brute force desde IP interna.", "mitigacion", "si", 0.5, 12, 1, 1, 1, 1),
            ("Exfiltracion de datos por USB", "Empleado copio base de datos de clientes a USB no autorizado.", "investigacion", "si", 2, None, 3, 1, 2, 2),
            ("Ataque DDoS al servidor web", "Servidor web sufrio denegacion de servicio durante 4 horas.", "mitigacion", "si", 0.5, 8, 2, 2, 1, 1),
            ("Malware en servidor de correo", "Troyano detectado en servidor de correo electronico.", "investigacion", "si", 3, None, 1, 1, 1, 2),
            ("Acceso no autorizado a DMZ", "Intento de acceso desde IP externa a servicios en la DMZ.", "abierto", "si", 1, None, 1, 2, 1, 1),
            ("Fuga de datos financieros", "Envio de archivos financieros confidenciales a correo personal.", "mitigacion", "si", 1.5, None, 2, 1, 2, 2),
            ("Vulnerabilidad critica en servidor de BD", "SQL injection detectado en aplicacion interna.", "investigacion", "si", 4, None, 1, 1, 1, 1),
            ("Phishing masivo a empleados", "Campana de phishing targeting a 50+ empleados.", "mitigacion", "si", 0.25, 6, 3, 1, 3, 2),
            ("Rootkit en servidor de produccion", "Rootkit detectado en SV-DC-01 durante escaneo de seguridad.", "nuevo", "no", None, None, 1, 2, 1, 2),
            ("Credenciales comprometidas en GitHub", "Credenciales de API encontradas en repositorio publico.", "cerrado", "si", 1, 12, 1, 1, 1, 1),
            ("Software espia en equipo directivo", "Keylogger detectado en laptop de gerencia.", "cerrado", "si", 0.5, 48, 2, 1, 2, 1),
            ("Secuestro DNS", "Configuracion DNS modificada no autorizadamente.", "investigacion", "si", 2, None, 1, 2, 1, 1),
            ("Exceso de privilegios de servicio", "Cuenta de servicio con permisos de Domain Admin.", "abierto", "si", 6, None, 1, 1, 1, 1),
            ("Escaneo de redes interno malicioso", "Escaneo intensivo de puertos detectado desde VLAN de usuarios.", "mitigacion", "si", 0.5, 3, 1, 3, 1, 1),
            ("Cifrado de archivos de backup", "Archivos de backup cifrados por ransomware.", "investigacion", "si", 1, None, 2, 2, 1, 2),
            ("Manipulacion de logs de auditoria", "Logs del sistema fueron parcialmente eliminados.", "abierto", "si", 3, None, 1, 1, 1, 2),
            ("Cuenta fantasma detectada", "Cuenta de administrador sin propietario conocido.", "investigacion", "si", 8, None, 1, 1, 1, 1),
            ("Malware en dispositivo IoT", "Camara de seguridad comprometida usando como pivote.", "mitigacion", "si", 1, 5, 1, 2, 1, 1),
            ("Fuga de datos por impresora", "Impresora de red configurada para enviar copias a servidor externo.", "cerrado", "si", 2, 36, 2, 1, 1, 1),
            ("Ataque de fuerza bruta SSH", "Multiples intentos fallidos de login SSH desde IP desconocida.", "nuevo", "no", None, None, 1, 1, 1, 1),
            ("Infeccion por cryptominer", "Servidor de testing utilizado para mineria de criptomonedas.", "investigacion", "si", 5, None, 1, 1, 1, 2),
            ("Suplantacion de identidad interna", "Empleado suplantando identidad de otro para acceder a datos.", "abierto", "si", 4, None, 2, 1, 2, 1),
            ("Fuga accidental de datos", "Archivo confidencial enviado por error a lista de distribucion externa.", "cerrado", "si", 0.25, 2, 1, 1, 1, 1),
            ("Compromiso de VPN corporativa", "Acceso VPN desde ubicacion sospechosa no autorizada.", "mitigacion", "si", 1.5, None, 2, 2, 1, 2),
        ]

        incidentes = []
        for i, (nombre, desc, estado, osri, t_att, t_sol, n_rep, n_serv, n_area, n_sub) in enumerate(incidentes_spec):
            year, month = meses[i % 6]
            fecha = _random_date_in_month(year, month)

            inc = Incidente.objects.create(
                nombre_incidente=nombre, descripcion=desc,
                estado_solucion=estado, notificado_osri=osri,
            )
            _set_auto_now(Incidente, inc, "fecha_hora", fecha)

            if t_att is not None:
                fecha_atencion = fecha + timedelta(hours=t_att)
                updates = {"fecha_atencion": fecha_atencion}
                if t_sol is not None:
                    updates["fecha_solucion"] = fecha + timedelta(hours=t_sol)
                Incidente.objects.filter(pk=inc.pk).update(**updates)
                inc.refresh_from_db()

            inc.reportes.set(random.sample(reportes, min(n_rep, len(reportes))))
            inc.servicios.set(random.sample(servicios[:12], min(n_serv, len(servicios[:12]))))
            inc.areas.set(random.sample(areas, min(n_area, len(areas))))
            inc.subcategorias.set(random.sample(subcategorias, min(n_sub, len(subcategorias))))
            incidentes.append(inc)

        # ── Involucrados ──────────────────────────────────────────────
        self.stdout.write("Creando involucrados...")
        invol_data = [
            ("Jose", "Perez Martinez", "jpmartinez", "192.168.12.150", "00:1A:2B:3C:4D:01", "interno"),
            ("Maria", "Gonzalez Luis", "mgonzalez", "192.168.12.151", "00:1A:2B:3C:4D:02", "interno"),
            ("Carlos", "Fernandez Rojas", "cfernandez", "192.168.12.152", "00:1A:2B:3C:4D:03", "interno"),
            ("Laura", "Martinez Soto", "lmartinez", "192.168.12.153", "00:1A:2B:3C:4D:04", "interno"),
            ("Pedro", "Lopez Hernandez", "plopez", "192.168.12.154", "00:1A:2B:3C:4D:05", "interno"),
            ("Sandra", "Torres Vega", "", "10.0.0.50", "", "externo"),
            ("Ricardo", "Morales Diaz", "rmorales", "192.168.12.155", "00:1A:2B:3C:4D:06", "interno"),
            ("Attacker", "Unknown", "", "45.33.32.100", "", "externo"),
            ("Desconocido", "USB Owner", "", "", "", "desconocido"),
            ("Felipe", "Castro Reyes", "fcastro", "192.168.12.156", "00:1A:2B:3C:4D:07", "interno"),
        ]
        involucrados = []
        for nom, ape, usr, ip, mac, tipo in invol_data:
            inv = Involucrado.objects.create(
                nombres=nom, apellidos=ape, usuario=usr, ip=ip or None, mac=mac, tipo=tipo,
            )
            involucrados.append(inv)

        # ── InvolucradoIncidente ──────────────────────────────────────
        self.stdout.write("Asociando involucrados...")
        for inc in incidentes[:20]:
            for inv in random.sample(involucrados, min(random.randint(1, 4), len(involucrados))):
                InvolucradoIncidente.objects.create(
                    incidente=inc, involucrado=inv,
                    descripcion=f"Rol: {random.choice(['Victima', 'Responsable', 'Testigo', 'Afectado'])}",
                    medida_impuesta=random.choice(medidas) if inv.tipo != "desconocido" else None,
                    fecha_inicio=inc.fecha_hora.date(),
                    fecha_fin=(inc.fecha_hora + timedelta(days=random.randint(7, 90))).date() if inc.estado_solucion == "cerrado" else None,
                )

        # ── MedidaIncidente ───────────────────────────────────────────
        self.stdout.write("Asociando medidas...")
        for inc in incidentes[:22]:
            for m in random.sample(medidas, min(random.randint(1, 4), len(medidas))):
                MedidaIncidente.objects.create(
                    incidente=inc, medida=m,
                    responsable=random.choice(responsables[:6]),
                    fecha_cumplimiento=(inc.fecha_hora + timedelta(days=random.randint(1, 30))).date(),
                    estado_cumplimiento=random.choice([True, True, False]),
                    observaciones=f"Medida aplicada para {inc.nombre_incidente.lower()}",
                )

        # ── DLP Policies ──────────────────────────────────────────────
        self.stdout.write("Creando politicas DLP...")
        policies = []
        for code, name, active, sev, mode, maxf, os_val, rt in [
            ("DLP-001", "Proteccion de datos financieros", True, "critical", "all", 25, "linux", True),
            ("DLP-002", "Proteccion de datos de clientes", True, "high", "all", 25, "linux", True),
            ("DLP-003", "Control de USB y medios removibles", True, "high", "paths", 50, "linux", False),
            ("DLP-004", "Monitoreo de correo electronico", True, "medium", "all", 25, "linux", True),
            ("DLP-005", "Deteccion de software no autorizado", True, "medium", "paths", 100, "windows", True),
            ("DLP-006", "Control de acceso a cloud storage", True, "high", "paths", 25, "linux", True),
            ("DLP-007", "Monitoreo de clipboard y copia", False, "low", "all", 10, "linux", False),
        ]:
            p = DlpPolicy.objects.create(
                code=code, name=name, is_active=active, severity=sev,
                scan_mode=mode, max_file_size_mb=maxf, target_os=os_val, realtime_enabled=rt,
                monitored_extensions=[".pdf", ".docx", ".xlsx", ".csv", ".sql", ".key"],
            )
            policies.append(p)

        # ── DLP Rules ─────────────────────────────────────────────────
        self.stdout.write("Creando reglas DLP...")
        for pi, name, pattern, mtype, classif, sev in [
            (0, "Numeros de tarjeta de credito", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-9][0-9]{14})\b", "regex", "PII-Financial", "critical"),
            (0, "Cuentas bancarias Cuba", r"\b\d{16}\b", "regex", "PII-Financial", "high"),
            (1, "Nombres y apellidos en archivos", "nombre, apellido, nombre_completo", "keyword", "PII-Identity", "high"),
            (1, "Carnet de identidad cubano", r"\b\d{11}\b", "regex", "PII-Identity", "critical"),
            (2, "Archivos CONFIDENCIAL", "CONFIDENCIAL, SECRET, CLASSIFIED", "keyword", "Classification", "high"),
            (3, "Envio masivo de correos", "attachment, archivo adjunto", "keyword", "Exfiltration-Email", "medium"),
            (4, "Software pirata", "crack, keygen, serial, activation", "keyword", "Unauthorized-Software", "medium"),
            (5, "Archivos subidos a cloud", "upload, subir, cloud, drive, mega", "keyword", "Exfiltration-Cloud", "high"),
            (6, "Copia de texto largo", "copy_paste", "keyword", "Clipboard-Exfil", "low"),
        ]:
            DlpRule.objects.create(
                policy=policies[pi], name=name, pattern=pattern,
                match_type=mtype, classification=classif, severity=sev, tags=[classif.lower()],
            )

        # ── DLP Threats (40, spread across months) ────────────────────
        self.stdout.write("Creando amenazas DLP...")
        agents = [
            ("agt-fin-001", "SV-DC-01"), ("agt-fin-002", "SV-DC-02"), ("agt-web-001", "SV-Web-01"),
            ("agt-test-001", "SV-Testing"), ("agt-rrhh-001", "PC-RRHH-01"), ("agt-fin-003", "PC-FIN-03"),
        ]
        archivos = [
            "reporte_financiero_Q4.xlsx", "nominas_empleados.csv", "contratos_clientes.pdf",
            "base_datos_clientes.sql", "credenciales_servidores.txt", "presupuesto_2026.xlsx",
            "datos_medicos_pacientes.csv", "contrasenas_root.txt", "informe_auditoria.docx",
            "lista_proveedores.xlsx", "acuerdos_comerciales.pdf", "plan_estrategico.docx",
            "registro_personal.docx", "estados_financieros.xlsx", "informe_vulnerabilidades.pdf",
            "diagrama_red_corporativa.vsdx", "scripts_administrativos.sh", "dump_base_datos.sql",
            "contrato_mantenimiento.pdf", "datos_biometricos.csv",
        ]
        channels = ["filesystem", "downloads", "desktop", "documents", "removable", "usb", "email", "cloud", "web"]
        dlp_threat_bulk = []
        for i in range(40):
            agt = random.choice(agents)
            arch = random.choice(archivos)
            actor = random.choice(["jpmartinez", "mgonzalez", "cfernandez", "lmartinez", "plopez", "rmorales", "fcastro", "unknown"])
            year, month = meses[i % 6]
            det = _random_date_in_month(year, month)
            dlp_threat_bulk.append(DlpThreat(
                fingerprint=uuid.uuid4().hex[:32],
                agent_id=agt[0], agent_hostname=agt[1],
                policy_code=random.choice(policies).code,
                rule_name=f"Regla-{random.randint(1, 9)}",
                classification=random.choice(["PII-Financial", "PII-Identity", "Classification", "Exfiltration-Email", "Exfiltration-Cloud"]),
                severity=random.choice(["critical", "high", "high", "medium", "medium", "low"]),
                status=random.choice(["open", "open", "investigating", "acknowledged", "resolved", "false_positive"]),
                file_name=arch, file_path=f"/home/{actor}/{arch}",
                file_hash=uuid.uuid4().hex[:64], file_size=random.randint(1024, 52428800),
                actor=actor, channel=random.choice(channels),
                summary=f"Archivo '{arch}' contiene datos clasificados detectados por politica DLP",
                matched_keywords=random.sample(["confidencial", "secret", "credencial", "password", "tarjeta", "cuenta"], random.randint(1, 3)),
                detected_at=det, event_published=random.random() > 0.3,
            ))
        DlpThreat.objects.bulk_create(dlp_threat_bulk)

        # ── DLP Scan Summaries ────────────────────────────────────────
        self.stdout.write("Creando escaneos DLP...")
        scan_bulk = []
        for i in range(15):
            agt = random.choice(agents)
            started = now - timedelta(hours=i * 12)
            scan_bulk.append(DlpScanSummary(
                agent_id=agt[0], agent_hostname=agt[1], started_at=started,
                finished_at=started + timedelta(minutes=random.randint(2, 30)),
                files_scanned=random.randint(1000, 50000), files_flagged=random.randint(0, 20),
                incidents_created=random.randint(0, 5), duration_seconds=random.randint(120, 1800),
                status=random.choice(["completed", "completed", "completed", "timeout"]),
            ))
        DlpScanSummary.objects.bulk_create(scan_bulk)

        # ── Summary ───────────────────────────────────────────────────
        est_counts = {}
        for inc in Incidente.objects.all():
            est_counts[inc.estado_solucion] = est_counts.get(inc.estado_solucion, 0) + 1

        rep_counts = {}
        for rep in Reporte.objects.all():
            rep_counts[rep.estado_solucion] = rep_counts.get(rep.estado_solucion, 0) + 1

        month_counts = {}
        for inc in Incidente.objects.all():
            key = inc.fecha_hora.strftime("%b %Y")
            month_counts[key] = month_counts.get(key, 0) + 1

        self.stdout.write(self.style.SUCCESS(
            f"\n=== DATOS CREADOS ===\n"
            f"  Responsables: {len(responsables)}\n"
            f"  Categorias: {len(categorias)}, Subcategorias: {len(subcategorias)}\n"
            f"  Areas: {len(areas)}\n"
            f"  Medidas: {len(medidas)}\n"
            f"  Reportes: {len(reportes)} ({rep_counts})\n"
            f"  Servicios: {len(servicios)}\n"
            f"  Incidentes: {len(incidentes)} ({est_counts})\n"
            f"  Por mes: {month_counts}\n"
            f"  Involucrados: {len(involucrados)}\n"
            f"  Politicas DLP: {len(policies)}\n"
            f"  Amenazas DLP: {DlpThreat.objects.count()}\n"
            f"  Monitoreo: {MonitoreoServicio.objects.count()}\n"
            f"  Conexiones: {ConexionTopologica.objects.count()}\n"
            f"  Puertos: {PuertoDispositivo.objects.count()}"
        ))
