from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid
from datetime import datetime

# Create your models here.
class Categoria(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()

    def __str__(self):
        return self.nombre

class Subcategoria(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()
    nivel_peligrosidad = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(10)])
    categoria = models.ForeignKey(Categoria, on_delete=models.CASCADE)

    def __str__(self):
        return self.nombre

class Servicio(models.Model):
    TIPO_CHOICES = [
        ('host', 'Host/Servidor'),
        ('switch', 'Switch'),
        ('router', 'Router'),
        ('firewall', 'Firewall'),
        ('access_point', 'Access Point'),
        ('ups', 'UPS'),
        ('storage', 'Storage/NAS'),
        ('vlan', 'VLAN'),
        ('segmento', 'Segmento de Red'),
        ('subred', 'Subred'),
        ('red', 'Red'),
        ('cluster', 'Cluster Virtualización'),
        ('plataforma', 'Plataforma'),
        ('servicio_externo', 'Servicio Externo/SaaS'),
    ]
    PLATAFORMA_CHOICES = [
        ('proxmox', 'Proxmox VE'),
        ('vmware', 'VMware ESXi'),
        ('hyper_v', 'Microsoft Hyper-V'),
        ('kubernetes', 'Kubernetes'),
        ('docker', 'Docker'),
        ('otro', 'Otro'),
    ]
    RED_TIPO_CHOICES = [
        ('interna', 'Red Interna'),
        ('dmz', 'DMZ'),
        ('gestion', 'Gestion'),
        ('usuarios', 'Usuarios'),
        ('servidores', 'Servidores'),
        ('vpn', 'VPN'),
        ('iot', 'IoT'),
        ('guest', 'Guest/Visitantes'),
        ('backup', 'Backup/Storage'),
        ('otro', 'Otro'),
    ]
    PUERTOS_CHOICES = [
        (4, '4 puertos'), (8, '8 puertos'), (10, '10 puertos'),
        (16, '16 puertos'), (24, '24 puertos'), (28, '28 puertos'),
        (48, '48 puertos'), (56, '56 puertos'),
    ]

    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()
    tipo = models.CharField(max_length=30, choices=TIPO_CHOICES, default='host')
    
    # ==================== CAMPOS FISICOS (switch, router, firewall, etc.) ====================
    num_puertos = models.IntegerField(choices=PUERTOS_CHOICES, blank=True, null=True)
    modelo = models.CharField(max_length=100, blank=True, null=True)
    fabricante = models.CharField(max_length=100, blank=True, null=True)
    numero_serie = models.CharField(max_length=100, blank=True, null=True)
    firmware = models.CharField(max_length=50, blank=True, null=True)
    
    # ==================== CAMPOS LOGICOS DE RED (subred, red, vlan, segmento) ====================
    network = models.GenericIPAddressField(blank=True, null=True, help_text="Direccion de red (ej: 10.10.0.0)")
    subnet_mask = models.CharField(max_length=18, blank=True, null=True, help_text="Mascara CIDR (ej: /24 o 255.255.255.0)")
    gateway = models.GenericIPAddressField(blank=True, null=True, help_text="Gateway de la subred")
    red_tipo = models.CharField(max_length=20, choices=RED_TIPO_CHOICES, blank=True, null=True, help_text="Tipo de red (solo para subred/segmento/red)")
    vlan_id = models.IntegerField(blank=True, null=True, validators=[MinValueValidator(1), MaxValueValidator(4094)], help_text="Tag VLAN (1-4094)")
    dns_primario = models.GenericIPAddressField(blank=True, null=True)
    dns_secundario = models.GenericIPAddressField(blank=True, null=True)
    dhcp_activo = models.BooleanField(default=False, blank=True, help_text="DHCP habilitado")
    dhcp_rango_inicio = models.GenericIPAddressField(blank=True, null=True)
    dhcp_rango_fin = models.GenericIPAddressField(blank=True, null=True)
    
    # ==================== CAMPOS COMUNES ====================
    host = models.GenericIPAddressField(blank=True, null=True, help_text="IP principal del servicio")
    
    # Servicios externos
    url_servicio = models.URLField(blank=True, null=True, help_text="URL del servicio externo")
    puerto_servicio = models.IntegerField(blank=True, null=True, validators=[MinValueValidator(1), MaxValueValidator(65535)], help_text="Puerto del servicio")
    api_key = models.CharField(max_length=500, blank=True, null=True, help_text="API Key si aplica")
    
    # Cluster/Virtualizacion
    plataforma = models.CharField(max_length=30, choices=PLATAFORMA_CHOICES, blank=True, null=True, help_text="Plataforma de virtualizacion")
    
    # Jerarquia
    servicio_padre = models.ForeignKey('self', on_delete=models.SET_NULL, related_name='subservicios', blank=True, null=True, help_text="Servicio padre (cluster, segmento)")
    servicios_hijos = models.ManyToManyField('self', symmetrical=False, related_name='servicios_padres', blank=True)
    
    # Monitoreo
    monitorear = models.BooleanField(default=False, blank=True, help_text="Activar monitoreo de este servicio")
    protocolo_monitoreo = models.CharField(max_length=20, choices=[('icmp', 'Ping ICMP'), ('tcp', 'TCP Port'), ('http', 'HTTP/HTTPS'), ('snmp', 'SNMP'), ('api', 'API Check')], default='icmp', help_text="Protocolo de monitoreo")
    puerto_monitoreo = models.IntegerField(default=80, help_text="Puerto para monitoreo TCP/HTTP")
    intervalo_segundos = models.IntegerField(default=60, blank=True, help_text="Intervalo de monitoreo")
    estado_monitoreo = models.BooleanField(default=True, help_text="Estado actual del monitoreo")
    
    # Topologia Fisica
    ubicacion_fisica = models.CharField(max_length=200, blank=True, null=True, help_text="Rack, posicion, ubicacion fisica")
    rack = models.CharField(max_length=50, blank=True, null=True)
    posicion_rack = models.IntegerField(blank=True, null=True, help_text="U en el rack")
    edificio = models.CharField(max_length=100, blank=True, null=True)
    piso = models.CharField(max_length=50, blank=True, null=True)
    coordenadas_x = models.IntegerField(default=0, help_text="Posicion X para topologia fisica")
    coordenadas_y = models.IntegerField(default=0, help_text="Posicion Y para topologia fisica")
    
    # Topologia Logica
    coordenadas_logicas_x = models.IntegerField(default=0, help_text="Posicion X para topologia logica")
    coordenadas_logicas_y = models.IntegerField(default=0, help_text="Posicion Y para topologia logica")
    nivel_red = models.IntegerField(default=0, help_text="Nivel en la jerarquia de red (0=core, 1=distribucion, 2=acceso)")
    
    # Metadata
    responsable = models.ForeignKey('Responsable', on_delete=models.SET_NULL, blank=True, null=True)
    fecha_creacion = models.DateTimeField(auto_now_add=True, null=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True, null=True)
    activo = models.BooleanField(default=True, blank=True, help_text="Si el servicio esta activo o dado de baja")
    ultima_actividad = models.DateTimeField(blank=True, null=True, help_text="Ultima vez detectado activo por monitoreo")

    class Meta:
        ordering = ['nombre']
        indexes = [
            models.Index(fields=['tipo']),
            models.Index(fields=['activo']),
            models.Index(fields=['monitorear']),
        ]

    def __str__(self):
        tipo_display = dict(self.TIPO_CHOICES).get(self.tipo, self.tipo)
        red_info = f" ({self.network}{self.subnet_mask})" if self.network else ""
        return f"{self.nombre} ({tipo_display}){red_info}"

    def es_fisico(self):
        return self.tipo in ['host', 'switch', 'router', 'firewall', 'access_point', 'ups', 'storage']

    def es_logico(self):
        return self.tipo in ['vlan', 'segmento', 'subred', 'red', 'cluster', 'plataforma', 'servicio_externo']

    def es_red(self):
        return self.tipo in ['subred', 'red', 'segmento', 'vlan']

    def total_ips(self):
        if self.es_red():
            if self.subnet_mask:
                prefijo = self.subnet_mask.replace('/', '')
                try:
                    return 2 ** (32 - int(prefijo))
                except:
                    pass
            return self.ips.count()
        return 1 if self.host else 0

    def total_dispositivos_activos(self):
        return self.ips.filter(estado='activo').count()

    def total_puertos(self):
        if self.tipo in ['switch', 'router', 'firewall']:
            return self.puertos.count()
        return self.num_puertos or 0

    def puertos_disponibles(self):
        if self.tipo in ['switch', 'router', 'firewall']:
            total = self.num_puertos or 0
            return total - self.puertos.filter(conectado_a_puerto__isnull=False).count()
        return 0


class ServicioIP(models.Model):
    ESTADO_CHOICES = [
        ('activo', 'Activo'),
        ('inactivo', 'Inactivo'),
        ('reservado', 'Reservado'),
        ('monitoreo', 'Solo Monitoreo'),
    ]
    servicio = models.ForeignKey(Servicio, related_name='ips', on_delete=models.SET_NULL, blank=True, null=True)
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=100, blank=True, null=True)
    mac_address = models.CharField(max_length=17, blank=True, null=True, help_text="Direccion MAC")
    monitorear = models.BooleanField(default=False, help_text="Monitorear esta IP especifica")
    estado = models.CharField(max_length=20, choices=ESTADO_CHOICES, default='activo')
    descripcion = models.CharField(max_length=200, blank=True, null=True)
    fecha_asignacion = models.DateTimeField(auto_now_add=True)
    ultima_actividad = models.DateTimeField(blank=True, null=True, help_text="Ultima vez que estuvo activo/visible")

    class Meta:
        ordering = ['ip_address']
        unique_together = ['servicio', 'ip_address']

    def __str__(self):
        return f"{self.ip_address} - {self.hostname or 'Sin hostname'}"


class PuertoDispositivo(models.Model):
    ESTADO_CHOICES = [
        ('activo', 'Activo'),
        ('inactivo', 'Inactivo'),
        ('reservado', 'Reservado'),
        ('error', 'Error'),
    ]
    VELOCIDAD_CHOICES = [
        ('10m', '10 Mbps'),
        ('100m', '100 Mbps'),
        ('1g', '1 Gbps'),
        ('10g', '10 Gbps'),
        ('40g', '40 Gbps'),
        ('100g', '100 Gbps'),
    ]
    dispositivo = models.ForeignKey(Servicio, related_name='puertos', on_delete=models.CASCADE)
    numero_puerto = models.IntegerField(help_text="Numero de puerto fisico")
    etiqueta = models.CharField(max_length=50, blank=True, null=True, help_text="Etiqueta del puerto (ej: Gi0/1)")
    descripcion = models.CharField(max_length=200, blank=True, null=True)
    vlan_asignada = models.IntegerField(blank=True, null=True, validators=[MinValueValidator(1), MaxValueValidator(4094)])
    velocidad = models.CharField(max_length=10, choices=VELOCIDAD_CHOICES, default='1g')
    conectado_a_puerto = models.ForeignKey('self', on_delete=models.SET_NULL, related_name='conectado_desde', blank=True, null=True, help_text="Puerto remoto conectado")
    estado = models.CharField(max_length=20, choices=ESTADO_CHOICES, default='activo')
    duplex = models.CharField(max_length=10, choices=[('full', 'Full Duplex'), ('half', 'Half Duplex'), ('auto', 'Auto')], default='auto')

    class Meta:
        ordering = ['dispositivo', 'numero_puerto']
        unique_together = ['dispositivo', 'numero_puerto']

    def __str__(self):
        return f"{self.dispositivo.nombre} - Puerto {self.numero_puerto} ({self.etiqueta or 'Sin etiqueta'})"

    def dispositivo_remoto(self):
        if self.conectado_a_puerto:
            return self.conectado_a_puerto.dispositivo
        return None


class ConexionTopologica(models.Model):
    TIPO_CHOICES = [
        ('fisica', 'Conexion Fisica'),
        ('logica', 'Conexion Logica'),
        ('wireless', 'Conexion Inalambrica'),
        ('vpn', 'VPN/Tunel'),
        ('virtual', 'Virtual (VM/Container)'),
    ]
    MEDIO_CHOICES = [
        ('fibra', 'Fibra Optica'),
        ('cobre', 'Cobre (Ethernet)'),
        ('wireless', 'Inalambrico'),
        ('virtual', 'Virtual'),
        ('otro', 'Otro'),
    ]
    origen = models.ForeignKey(Servicio, related_name='conexiones_salida', on_delete=models.CASCADE)
    destino = models.ForeignKey(Servicio, related_name='conexiones_entrada', on_delete=models.CASCADE)
    tipo = models.CharField(max_length=20, choices=TIPO_CHOICES, default='fisica')
    medio = models.CharField(max_length=20, choices=MEDIO_CHOICES, blank=True, null=True)
    ancho_banda = models.CharField(max_length=20, blank=True, null=True, help_text="Ej: 1Gbps, 10Gbps")
    puerto_origen = models.ForeignKey(PuertoDispositivo, on_delete=models.SET_NULL, related_name='conexion_origen', blank=True, null=True)
    puerto_destino = models.ForeignKey(PuertoDispositivo, on_delete=models.SET_NULL, related_name='conexion_destino', blank=True, null=True)
    descripcion = models.TextField(blank=True, null=True)
    activa = models.BooleanField(default=True)

    class Meta:
        ordering = ['origen', 'destino']
        unique_together = ['origen', 'destino', 'tipo']

    def __str__(self):
        return f"{self.origen.nombre} -> {self.destino.nombre} ({self.tipo})"

class Responsable(models.Model):
    TIPO_CHOICES = [
        ('Cuadro Centro', 'Cuadro Centro'),
        ('RSI', 'RSI'),
        ('Admin', 'Administrador'),
    ]
    nombres = models.CharField(max_length=200)
    apellidos = models.CharField(max_length=200)
    email = models.EmailField()
    telefono_particular = models.CharField(max_length=20)
    telefono_corp = models.CharField(max_length=20)
    tipo = models.CharField(max_length=200, choices=TIPO_CHOICES, default='Cuadro Centro')
    descripcion = models.TextField()

    def __str__(self):
        return self.nombres + ' ' + self.apellidos

class Area(models.Model):
    nombre = models.CharField(max_length=200)
    acronimo = models.CharField(max_length=10)
    cuadro_centro = models.ForeignKey(Responsable, related_name='cuadro_centro', on_delete=models.CASCADE)
    rsi = models.ForeignKey(Responsable, related_name='rsi', on_delete=models.CASCADE)
    admin = models.ForeignKey(Responsable, related_name='admin', on_delete=models.CASCADE)

    def __str__(self):
        return self.nombre


class Medida(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()

    def __str__(self):
        return self.nombre

class Reporte(models.Model):
    nombre_informante = models.CharField(max_length=200)
    email_informante = models.EmailField()
    area = models.ForeignKey(Area, on_delete=models.CASCADE)
    descripcion = models.TextField()
    fecha_hora = models.DateTimeField(auto_now_add=True)
    fecha_atencion = models.DateTimeField(null=True, blank=True)
    fecha_solucion = models.DateTimeField(null=True, blank=True)
    ESTADO_SOLUCION_CHOICES = [
        ('Nuevo', 'Nuevo'),
        ('Atendido', 'Atendido'),
        ('Rechazado', 'Rechazado'),
    ]
    estado_solucion = models.CharField(
        max_length=13,
        choices=ESTADO_SOLUCION_CHOICES,
        default='Nuevo',
    )
    def __str__(self):
        return self.nombre_informante

    def tiempo_atencion_horas(self):
        if self.fecha_atencion:
            delta = self.fecha_atencion - self.fecha_hora
            return round(delta.total_seconds() / 3600, 2)
        return None

    def tiempo_solucion_horas(self):
        if self.fecha_solucion:
            delta = self.fecha_solucion - self.fecha_hora
            return round(delta.total_seconds() / 3600, 2)
        return None

class Incidente(models.Model):
    ESTADO_NUEVO = 'nuevo'
    ESTADO_ABIERTO = 'abierto'
    ESTADO_INVESTIGACION = 'investigacion'
    ESTADO_MITIGACION = 'mitigacion'
    ESTADO_CERRADO = 'cerrado'
    ESTADO_SOLUCION_CHOICES = [
        (ESTADO_NUEVO, 'Nuevo'),
        (ESTADO_ABIERTO, 'Abierto'),
        (ESTADO_INVESTIGACION, 'Investigación'),
        (ESTADO_MITIGACION, 'Mitigación'),
        (ESTADO_CERRADO, 'Cerrado'),
    ]

    NOTIFICADO_OSRI_CHOICES = [
        ('si', 'Sí'),
        ('no', 'No'),
    ]

    fecha_hora = models.DateTimeField(auto_now_add=True)
    fecha_atencion = models.DateTimeField(null=True, blank=True)
    fecha_solucion = models.DateTimeField(null=True, blank=True)
    nombre_incidente = models.CharField(max_length=200)
    codigo_incidente = models.CharField(max_length=200, unique=True, blank=True)
    descripcion = models.TextField()
    reportes = models.ManyToManyField(Reporte, related_name='incidentes')
    servicios = models.ManyToManyField(Servicio)
    areas = models.ManyToManyField(Area)
    subcategorias = models.ManyToManyField(Subcategoria)
    evidencia = models.FileField(upload_to='evidencias/', blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.codigo_incidente:
            self.codigo_incidente = str(uuid.uuid4())[:8]
            while Incidente.objects.filter(codigo_incidente=self.codigo_incidente).exists():
                self.codigo_incidente = str(uuid.uuid4())[:8]
        super().save(*args, **kwargs)

    estado_solucion = models.CharField(
        max_length=13,
        choices=ESTADO_SOLUCION_CHOICES,
        default='nuevo',
    )
    notificado_osri = models.CharField(
        max_length=2,
        choices=NOTIFICADO_OSRI_CHOICES,
        default='no',
    )

    def __str__(self):
        return self.nombre_incidente

    def tiempo_atencion_horas(self):
        if self.fecha_atencion:
            delta = self.fecha_atencion - self.fecha_hora
            return round(delta.total_seconds() / 3600, 2)
        return None

    def tiempo_solucion_horas(self):
        if self.fecha_solucion:
            delta = self.fecha_solucion - self.fecha_hora
            return round(delta.total_seconds() / 3600, 2)
        return None


class MedidaIncidente(models.Model):
    incidente = models.ForeignKey(Incidente, on_delete=models.CASCADE)
    medida = models.ForeignKey(Medida, on_delete=models.CASCADE)
    responsable = models.ForeignKey(Responsable, on_delete=models.CASCADE)
    fecha_cumplimiento = models.DateField()
    estado_cumplimiento = models.BooleanField(default=False)
    observaciones = models.TextField()

    def __str__(self):
        return str(self.incidente) + ' - ' + str(self.medida)

class Involucrado(models.Model):
    nombres = models.CharField(max_length=200)
    apellidos = models.CharField(max_length=200)
    usuario = models.CharField(max_length=200)
    ip = models.GenericIPAddressField()
    mac = models.CharField(max_length=17)
    tipo = models.CharField(max_length=200)

    def __str__(self):
        return self.nombres + ' ' + self.apellidos

class InvolucradoIncidente(models.Model):
    incidente = models.ForeignKey(Incidente, on_delete=models.CASCADE)
    involucrado = models.ForeignKey(Involucrado, on_delete=models.CASCADE)
    descripcion = models.TextField()
    medida_impuesta = models.ForeignKey(Medida, on_delete=models.CASCADE)
    fecha_inicio = models.DateField()
    fecha_fin = models.DateField()

    def __str__(self):
        return str(self.incidente) + ' - ' + str(self.involucrado)

class MonitoreoServicio(models.Model):
    servicio = models.ForeignKey(Servicio, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    latencia = models.FloatField(null=True, blank=True, help_text="Latencia en milisegundos")
    estado = models.BooleanField(default=False, help_text="True si el servicio está activo")
    error = models.TextField(blank=True, null=True, help_text="Mensaje de error si falla el ping")

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['servicio', '-timestamp']),
        ]

    def __str__(self):
        return f"{self.servicio.nombre} - {self.timestamp} - {'Activo' if self.estado else 'Inactivo'}"

class ConfiguracionMonitoreo(models.Model):
    intervalo_segundos = models.IntegerField(default=60, help_text="Intervalo de monitoreo en segundos")
    activo = models.BooleanField(default=False, help_text="Si el servicio de monitoreo está activo")
    ultima_ejecucion = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = "Configuración de Monitoreo"
        verbose_name_plural = "Configuraciones de Monitoreo"

    def __str__(self):
        return f"Monitoreo - {'Activo' if self.activo else 'Inactivo'} - {self.intervalo_segundos}s"
