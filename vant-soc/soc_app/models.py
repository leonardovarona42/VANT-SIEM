import uuid
from django.db import models


# ============================================================================
#  DLP MODELS
# ============================================================================

SEVERITY_CHOICES = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
]

DLP_STATUS_CHOICES = [
    ("open", "Open"),
    ("investigating", "Investigating"),
    ("acknowledged", "Acknowledged"),
    ("resolved", "Resolved"),
    ("false_positive", "False Positive"),
]

MATCH_TYPE_CHOICES = [
    ("keyword", "Keyword"),
    ("regex", "Regular Expression"),
    ("metadata", "Metadata"),
]

TARGET_OS_CHOICES = [
    ("linux", "Linux"),
    ("windows", "Windows"),
]

SCAN_MODE_CHOICES = [
    ("all", "Todo el almacenamiento"),
    ("paths", "Rutas especificas"),
]

CHANNEL_CHOICES = [
    ("filesystem", "Filesystem"),
    ("downloads", "Downloads"),
    ("desktop", "Desktop"),
    ("documents", "Documents"),
    ("removable", "Removable Media"),
    ("network", "Network Share"),
    ("email", "Email"),
    ("clipboard", "Clipboard"),
    ("usb", "USB"),
    ("cloud", "Cloud Storage"),
    ("web", "Web Upload"),
]


class DlpPolicy(models.Model):
    code = models.SlugField(max_length=64, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    is_active = models.BooleanField(default=True, db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="high")
    scan_mode = models.CharField(max_length=16, choices=SCAN_MODE_CHOICES, default="all")
    scan_paths = models.JSONField(default=list, blank=True)
    monitored_extensions = models.JSONField(default=list, blank=True)
    max_file_size_mb = models.IntegerField(default=25)
    max_scan_seconds = models.IntegerField(default=0)
    target_os = models.CharField(max_length=32, choices=TARGET_OS_CHOICES, default="linux")
    realtime_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "soc_policies"
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.code}: {self.name}"


class DlpRule(models.Model):
    policy = models.ForeignKey(DlpPolicy, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=255)
    pattern = models.TextField()
    match_type = models.CharField(max_length=16, choices=MATCH_TYPE_CHOICES, default="keyword")
    classification = models.CharField(max_length=64, blank=True, default="")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="high")
    tags = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "soc_rules"
        ordering = ["policy", "name"]
        indexes = [
            models.Index(fields=["policy", "is_active"]),
        ]

    def __str__(self):
        return f"{self.policy.code}/{self.name}"


class DlpThreat(models.Model):
    fingerprint = models.CharField(max_length=128, unique=True, db_index=True)
    agent_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    agent_hostname = models.CharField(max_length=255, blank=True, default="")
    policy_code = models.SlugField(max_length=64, blank=True, default="", db_index=True)
    rule_name = models.CharField(max_length=255, blank=True, default="")
    classification = models.CharField(max_length=64, blank=True, default="", db_index=True)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default="high", db_index=True)
    status = models.CharField(max_length=24, choices=DLP_STATUS_CHOICES, default="open", db_index=True)
    file_name = models.CharField(max_length=512, blank=True, default="")
    file_path = models.TextField(blank=True, default="")
    file_hash = models.CharField(max_length=128, blank=True, default="")
    file_size = models.BigIntegerField(default=0)
    actor = models.CharField(max_length=255, blank=True, default="")
    channel = models.CharField(max_length=32, choices=CHANNEL_CHOICES, default="filesystem")
    summary = models.TextField(blank=True, default="")
    matched_keywords = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    event_published = models.BooleanField(default=False)
    evidence_file = models.FileField(upload_to="soc/evidence/%Y/%m/%d/", blank=True, null=True, max_length=512)
    detected_at = models.DateTimeField(db_index=True)
    acknowledged_at = models.DateTimeField(blank=True, null=True)
    acknowledged_by = models.CharField(max_length=255, blank=True, default="")
    resolved_at = models.DateTimeField(blank=True, null=True)
    resolved_by = models.CharField(max_length=255, blank=True, default="")
    resolution_notes = models.TextField(blank=True, default="")
    reporte = models.ForeignKey("Reporte", on_delete=models.SET_NULL, null=True, blank=True, related_name="dlp_threats")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "soc_threats"
        ordering = ["-detected_at"]
        indexes = [
            models.Index(fields=["severity", "status"]),
            models.Index(fields=["classification", "status"]),
            models.Index(fields=["agent_id", "detected_at"]),
        ]

    def __str__(self):
        return f"[{self.severity}] {self.file_name} via {self.channel}"


class DlpScanSummary(models.Model):
    agent_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    agent_hostname = models.CharField(max_length=255, blank=True, default="")
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(blank=True, null=True)
    files_scanned = models.IntegerField(default=0)
    files_flagged = models.IntegerField(default=0)
    incidents_created = models.IntegerField(default=0)
    duration_seconds = models.FloatField(blank=True, null=True)
    status = models.CharField(max_length=16, default="completed", choices=[
        ("running", "Running"),
        ("completed", "Completed"),
        ("timeout", "Timeout"),
        ("error", "Error"),
    ])
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "soc_scan_summaries"
        ordering = ["-started_at"]

    def __str__(self):
        return f"Agent {self.agent_id} scan {self.started_at} ({self.status})"


# ============================================================================
#  BITACORA DE INCIDENTES
# ============================================================================

class Categoria(models.Model):
    nombre = models.CharField(max_length=200, unique=True)
    descripcion = models.TextField(blank=True, default="")

    class Meta:
        db_table = "soc_categorias"
        ordering = ["nombre"]
        verbose_name_plural = "categorias"

    def __str__(self):
        return self.nombre


class Subcategoria(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField(blank=True, default="")
    nivel_peligrosidad = models.IntegerField(default=5, help_text="1-10")
    categoria = models.ForeignKey(Categoria, on_delete=models.CASCADE, related_name="subcategorias")

    class Meta:
        db_table = "soc_subcategorias"
        ordering = ["categoria", "nombre"]
        unique_together = ["categoria", "nombre"]

    def __str__(self):
        return f"{self.categoria.nombre} > {self.nombre} (peligro: {self.nivel_peligrosidad})"


class Responsable(models.Model):
    TIPO_CHOICES = [
        ("cuadro", "Cuadro Centro"),
        ("rsi", "RSI"),
        ("admin", "Administrador"),
        ("sistema", "Sistema Automatico"),
    ]
    nombres = models.CharField(max_length=200)
    apellidos = models.CharField(max_length=200)
    email = models.EmailField(blank=True, default="")
    telefono_particular = models.CharField(max_length=30, blank=True, default="")
    telefono_corp = models.CharField(max_length=30, blank=True, default="")
    tipo = models.CharField(max_length=20, choices=TIPO_CHOICES, default="rsi")
    descripcion = models.TextField(blank=True, default="")

    class Meta:
        db_table = "soc_responsables"
        ordering = ["apellidos", "nombres"]

    def __str__(self):
        return f"{self.nombres} {self.apellidos} ({self.get_tipo_display()})"


class Area(models.Model):
    nombre = models.CharField(max_length=200)
    acronimo = models.CharField(max_length=10)
    cuadro_centro = models.ForeignKey(Responsable, on_delete=models.SET_NULL, null=True, blank=True, related_name="areas_cuadro")
    rsi = models.ForeignKey(Responsable, on_delete=models.SET_NULL, null=True, blank=True, related_name="areas_rsi")
    admin = models.ForeignKey(Responsable, on_delete=models.SET_NULL, null=True, blank=True, related_name="areas_admin")

    class Meta:
        db_table = "soc_areas"
        ordering = ["nombre"]

    def __str__(self):
        return f"{self.acronimo} - {self.nombre}"


class Medida(models.Model):
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField(blank=True, default="")

    class Meta:
        db_table = "soc_medidas"
        ordering = ["nombre"]

    def __str__(self):
        return self.nombre


class Reporte(models.Model):
    ESTADO_CHOICES = [
        ("nuevo", "Nuevo"),
        ("atendido", "Atendido"),
        ("rechazado", "Rechazado"),
    ]
    nombre_informante = models.CharField(max_length=255)
    email_informante = models.EmailField(blank=True, default="")
    area = models.ForeignKey(Area, on_delete=models.SET_NULL, null=True, blank=True, related_name="reportes")
    descripcion = models.TextField()
    fecha_hora = models.DateTimeField(auto_now_add=True)
    fecha_atencion = models.DateTimeField(blank=True, null=True)
    fecha_solucion = models.DateTimeField(blank=True, null=True)
    estado_solucion = models.CharField(max_length=20, choices=ESTADO_CHOICES, default="nuevo")

    class Meta:
        db_table = "soc_reportes"
        ordering = ["-fecha_hora"]

    def __str__(self):
        return f"Reporte #{self.pk} - {self.nombre_informante} ({self.estado_solucion})"

    def tiempo_atencion_horas(self):
        if self.fecha_atencion and self.fecha_hora:
            return (self.fecha_atencion - self.fecha_hora).total_seconds() / 3600
        return None

    def tiempo_solucion_horas(self):
        if self.fecha_solucion and self.fecha_hora:
            return (self.fecha_solucion - self.fecha_hora).total_seconds() / 3600
        return None


class Incidente(models.Model):
    ESTADO_CHOICES = [
        ("nuevo", "Nuevo"),
        ("abierto", "Abierto"),
        ("investigacion", "Investigacion"),
        ("mitigacion", "Mitigacion"),
        ("cerrado", "Cerrado"),
    ]
    codigo_incidente = models.CharField(max_length=8, unique=True, editable=False)
    nombre_incidente = models.CharField(max_length=255)
    descripcion = models.TextField()
    fecha_hora = models.DateTimeField(auto_now_add=True)
    fecha_atencion = models.DateTimeField(blank=True, null=True)
    fecha_solucion = models.DateTimeField(blank=True, null=True)
    estado_solucion = models.CharField(max_length=20, choices=ESTADO_CHOICES, default="nuevo")
    notificado_osri = models.CharField(max_length=2, choices=[("si", "Si"), ("no", "No")], default="no")
    evidencia = models.FileField(upload_to="soc/evidencias/%Y/%m/%d/", blank=True, null=True, max_length=512)

    reportes = models.ManyToManyField(Reporte, blank=True, related_name="incidentes")
    servicios = models.ManyToManyField("Servicio", blank=True, related_name="incidentes")
    areas = models.ManyToManyField(Area, blank=True, related_name="incidentes")
    subcategorias = models.ManyToManyField(Subcategoria, blank=True, related_name="incidentes")

    class Meta:
        db_table = "soc_incidentes"
        ordering = ["-fecha_hora"]

    def __str__(self):
        return f"[{self.codigo_incidente}] {self.nombre_incidente} ({self.get_estado_solucion_display()})"

    def save(self, *args, **kwargs):
        if not self.codigo_incidente:
            self.codigo_incidente = uuid.uuid4().hex[:8].upper()
        super().save(*args, **kwargs)

    def tiempo_atencion_horas(self):
        if self.fecha_atencion and self.fecha_hora:
            return (self.fecha_atencion - self.fecha_hora).total_seconds() / 3600
        return None

    def tiempo_solucion_horas(self):
        if self.fecha_solucion and self.fecha_hora:
            return (self.fecha_solucion - self.fecha_hora).total_seconds() / 3600
        return None


class MedidaIncidente(models.Model):
    incidente = models.ForeignKey(Incidente, on_delete=models.CASCADE, related_name="medidas")
    medida = models.ForeignKey(Medida, on_delete=models.CASCADE)
    responsable = models.ForeignKey(Responsable, on_delete=models.CASCADE)
    fecha_cumplimiento = models.DateField()
    estado_cumplimiento = models.BooleanField(default=False)
    observaciones = models.TextField(blank=True, default="")

    class Meta:
        db_table = "soc_medidas_incidente"
        ordering = ["-fecha_cumplimiento"]

    def __str__(self):
        return f"{self.incidente.codigo_incidente} - {self.medida.nombre}"


class Involucrado(models.Model):
    TIPO_CHOICES = [
        ("interno", "Interno"),
        ("externo", "Externo"),
        ("desconocido", "Desconocido"),
    ]
    nombres = models.CharField(max_length=200)
    apellidos = models.CharField(max_length=200, blank=True, default="")
    usuario = models.CharField(max_length=255, blank=True, default="")
    ip = models.GenericIPAddressField(blank=True, null=True)
    mac = models.CharField(max_length=17, blank=True, default="")
    tipo = models.CharField(max_length=20, choices=TIPO_CHOICES, default="interno")

    class Meta:
        db_table = "soc_involucrados"
        ordering = ["apellidos", "nombres"]

    def __str__(self):
        return f"{self.nombres} {self.apellidos} ({self.get_tipo_display()})"


class InvolucradoIncidente(models.Model):
    incidente = models.ForeignKey(Incidente, on_delete=models.CASCADE, related_name="involucrados")
    involucrado = models.ForeignKey(Involucrado, on_delete=models.CASCADE)
    descripcion = models.TextField(blank=True, default="")
    medida_impuesta = models.ForeignKey(Medida, on_delete=models.SET_NULL, null=True, blank=True)
    fecha_inicio = models.DateField(blank=True, null=True)
    fecha_fin = models.DateField(blank=True, null=True)

    class Meta:
        db_table = "soc_involucrado_incidente"
        unique_together = ["incidente", "involucrado"]

    def __str__(self):
        return f"{self.incidente.codigo_incidente} - {self.involucrado}"


# ============================================================================
#  INFRAESTRUCTURA / CMDB
# ============================================================================

SERVICIO_TIPO_CHOICES = [
    ("host", "Host"),
    ("switch", "Switch"),
    ("router", "Router"),
    ("firewall", "Firewall"),
    ("access_point", "Access Point"),
    ("ups", "UPS"),
    ("storage", "Storage"),
    ("vlan", "VLAN"),
    ("segmento", "Segmento"),
    ("subred", "Subred"),
    ("red", "Red"),
    ("cluster", "Cluster"),
    ("plataforma", "Plataforma"),
    ("servicio_externo", "Servicio Externo"),
]

RED_TIPO_CHOICES = [
    ("interna", "Interna"),
    ("dmz", "DMZ"),
    ("gestion", "Gestion"),
    ("usuarios", "Usuarios"),
    ("servidores", "Servidores"),
    ("vpn", "VPN"),
    ("iot", "IoT"),
    ("guest", "Guest"),
    ("backup", "Backup"),
    ("otro", "Otro"),
]

NIVEL_RED_CHOICES = [
    (0, "Core"),
    (1, "Distribucion"),
    (2, "Acceso"),
]


class Servicio(models.Model):
    nombre = models.CharField(max_length=200)
    tipo = models.CharField(max_length=30, choices=SERVICIO_TIPO_CHOICES, default="host")
    descripcion = models.TextField(blank=True, default="")

    num_puertos = models.IntegerField(blank=True, null=True)
    modelo = models.CharField(max_length=200, blank=True, default="")
    fabricante = models.CharField(max_length=200, blank=True, default="")
    numero_serie = models.CharField(max_length=200, blank=True, default="")
    firmware = models.CharField(max_length=200, blank=True, default="")

    host = models.GenericIPAddressField(blank=True, null=True)
    network = models.CharField(max_length=50, blank=True, default="")
    subnet_mask = models.CharField(max_length=50, blank=True, default="")
    gateway = models.GenericIPAddressField(blank=True, null=True)
    red_tipo = models.CharField(max_length=20, choices=RED_TIPO_CHOICES, default="interna")
    vlan_id = models.IntegerField(blank=True, null=True)
    dns_primario = models.GenericIPAddressField(blank=True, null=True)
    dns_secundario = models.GenericIPAddressField(blank=True, null=True)
    dhcp_activo = models.BooleanField(default=False)
    dhcp_rango_inicio = models.GenericIPAddressField(blank=True, null=True)
    dhcp_rango_fin = models.GenericIPAddressField(blank=True, null=True)

    url_servicio = models.URLField(blank=True, default="")
    puerto_servicio = models.IntegerField(blank=True, null=True)
    api_key = models.CharField(max_length=255, blank=True, default="")

    plataforma = models.CharField(max_length=50, blank=True, default="")

    servicio_padre = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True, related_name="hijos")
    servicios_hijos = models.ManyToManyField("self", blank=True, related_name="padres", symmetrical=False)

    monitorear = models.BooleanField(default=False)
    protocolo_monitoreo = models.CharField(max_length=10, blank=True, default="", choices=[
        ("icmp", "ICMP"), ("tcp", "TCP"), ("http", "HTTP"), ("snmp", "SNMP"), ("api", "API"),
    ])
    puerto_monitoreo = models.IntegerField(blank=True, null=True)
    intervalo_segundos = models.IntegerField(default=60)
    estado_monitoreo = models.CharField(max_length=20, blank=True, default="desconocido")

    ubicacion_fisica = models.CharField(max_length=255, blank=True, default="")
    rack = models.CharField(max_length=50, blank=True, default="")
    posicion_rack = models.CharField(max_length=50, blank=True, default="")
    edificio = models.CharField(max_length=200, blank=True, default="")
    piso = models.CharField(max_length=50, blank=True, default="")

    coordenadas_logicas_x = models.IntegerField(blank=True, null=True)
    coordenadas_logicas_y = models.IntegerField(blank=True, null=True)
    nivel_red = models.IntegerField(choices=NIVEL_RED_CHOICES, blank=True, null=True)

    responsable = models.ForeignKey(Responsable, on_delete=models.SET_NULL, null=True, blank=True, related_name="servicios")
    activo = models.BooleanField(default=True)
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    fecha_actualizacion = models.DateTimeField(auto_now=True)
    ultima_actividad = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "soc_servicios"
        ordering = ["nombre"]

    def __str__(self):
        return f"{self.nombre} ({self.get_tipo_display()})"

    def es_fisico(self):
        return self.tipo in ("host", "switch", "router", "firewall", "access_point", "ups", "storage")

    def es_logico(self):
        return self.tipo in ("vlan", "segmento", "subred", "red", "cluster", "plataforma", "servicio_externo")


class ServicioIP(models.Model):
    servicio = models.ForeignKey(Servicio, on_delete=models.SET_NULL, null=True, blank=True, related_name="ips")
    ip_address = models.GenericIPAddressField()
    hostname = models.CharField(max_length=255, blank=True, default="")
    mac_address = models.CharField(max_length=17, blank=True, default="")
    monitorear = models.BooleanField(default=True)
    estado = models.CharField(max_length=20, default="activo", choices=[
        ("activo", "Activo"), ("inactivo", "Inactivo"), ("reservado", "Reservado"), ("monitoreo", "Monitoreo"),
    ])
    descripcion = models.CharField(max_length=255, blank=True, default="")
    fecha_asignacion = models.DateTimeField(auto_now_add=True)
    ultima_actividad = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "soc_servicio_ips"
        unique_together = ["servicio", "ip_address"]

    def __str__(self):
        return f"{self.ip_address} ({self.hostname or 'sin hostname'})"


class PuertoDispositivo(models.Model):
    dispositivo = models.ForeignKey(Servicio, on_delete=models.CASCADE, related_name="puertos")
    numero_puerto = models.IntegerField()
    etiqueta = models.CharField(max_length=50, blank=True, default="")
    descripcion = models.CharField(max_length=255, blank=True, default="")
    vlan_asignada = models.IntegerField(blank=True, null=True)
    velocidad = models.CharField(max_length=10, blank=True, default="", choices=[
        ("10m", "10 Mbps"), ("100m", "100 Mbps"), ("1g", "1 Gbps"),
        ("10g", "10 Gbps"), ("40g", "40 Gbps"), ("100g", "100 Gbps"),
    ])
    conectado_a_puerto = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True)
    estado = models.CharField(max_length=20, default="activo", choices=[
        ("activo", "Activo"), ("inactivo", "Inactivo"), ("reservado", "Reservado"), ("error", "Error"),
    ])
    duplex = models.CharField(max_length=10, default="auto", choices=[
        ("full", "Full Duplex"), ("half", "Half Duplex"), ("auto", "Auto"),
    ])

    class Meta:
        db_table = "soc_puertos"
        unique_together = ["dispositivo", "numero_puerto"]

    def __str__(self):
        return f"{self.dispositivo.nombre} :{self.numero_puerto} ({self.etiqueta or self.estado})"


class ConexionTopologica(models.Model):
    origen = models.ForeignKey(Servicio, on_delete=models.CASCADE, related_name="conexiones_salida")
    destino = models.ForeignKey(Servicio, on_delete=models.CASCADE, related_name="conexiones_entrada")
    tipo = models.CharField(max_length=20, default="fisica", choices=[
        ("fisica", "Fisica"), ("logica", "Logica"), ("wireless", "Wireless"),
        ("vpn", "VPN"), ("virtual", "Virtual"),
    ])
    medio = models.CharField(max_length=20, blank=True, default="", choices=[
        ("fibra", "Fibra"), ("cobre", "Cobre"), ("wireless", "Wireless"),
        ("virtual", "Virtual"), ("otro", "Otro"),
    ])
    ancho_banda = models.CharField(max_length=50, blank=True, default="")
    puerto_origen = models.ForeignKey(PuertoDispositivo, on_delete=models.SET_NULL, null=True, blank=True, related_name="conexiones_desde")
    puerto_destino = models.ForeignKey(PuertoDispositivo, on_delete=models.SET_NULL, null=True, blank=True, related_name="conexiones_hasta")
    descripcion = models.TextField(blank=True, default="")
    activa = models.BooleanField(default=True)

    class Meta:
        db_table = "soc_conexiones_topologicas"
        unique_together = ["origen", "destino", "tipo"]

    def __str__(self):
        return f"{self.origen.nombre} --({self.tipo})--> {self.destino.nombre}"


class MonitoreoServicio(models.Model):
    servicio = models.ForeignKey(Servicio, on_delete=models.CASCADE, related_name="monitoreo")
    timestamp = models.DateTimeField(auto_now_add=True)
    latencia = models.FloatField(default=0, help_text="milisegundos")
    estado = models.BooleanField(default=True, help_text="True = up")
    error = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "soc_monitoreo_servicios"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["servicio", "-timestamp"]),
        ]

    def __str__(self):
        estado = "UP" if self.estado else "DOWN"
        return f"{self.servicio.nombre} @ {self.timestamp} = {estado} ({self.latencia}ms)"


class ConfiguracionMonitoreo(models.Model):
    intervalo_segundos = models.IntegerField(default=60)
    activo = models.BooleanField(default=False)
    ultima_ejecucion = models.DateTimeField(blank=True, null=True)

    class Meta:
        db_table = "soc_config_monitoreo"

    def __str__(self):
        return f"Monitoreo: {'activo' if self.activo else 'inactivo'} (cada {self.intervalo_segundos}s)"
