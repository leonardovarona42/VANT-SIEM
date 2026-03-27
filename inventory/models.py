from django.db import models


class AgentDevice(models.Model):
    agent_id = models.CharField(max_length=100, unique=True)
    host_name = models.CharField(max_length=200, blank=True, default="")
    host_ip = models.CharField(max_length=64, blank=True, default="")
    agent_version = models.CharField(max_length=50, blank=True, default="")
    status = models.CharField(max_length=20, default="unknown")
    last_seen = models.DateTimeField(null=True, blank=True)
    last_inventory_at = models.DateTimeField(null=True, blank=True)
    last_dlp_at = models.DateTimeField(null=True, blank=True)
    known_ips = models.JSONField(default=list, blank=True)
    latest_inventory = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Agente"
        verbose_name_plural = "Agentes"

    def __str__(self):
        return f"{self.agent_id} ({self.host_name})"


class AgentCommand(models.Model):
    COMMAND_CHOICES = [
        ("stop", "Stop"),
        ("restart", "Restart"),
        ("activate", "Activate"),
    ]
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("issued", "Issued"),
        ("done", "Done"),
        ("failed", "Failed"),
    ]
    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="commands")
    command = models.CharField(max_length=20, choices=COMMAND_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    executed_at = models.DateTimeField(null=True, blank=True)
    message = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "Comando de Agente"
        verbose_name_plural = "Comandos de Agente"

    def __str__(self):
        return f"{self.agent.agent_id} {self.command} ({self.status})"


class AgentInventorySnapshot(models.Model):
    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="inventory_snapshots")
    payload = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Inventario de Agente"
        verbose_name_plural = "Inventarios de Agente"

    def __str__(self):
        return f"{self.agent.agent_id} {self.created_at}"


class AgentTimelineEvent(models.Model):
    CATEGORY_CHOICES = [
        ("hardware", "Hardware"),
        ("software", "Software"),
        ("network", "Network"),
        ("usb", "USB"),
        ("user", "User"),
        ("system", "System"),
        ("dlp", "DLP"),
        ("file", "File"),
    ]
    SEVERITY_CHOICES = [
        ("info", "Info"),
        ("low", "Low"),
        ("medium", "Medium"),
        ("high", "High"),
        ("critical", "Critical"),
    ]

    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="timeline_events")
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default="system")
    event_type = models.CharField(max_length=100)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="info")
    actor = models.CharField(max_length=255, blank=True, default="")
    file_path = models.CharField(max_length=1024, blank=True, default="")
    file_hash = models.CharField(max_length=128, blank=True, default="")
    observed_at = models.DateTimeField()
    source_service = models.CharField(max_length=100, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Evento de linea de tiempo"
        verbose_name_plural = "Eventos de linea de tiempo"
        ordering = ["-observed_at", "-id"]

    def __str__(self):
        return f"{self.agent.agent_id} {self.category}:{self.event_type}"


class AgentHardwareComponent(models.Model):
    TYPE_CHOICES = [
        ("bios", "BIOS"),
        ("system", "System"),
        ("cpu", "CPU"),
        ("board", "Board"),
        ("memory", "Memory"),
        ("disk", "Disk"),
        ("network", "Network"),
        ("usb", "USB"),
        ("other", "Other"),
    ]

    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="hardware_components")
    component_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    fingerprint = models.CharField(max_length=255)
    name = models.CharField(max_length=255, blank=True, default="")
    vendor = models.CharField(max_length=255, blank=True, default="")
    model = models.CharField(max_length=255, blank=True, default="")
    serial_number = models.CharField(max_length=255, blank=True, default="")
    status = models.CharField(max_length=20, default="active")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Componente de hardware"
        verbose_name_plural = "Componentes de hardware"
        unique_together = ("agent", "component_type", "fingerprint")

    def __str__(self):
        return f"{self.agent.agent_id} {self.component_type} {self.name or self.model or self.fingerprint}"


class AgentSoftwareRecord(models.Model):
    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="software_records")
    fingerprint = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    version = models.CharField(max_length=100, blank=True, default="")
    publisher = models.CharField(max_length=255, blank=True, default="")
    installed_at = models.DateTimeField(null=True, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_present = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Software observado"
        verbose_name_plural = "Software observado"
        unique_together = ("agent", "fingerprint")

    def __str__(self):
        return f"{self.agent.agent_id} {self.name} {self.version}"


class AgentNetworkIdentity(models.Model):
    ADDRESS_TYPE_CHOICES = [
        ("ipv4", "IPv4"),
        ("ipv6", "IPv6"),
        ("mac", "MAC"),
    ]

    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="network_identities")
    fingerprint = models.CharField(max_length=255)
    interface_name = models.CharField(max_length=255, blank=True, default="")
    address = models.CharField(max_length=255)
    mac_address = models.CharField(max_length=64, blank=True, default="")
    address_type = models.CharField(max_length=10, choices=ADDRESS_TYPE_CHOICES, default="ipv4")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        verbose_name = "Identidad de red"
        verbose_name_plural = "Identidades de red"
        unique_together = ("agent", "fingerprint")

    def __str__(self):
        return f"{self.agent.agent_id} {self.address_type} {self.address}"


class AegisDlpPolicy(models.Model):
    name = models.CharField(max_length=150, unique=True)
    code = models.CharField(max_length=80, unique=True)
    description = models.TextField(blank=True, default="")
    enabled = models.BooleanField(default=True)
    severity = models.CharField(max_length=20, default="high")
    scan_paths = models.JSONField(default=list, blank=True)
    monitored_extensions = models.JSONField(default=list, blank=True)
    max_file_size_mb = models.PositiveIntegerField(default=10)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Politica Aegis DLP"
        verbose_name_plural = "Politicas Aegis DLP"

    def __str__(self):
        return self.name


class AegisDlpRule(models.Model):
    MATCH_TYPE_CHOICES = [
        ("keyword", "Keyword"),
        ("regex", "Regex"),
        ("metadata", "Metadata"),
    ]

    policy = models.ForeignKey(AegisDlpPolicy, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=150)
    enabled = models.BooleanField(default=True)
    classification = models.CharField(max_length=120, blank=True, default="")
    severity = models.CharField(max_length=20, default="high")
    match_type = models.CharField(max_length=20, choices=MATCH_TYPE_CHOICES, default="keyword")
    pattern = models.TextField()
    tags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Regla Aegis DLP"
        verbose_name_plural = "Reglas Aegis DLP"

    def __str__(self):
        return f"{self.policy.code}:{self.name}"


class AegisDlpIncident(models.Model):
    agent = models.ForeignKey(AgentDevice, on_delete=models.CASCADE, related_name="dlp_incidents")
    policy = models.ForeignKey(AegisDlpPolicy, on_delete=models.SET_NULL, null=True, blank=True, related_name="incidents")
    rule = models.ForeignKey(AegisDlpRule, on_delete=models.SET_NULL, null=True, blank=True, related_name="incidents")
    reporte = models.ForeignKey("EVENT_M.Reporte", on_delete=models.SET_NULL, null=True, blank=True, related_name="osic_threads")
    incidente = models.ForeignKey("EVENT_M.Incidente", on_delete=models.SET_NULL, null=True, blank=True, related_name="osic_threads")
    fingerprint = models.CharField(max_length=255, blank=True, default="")
    classification = models.CharField(max_length=120, blank=True, default="")
    severity = models.CharField(max_length=20, default="high")
    file_name = models.CharField(max_length=255, blank=True, default="")
    file_path = models.CharField(max_length=1024, blank=True, default="")
    file_hash = models.CharField(max_length=128, blank=True, default="")
    actor = models.CharField(max_length=255, blank=True, default="")
    channel = models.CharField(max_length=100, blank=True, default="")
    status = models.CharField(max_length=20, default="open")
    reported_by = models.CharField(max_length=255, blank=True, default="")
    reported_at = models.DateTimeField(null=True, blank=True)
    detected_at = models.DateTimeField()
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Incidente Aegis DLP"
        verbose_name_plural = "Incidentes Aegis DLP"
        ordering = ["-detected_at", "-id"]

    def __str__(self):
        return f"{self.agent.agent_id} {self.classification} {self.file_name}"
