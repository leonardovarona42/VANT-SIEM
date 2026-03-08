from django.db import models
from django.utils import timezone
import hashlib
import json

class IDSIngestConfig(models.Model):
    IDS_TYPE_CHOICES = [('snort', 'Snort'), ('suricata', 'Suricata')]
    ids_type = models.CharField(max_length=10, choices=IDS_TYPE_CHOICES)
    log_path = models.CharField(max_length=255)
    active = models.BooleanField(default=True)
    retention_days = models.IntegerField(default=30)
    last_run = models.DateTimeField(null=True, blank=True)
    last_position = models.BigIntegerField(default=0, help_text="Última posición leída en el archivo")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Configuración IDS/IPS"
        verbose_name_plural = "Configuraciones IDS/IPS"
    
    def __str__(self):
        return f"{self.ids_type.upper()} - {self.log_path}"

class BaseLogModel(models.Model):
    """Modelo base para logs de IDS/IPS"""
    timestamp = models.DateTimeField(db_index=True)
    severity = models.CharField(max_length=20, db_index=True)
    priority = models.IntegerField(default=0)
    src_ip = models.GenericIPAddressField(db_index=True)
    dst_ip = models.GenericIPAddressField(db_index=True)
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, db_index=True)
    message = models.TextField()
    gid = models.IntegerField(default=0)
    sid = models.IntegerField(default=0)
    rev = models.IntegerField(default=0)
    classification = models.CharField(max_length=100, null=True, blank=True)
    raw = models.TextField()
    log_hash = models.CharField(max_length=64, unique=True, db_index=True, help_text="Hash único para evitar duplicidad")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        abstract = True
        ordering = ['-timestamp']
    
    def generate_hash(self):
        """Generar hash único basado en contenido del log"""
        hash_data = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else '',
            'src_ip': str(self.src_ip),
            'dst_ip': str(self.dst_ip),
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol,
            'message': self.message,
            'sid': self.sid,
            'gid': self.gid
        }
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        if not self.log_hash:
            self.log_hash = self.generate_hash()
        super().save(*args, **kwargs)

class SnortLog(BaseLogModel):
    """Logs de Snort"""
    # Campos específicos de Snort
    ttl = models.IntegerField(null=True, blank=True, help_text="Time To Live")
    tos = models.CharField(max_length=10, null=True, blank=True, help_text="Type of Service")
    packet_id = models.IntegerField(null=True, blank=True, help_text="Packet ID")
    ip_len = models.IntegerField(null=True, blank=True, help_text="IP Header Length")
    dgm_len = models.IntegerField(null=True, blank=True, help_text="Datagram Length")
    flags = models.CharField(max_length=20, null=True, blank=True, help_text="TCP Flags")
    seq = models.CharField(max_length=20, null=True, blank=True, help_text="Sequence Number")
    ack = models.CharField(max_length=20, null=True, blank=True, help_text="Acknowledgment Number")
    win = models.CharField(max_length=20, null=True, blank=True, help_text="Window Size")
    tcp_len = models.IntegerField(null=True, blank=True, help_text="TCP Header Length")
    
    class Meta:
        verbose_name = "Log Snort"
        verbose_name_plural = "Logs Snort"
        indexes = [
            models.Index(fields=['timestamp', 'severity']),
            models.Index(fields=['src_ip', 'dst_ip']),
            models.Index(fields=['protocol', 'severity']),
            models.Index(fields=['sid', 'gid']),
        ]
    
    def __str__(self):
        return f"Snort {self.sid}:{self.gid} - {self.src_ip} -> {self.dst_ip}"

class SuricataLog(BaseLogModel):
    """Logs de Suricata"""
    
    class Meta:
        verbose_name = "Log Suricata"
        verbose_name_plural = "Logs Suricata"
        indexes = [
            models.Index(fields=['timestamp', 'severity']),
            models.Index(fields=['src_ip', 'dst_ip']),
            models.Index(fields=['protocol', 'severity']),
        ]
    
    def __str__(self):
        return f"Suricata {self.sid}:{self.gid} - {self.src_ip} -> {self.dst_ip}"

# Modelos específicos para diferentes tipos de logs de Suricata
class SuricataEveAlert(models.Model):
    """Alertas del archivo eve.json de Suricata"""
    timestamp = models.DateTimeField(db_index=True)
    event_type = models.CharField(max_length=50, db_index=True)
    src_ip = models.GenericIPAddressField(db_index=True)
    dest_ip = models.GenericIPAddressField(db_index=True)
    src_port = models.IntegerField(null=True, blank=True)
    dest_port = models.IntegerField(null=True, blank=True)
    proto = models.CharField(max_length=10, db_index=True)
    signature_id = models.IntegerField(db_index=True)
    signature_rev = models.IntegerField(default=0)
    category = models.CharField(max_length=100, null=True, blank=True)
    action = models.CharField(max_length=20, default='alert')
    severity = models.IntegerField(default=1)
    message = models.TextField()
    raw_data = models.JSONField(default=dict)
    log_hash = models.CharField(max_length=64, unique=True, db_index=True, help_text="Hash único para evitar duplicidad")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Alerta Suricata EVE"
        verbose_name_plural = "Alertas Suricata EVE"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'event_type']),
            models.Index(fields=['src_ip', 'dest_ip']),
            models.Index(fields=['signature_id', 'severity']),
        ]
    
    def generate_hash(self):
        """Generar hash único basado en contenido del log"""
        hash_data = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else '',
            'event_type': self.event_type,
            'src_ip': str(self.src_ip),
            'dest_ip': str(self.dest_ip),
            'src_port': self.src_port,
            'dest_port': self.dest_port,
            'proto': self.proto,
            'signature_id': self.signature_id,
            'message': self.message
        }
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        if not self.log_hash:
            self.log_hash = self.generate_hash()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"EVE Alert {self.signature_id} - {self.src_ip} -> {self.dest_ip}"

class SuricataFlow(models.Model):
    """Flujos de red del archivo eve.json"""
    timestamp = models.DateTimeField(db_index=True)
    src_ip = models.GenericIPAddressField(db_index=True)
    dest_ip = models.GenericIPAddressField(db_index=True)
    src_port = models.IntegerField()
    dest_port = models.IntegerField()
    proto = models.CharField(max_length=10, db_index=True)
    app_proto = models.CharField(max_length=20, null=True, blank=True)
    state = models.CharField(max_length=20, null=True, blank=True)
    pkts_toserver = models.BigIntegerField(default=0)
    pkts_toclient = models.BigIntegerField(default=0)
    bytes_toserver = models.BigIntegerField(default=0)
    bytes_toclient = models.BigIntegerField(default=0)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    age = models.IntegerField(default=0)
    raw_data = models.JSONField(default=dict)
    log_hash = models.CharField(max_length=64, unique=True, db_index=True, help_text="Hash único para evitar duplicidad")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Flujo Suricata"
        verbose_name_plural = "Flujos Suricata"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'proto']),
            models.Index(fields=['src_ip', 'dest_ip']),
            models.Index(fields=['app_proto', 'state']),
        ]
    
    def generate_hash(self):
        """Generar hash único basado en contenido del log"""
        hash_data = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else '',
            'src_ip': str(self.src_ip),
            'dest_ip': str(self.dest_ip),
            'src_port': self.src_port,
            'dest_port': self.dest_port,
            'proto': self.proto,
            'start_time': self.start_time.isoformat() if self.start_time else '',
            'end_time': self.end_time.isoformat() if self.end_time else ''
        }
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        if not self.log_hash:
            self.log_hash = self.generate_hash()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Flow {self.proto} - {self.src_ip}:{self.src_port} -> {self.dest_ip}:{self.dest_port}"

class SuricataStats(models.Model):
    """Estadísticas del archivo stats.log"""
    timestamp = models.DateTimeField(db_index=True)
    uptime = models.IntegerField(default=0)
    total_packets = models.BigIntegerField(default=0)
    total_bytes = models.BigIntegerField(default=0)
    packets_per_second = models.FloatField(default=0.0)
    bytes_per_second = models.FloatField(default=0.0)
    total_flows = models.BigIntegerField(default=0)
    total_alerts = models.BigIntegerField(default=0)
    total_drops = models.BigIntegerField(default=0)
    memory_usage = models.FloatField(default=0.0)
    cpu_usage = models.FloatField(default=0.0)
    rules_loaded = models.IntegerField(default=0)
    rules_failed = models.IntegerField(default=0)
    raw_data = models.JSONField(default=dict)
    log_hash = models.CharField(max_length=64, unique=True, db_index=True, help_text="Hash único para evitar duplicidad")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Estadística Suricata"
        verbose_name_plural = "Estadísticas Suricata"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
        ]
    
    def generate_hash(self):
        """Generar hash único basado en contenido del log"""
        hash_data = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else '',
            'uptime': self.uptime,
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'packets_per_second': self.packets_per_second,
            'bytes_per_second': self.bytes_per_second
        }
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        if not self.log_hash:
            self.log_hash = self.generate_hash()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"Stats {self.timestamp.strftime('%Y-%m-%d %H:%M')} - {self.total_packets} packets"

class SuricataSystemLog(models.Model):
    """Logs del sistema del archivo suricata.log"""
    LOG_LEVEL_CHOICES = [
        ('DEBUG', 'Debug'),
        ('INFO', 'Info'),
        ('NOTICE', 'Notice'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]
    
    timestamp = models.DateTimeField(db_index=True)
    level = models.CharField(max_length=10, choices=LOG_LEVEL_CHOICES, db_index=True)
    component = models.CharField(max_length=50, null=True, blank=True)
    message = models.TextField()
    raw_line = models.TextField()
    log_hash = models.CharField(max_length=64, unique=True, db_index=True, help_text="Hash único para evitar duplicidad")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Log Sistema Suricata"
        verbose_name_plural = "Logs Sistema Suricata"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'level']),
            models.Index(fields=['component', 'level']),
        ]
    
    def generate_hash(self):
        """Generar hash único basado en contenido del log"""
        hash_data = {
            'timestamp': self.timestamp.isoformat() if self.timestamp else '',
            'level': self.level,
            'component': self.component,
            'message': self.message,
            'raw_line': self.raw_line
        }
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def save(self, *args, **kwargs):
        if not self.log_hash:
            self.log_hash = self.generate_hash()
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.level} - {self.component}: {self.message[:50]}"

class IDSAlert(models.Model):
    """Alertas críticas de IDS/IPS"""
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]
    
    ids_type = models.CharField(max_length=10, choices=IDSIngestConfig.IDS_TYPE_CHOICES)
    log_id = models.BigIntegerField(help_text="ID del log original")
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    message = models.TextField()
    timestamp = models.DateTimeField()
    acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, blank=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Alerta IDS/IPS"
        verbose_name_plural = "Alertas IDS/IPS"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['severity', 'acknowledged']),
            models.Index(fields=['timestamp', 'severity']),
        ]
    
    def __str__(self):
        return f"{self.ids_type.upper()} Alert: {self.severity} - {self.src_ip} -> {self.dst_ip}"

class IDSStatistics(models.Model):
    """Estadísticas de IDS/IPS"""
    ids_type = models.CharField(max_length=10, choices=IDSIngestConfig.IDS_TYPE_CHOICES)
    date = models.DateField()
    total_events = models.IntegerField(default=0)
    critical_events = models.IntegerField(default=0)
    high_events = models.IntegerField(default=0)
    medium_events = models.IntegerField(default=0)
    low_events = models.IntegerField(default=0)
    unique_src_ips = models.IntegerField(default=0)
    unique_dst_ips = models.IntegerField(default=0)
    top_protocols = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = "Estadística IDS/IPS"
        verbose_name_plural = "Estadísticas IDS/IPS"
        unique_together = ['ids_type', 'date']
        ordering = ['-date']
    
    def __str__(self):
        return f"{self.ids_type.upper()} Stats - {self.date}"
