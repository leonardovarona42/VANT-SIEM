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
    nombre = models.CharField(max_length=200)
    descripcion = models.TextField()
    host = models.GenericIPAddressField(blank=True, null=True, help_text="IP del servicio para monitoreo")
    monitorear = models.BooleanField(default=False, help_text="Activar monitoreo de este servicio")

    def __str__(self):
        return self.nombre

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
    ESTADO_SOLUCION_CHOICES = [
        ('Nuevo', 'Nuevo'),
        ('Atendido', 'Atendido'),
        # ('cerrado', 'Cerrado'),
        ('Rechazado', 'Rechazado'),
    ]
    estado_solucion = models.CharField(
        max_length=13,
        choices=ESTADO_SOLUCION_CHOICES,
        default='Nuevo',
    )
    def __str__(self):
        return self.nombre_informante

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
    nombre_incidente = models.CharField(max_length=200)
    codigo_incidente = models.CharField(max_length=200, unique=True, blank=True)
    descripcion = models.TextField()
    reporte = models.OneToOneField(Reporte, on_delete=models.CASCADE)
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
