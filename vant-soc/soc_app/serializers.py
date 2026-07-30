from rest_framework import serializers
from .models import (
    DlpPolicy, DlpRule, DlpThreat, DlpScanSummary,
    Categoria, Subcategoria, Responsable, Area, Medida,
    Reporte, Incidente, MedidaIncidente, MedidaInvolucrado, Involucrado, InvolucradoIncidente,
    Servicio, ServicioIP, PuertoDispositivo, ConexionTopologica,
    MonitoreoServicio, ConfiguracionMonitoreo,
    RetentionPolicy, BackupRecord,
)


# ============================================================================
#  DLP SERIALIZERS
# ============================================================================

class DlpRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpRule
        fields = ["id", "name", "pattern", "match_type", "classification", "severity", "tags", "is_active"]


class DlpPolicySerializer(serializers.ModelSerializer):
    rules = DlpRuleSerializer(many=True, read_only=True)

    class Meta:
        model = DlpPolicy
        fields = [
            "code", "name", "description", "is_active", "severity",
            "scan_mode", "scan_paths", "monitored_extensions", "max_file_size_mb",
            "max_scan_seconds", "target_os", "realtime_enabled", "rules", "updated_at",
        ]


class DlpThreatListSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpThreat
        fields = [
            "id", "fingerprint", "agent_id", "agent_hostname", "policy_code",
            "rule_name", "classification", "severity", "status", "file_name",
            "file_path", "actor", "channel", "summary", "detected_at", "created_at",
        ]


class DlpThreatDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpThreat
        fields = "__all__"
        read_only_fields = ["fingerprint", "created_at", "event_published"]


class DlpThreatIngestSerializer(serializers.Serializer):
    agent_id = serializers.CharField(required=False, default="")
    incidents = serializers.ListField(child=serializers.DictField())


class DlpThreatIngestMultipartSerializer(serializers.Serializer):
    metadata = serializers.CharField(required=True)


class DlpScanSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = DlpScanSummary
        fields = "__all__"


class DlpAgentConfigSerializer(serializers.Serializer):
    policies = DlpPolicySerializer(many=True)
    fetched_at = serializers.DateTimeField(required=False)


# ============================================================================
#  BITACORA DE INCIDENTES SERIALIZERS
# ============================================================================

class CategoriaSerializer(serializers.ModelSerializer):
    subcategoria_count = serializers.SerializerMethodField()

    class Meta:
        model = Categoria
        fields = ["id", "nombre", "descripcion", "subcategoria_count"]

    def get_subcategoria_count(self, obj):
        return obj.subcategorias.count()


class SubcategoriaSerializer(serializers.ModelSerializer):
    categoria_nombre = serializers.CharField(source="categoria.nombre", read_only=True)

    class Meta:
        model = Subcategoria
        fields = ["id", "nombre", "descripcion", "nivel_peligrosidad", "categoria", "categoria_nombre"]


class ResponsableSerializer(serializers.ModelSerializer):
    class Meta:
        model = Responsable
        fields = "__all__"


class AreaSerializer(serializers.ModelSerializer):
    cuadro_centro_nombre = serializers.SerializerMethodField()
    rsi_nombre = serializers.SerializerMethodField()
    admin_nombre = serializers.SerializerMethodField()

    class Meta:
        model = Area
        fields = ["id", "nombre", "acronimo", "cuadro_centro", "rsi", "admin",
                  "cuadro_centro_nombre", "rsi_nombre", "admin_nombre"]

    def get_cuadro_centro_nombre(self, obj):
        return str(obj.cuadro_centro) if obj.cuadro_centro else None

    def get_rsi_nombre(self, obj):
        return str(obj.rsi) if obj.rsi else None

    def get_admin_nombre(self, obj):
        return str(obj.admin) if obj.admin else None


class MedidaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Medida
        fields = "__all__"


class ReporteSerializer(serializers.ModelSerializer):
    area_nombre = serializers.SerializerMethodField()

    class Meta:
        model = Reporte
        fields = [
            "id", "nombre_informante", "email_informante", "area", "area_nombre",
            "descripcion", "fecha_hora", "fecha_atencion", "fecha_solucion", "estado_solucion",
        ]

    def get_area_nombre(self, obj):
        return str(obj.area) if obj.area else None


class MedidaIncidenteSerializer(serializers.ModelSerializer):
    medida_nombre = serializers.CharField(source="medida.nombre", read_only=True)
    responsable_nombre = serializers.SerializerMethodField()

    class Meta:
        model = MedidaIncidente
        fields = [
            "id", "incidente", "medida", "medida_nombre", "responsable",
            "responsable_nombre", "fecha_cumplimiento", "estado_cumplimiento", "observaciones",
        ]

    def get_responsable_nombre(self, obj):
        return str(obj.responsable) if obj.responsable else None


class MedidaInvolucradoSerializer(serializers.ModelSerializer):
    medida_nombre = serializers.CharField(source="medida.nombre", read_only=True)
    responsable_nombre = serializers.SerializerMethodField()
    involucrado_nombre = serializers.SerializerMethodField()

    class Meta:
        model = MedidaInvolucrado
        fields = [
            "id", "involucrado", "involucrado_nombre", "medida", "medida_nombre",
            "responsable", "responsable_nombre", "fecha_cumplimiento", "estado_cumplimiento", "observaciones",
        ]

    def get_responsable_nombre(self, obj):
        return str(obj.responsable) if obj.responsable else None

    def get_involucrado_nombre(self, obj):
        return str(obj.involucrado) if obj.involucrado else None


class InvolucradoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Involucrado
        fields = "__all__"


class InvolucradoIncidenteSerializer(serializers.ModelSerializer):
    involucrado_nombre = serializers.SerializerMethodField()
    medida_nombre = serializers.SerializerMethodField()

    class Meta:
        model = InvolucradoIncidente
        fields = [
            "id", "incidente", "involucrado", "involucrado_nombre",
            "descripcion", "medida_impuesta", "medida_nombre",
            "fecha_inicio", "fecha_fin",
        ]

    def get_involucrado_nombre(self, obj):
        return str(obj.involucrado) if obj.involucrado else None

    def get_medida_nombre(self, obj):
        return str(obj.medida_impuesta) if obj.medida_impuesta else None


class IncidenteListSerializer(serializers.ModelSerializer):
    estado_display = serializers.CharField(source="get_estado_solucion_display", read_only=True)
    medida_count = serializers.SerializerMethodField()
    involucrado_count = serializers.SerializerMethodField()
    servicios_nombres = serializers.SerializerMethodField()
    areas_nombres = serializers.SerializerMethodField()
    reporte_informantes = serializers.SerializerMethodField()

    class Meta:
        model = Incidente
        fields = [
            "id", "codigo_incidente", "nombre_incidente", "descripcion",
            "fecha_hora", "fecha_atencion", "fecha_solucion",
            "estado_solucion", "estado_display", "notificado_osri",
            "evidencia", "medida_count", "involucrado_count",
            "servicios_nombres", "areas_nombres", "reporte_informantes",
        ]

    def get_medida_count(self, obj):
        return obj.medidas.count()

    def get_involucrado_count(self, obj):
        return obj.involucrados.count()

    def get_servicios_nombres(self, obj):
        return [str(s) for s in obj.servicios.all()]

    def get_areas_nombres(self, obj):
        return [str(a) for a in obj.areas.all()]

    def get_reporte_informantes(self, obj):
        return [r.nombre_informante for r in obj.reportes.all()]


class IncidenteDetailSerializer(serializers.ModelSerializer):
    estado_display = serializers.CharField(source="get_estado_solucion_display", read_only=True)
    reportes = ReporteSerializer(many=True, read_only=True)
    areas_data = AreaSerializer(source="areas", many=True, read_only=True)
    subcategorias_data = SubcategoriaSerializer(source="subcategorias", many=True, read_only=True)
    medidas = MedidaIncidenteSerializer(many=True, read_only=True)
    involucrados_data = InvolucradoIncidenteSerializer(source="involucrados", many=True, read_only=True)
    servicios_data = serializers.SerializerMethodField()

    class Meta:
        model = Incidente
        fields = "__all__"

    def get_servicios_data(self, obj):
        return [
            {
                "id": s.id,
                "nombre": s.nombre,
                "tipo": s.tipo,
                "tipo_display": s.get_tipo_display(),
                "responsable_nombre": str(s.responsable) if s.responsable else None,
                "activo": s.activo,
            }
            for s in obj.servicios.all()
        ]


# ============================================================================
#  INFRAESTRUCTURA / CMDB SERIALIZERS
# ============================================================================

class ServicioSerializer(serializers.ModelSerializer):
    tipo_display = serializers.CharField(source="get_tipo_display", read_only=True)
    responsable_nombre = serializers.SerializerMethodField()
    ip_count = serializers.SerializerMethodField()
    hijos_count = serializers.SerializerMethodField()

    class Meta:
        model = Servicio
        fields = [
            "id", "nombre", "tipo", "tipo_display", "descripcion",
            "num_puertos", "modelo", "fabricante", "numero_serie", "firmware",
            "host", "network", "subnet_mask", "gateway", "red_tipo", "vlan_id",
            "dns_primario", "dns_secundario", "dhcp_activo",
            "url_servicio", "puerto_servicio",
            "plataforma", "servicio_padre", "monitorear", "protocolo_monitoreo",
            "puerto_monitoreo", "intervalo_segundos", "estado_monitoreo",
            "ubicacion_fisica", "rack", "posicion_rack", "edificio", "piso",
            "nivel_red", "coordenadas_logicas_x", "coordenadas_logicas_y",
            "responsable", "responsable_nombre",
            "zona_ancho", "zona_alto", "zona_color_fondo", "zona_color_borde",
            "activo", "fecha_creacion", "fecha_actualizacion", "ip_count", "hijos_count",
        ]

    def get_responsable_nombre(self, obj):
        return str(obj.responsable) if obj.responsable else None

    def get_ip_count(self, obj):
        return obj.ips.count()

    def get_hijos_count(self, obj):
        return obj.hijos.count()


class ServicioIPSerializer(serializers.ModelSerializer):
    servicio_nombre = serializers.CharField(source="servicio.nombre", read_only=True)

    class Meta:
        model = ServicioIP
        fields = "__all__"


class PuertoDispositivoSerializer(serializers.ModelSerializer):
    dispositivo_nombre = serializers.CharField(source="dispositivo.nombre", read_only=True)

    class Meta:
        model = PuertoDispositivo
        fields = "__all__"


class ConexionTopologicaSerializer(serializers.ModelSerializer):
    origen_nombre = serializers.CharField(source="origen.nombre", read_only=True)
    destino_nombre = serializers.CharField(source="destino.nombre", read_only=True)

    class Meta:
        model = ConexionTopologica
        fields = "__all__"


class MonitoreoServicioSerializer(serializers.ModelSerializer):
    servicio_nombre = serializers.CharField(source="servicio.nombre", read_only=True)

    class Meta:
        model = MonitoreoServicio
        fields = "__all__"


class ConfiguracionMonitoreoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ConfiguracionMonitoreo
        fields = "__all__"


class RetentionPolicySerializer(serializers.ModelSerializer):
    entity_type_display = serializers.CharField(source="get_entity_type_display", read_only=True)
    action_display = serializers.CharField(source="get_action_display", read_only=True)

    class Meta:
        model = RetentionPolicy
        fields = "__all__"


class BackupRecordSerializer(serializers.ModelSerializer):
    backup_type_display = serializers.CharField(source="get_backup_type_display", read_only=True)
    status_display = serializers.CharField(source="get_status_display", read_only=True)
    file_size_display = serializers.SerializerMethodField()

    class Meta:
        model = BackupRecord
        fields = "__all__"

    def get_file_size_display(self, obj):
        if obj.file_size < 1024:
            return f"{obj.file_size} B"
        elif obj.file_size < 1024 ** 2:
            return f"{obj.file_size / 1024:.1f} KB"
        elif obj.file_size < 1024 ** 3:
            return f"{obj.file_size / 1024 ** 2:.1f} MB"
        else:
            return f"{obj.file_size / 1024 ** 3:.2f} GB"
