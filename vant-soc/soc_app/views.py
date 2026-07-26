import base64
import logging
from datetime import timedelta
from pathlib import Path

from django.db.models import Count, Q
from django.http import FileResponse, Http404
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

from .models import (
    DlpPolicy, DlpRule, DlpThreat, DlpScanSummary,
    Categoria, Subcategoria, Responsable, Area, Medida,
    Reporte, Incidente, MedidaIncidente, Involucrado, InvolucradoIncidente,
    Servicio, ServicioIP, PuertoDispositivo, ConexionTopologica,
    MonitoreoServicio, ConfiguracionMonitoreo,
)
from .serializers import (
    DlpPolicySerializer, DlpRuleSerializer,
    DlpThreatListSerializer, DlpThreatDetailSerializer,
    DlpThreatIngestSerializer, DlpScanSummarySerializer,
    DlpAgentConfigSerializer, DlpThreatIngestMultipartSerializer,
    CategoriaSerializer, SubcategoriaSerializer,
    ResponsableSerializer, AreaSerializer, MedidaSerializer,
    ReporteSerializer, IncidenteListSerializer, IncidenteDetailSerializer,
    MedidaIncidenteSerializer, InvolucradoSerializer, InvolucradoIncidenteSerializer,
    ServicioSerializer, ServicioIPSerializer, PuertoDispositivoSerializer,
    ConexionTopologicaSerializer, MonitoreoServicioSerializer,
)

logger = logging.getLogger(__name__)

ALLOWED_MIME_PREFIXES = (
    "text/", "application/pdf", "application/msword",
    "application/vnd.openxmlformats-officedocument",
    "application/vnd.ms-", "image/", "message/rfc822",
)
MAX_EVIDENCE_SIZE = 25 * 1024 * 1024


# ============================================================================
#  HELPERS
# ============================================================================

def _get_agent_id(request):
    return getattr(request, "agent_id", "") or ""


def _get_username(request):
    claims = getattr(request, "user_claims", None)
    if claims:
        return claims.get("username", "api")
    return "api"


def _parse_detected_at(raw):
    if raw:
        try:
            dt = timezone.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if not timezone.is_aware(dt):
                dt = timezone.make_aware(dt)
            return dt
        except (ValueError, TypeError):
            pass
    return timezone.now()


def _publish_dlp_event(threat):
    try:
        from vant_common.bus import EventBus
        bus = EventBus("soc")
        bus.publish_event("threats", "threat_detected", {
            "fingerprint": threat.fingerprint,
            "agent_id": str(threat.agent_id),
            "classification": threat.classification,
            "severity": threat.severity,
            "file_name": threat.file_name,
            "detected_at": threat.detected_at.isoformat(),
        })
    except Exception as e:
        logger.warning("soc.service_bus.unavailable error=%s", e)


def _ingest_threats(incidents_data, agent_id, uploaded_files=None):
    uploaded_files = uploaded_files or {}
    created_count = skipped_count = 0

    for inc_data in incidents_data:
        fingerprint = inc_data.get("fingerprint", "")
        if not fingerprint:
            skipped_count += 1
            continue

        detected_at = _parse_detected_at(inc_data.get("detected_at", ""))
        metadata = inc_data.get("metadata", {})

        threat, created = DlpThreat.objects.update_or_create(
            fingerprint=fingerprint,
            defaults={
                "agent_id": agent_id,
                "agent_hostname": inc_data.get("agent_hostname", ""),
                "policy_code": inc_data.get("policy_code", ""),
                "rule_name": inc_data.get("rule_name", ""),
                "classification": inc_data.get("classification", ""),
                "severity": inc_data.get("severity", "high"),
                "status": inc_data.get("status", "open"),
                "file_name": inc_data.get("file_name", "") or "",
                "file_path": inc_data.get("file_path", "") or "",
                "file_hash": inc_data.get("file_hash", "") or "",
                "file_size": metadata.get("size", 0),
                "actor": inc_data.get("actor", ""),
                "channel": inc_data.get("channel", "filesystem"),
                "summary": inc_data.get("summary", "") or "",
                "matched_keywords": inc_data.get("matched_keywords", []),
                "metadata": metadata,
                "detected_at": detected_at,
            },
        )
        if created:
            created_count += 1
            if threat.severity == "critical":
                try:
                    _publish_dlp_event(threat)
                    DlpThreat.objects.filter(fingerprint=fingerprint).update(event_published=True)
                except Exception:
                    pass

    return created_count, skipped_count


# ============================================================================
#  HEALTH
# ============================================================================

@api_view(["GET"])
def health_check(request):
    try:
        from django.db import connection
        connection.ensure_connection()
        db_ok = True
    except Exception:
        db_ok = False

    return Response({
        "status": "healthy" if db_ok else "degraded",
        "service": "vant-soc",
        "database": "connected" if db_ok else "disconnected",
        "dlp_threats": DlpThreat.objects.count(),
        "incidentes": Incidente.objects.count(),
        "servicios": Servicio.objects.count(),
        "timestamp": timezone.now().isoformat(),
    })


# ============================================================================
#  STATISTICS
# ============================================================================

@api_view(["GET"])
def soc_statistics(request):
    hours = int(request.query_params.get("hours", 24))
    cutoff = timezone.now() - timedelta(hours=hours)

    threats_qs = DlpThreat.objects.filter(detected_at__gte=cutoff)
    incidents_qs = Incidente.objects.filter(fecha_hora__gte=cutoff)

    threat_by_severity = list(threats_qs.values("severity").annotate(count=Count("id")))
    threat_by_status = list(threats_qs.values("status").annotate(count=Count("id")))
    incident_by_estado = list(incidents_qs.values("estado_solucion").annotate(count=Count("id")))

    today_threats = DlpThreat.objects.filter(detected_at__date=timezone.now().date()).count()
    today_incidents = Incidente.objects.filter(fecha_hora__date=timezone.now().date()).count()
    open_incidents = Incidente.objects.exclude(estado_solucion="cerrado").count()

    return Response({
        "dlp": {
            "total": DlpThreat.objects.count(),
            "today": today_threats,
            "by_severity": {s["severity"]: s["count"] for s in threat_by_severity},
            "by_status": {s["status"]: s["count"] for s in threat_by_status},
        },
        "incidentes": {
            "total": Incidente.objects.count(),
            "today": today_incidents,
            "open": open_incidents,
            "by_estado": {s["estado_solucion"]: s["count"] for s in incident_by_estado},
        },
        "infraestructura": {
            "servicios": Servicio.objects.count(),
            "areas": Area.objects.count(),
            "responsables": Responsable.objects.count(),
        },
    })


# ============================================================================
#  DLP - AGENT ENDPOINTS
# ============================================================================

@api_view(["GET"])
def agent_dlp_config(request):
    if getattr(request, "auth_type", "") != "agent":
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("Valid agent token required")
    policies = DlpPolicy.objects.filter(is_active=True).prefetch_related("rules")
    serializer = DlpAgentConfigSerializer({"policies": policies, "fetched_at": timezone.now()})
    return Response(serializer.data)


@api_view(["POST"])
def ingest_dlp_threats(request):
    if getattr(request, "auth_type", "") != "agent":
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("Valid agent token required")
    serializer = DlpThreatIngestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data
    agent_id = data.get("agent_id", _get_agent_id(request))
    created, skipped = _ingest_threats(data["incidents"], agent_id)
    return Response({"status": "ok", "ingested": created, "skipped": skipped}, status=status.HTTP_201_CREATED)


@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
def ingest_dlp_threats_multipart(request):
    if getattr(request, "auth_type", "") not in ("agent", "user"):
        from rest_framework.exceptions import NotAuthenticated
        raise NotAuthenticated("Valid token required")
    serializer = DlpThreatIngestMultipartSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    import json
    meta = serializer.validated_data["metadata"]
    if isinstance(meta, str):
        meta = json.loads(meta)
    agent_id = meta.get("agent_id", _get_agent_id(request))
    uploaded_files = {k[5:]: request.FILES[k] for k in request.FILES if k.startswith("file_")}
    created, skipped = _ingest_threats(meta["incidents"], agent_id, uploaded_files)
    return Response({"status": "ok", "ingested": created, "skipped": skipped}, status=status.HTTP_201_CREATED)


# ============================================================================
#  DLP - POLICIES
# ============================================================================

class DlpPolicyViewSet(viewsets.ModelViewSet):
    queryset = DlpPolicy.objects.all()
    serializer_class = DlpPolicySerializer
    lookup_field = "code"

    def get_queryset(self):
        qs = super().get_queryset()
        enabled = self.request.query_params.get("enabled")
        if enabled is not None:
            qs = qs.filter(is_active=enabled.lower() == "true")
        return qs

    @action(detail=True, methods=["get"])
    def rules(self, request, code=None):
        policy = self.get_object()
        rules = policy.rules.filter(is_active=True)
        return Response(DlpRuleSerializer(rules, many=True).data)


# ============================================================================
#  DLP - THREATS
# ============================================================================

class DlpThreatViewSet(viewsets.ModelViewSet):
    http_method_names = ["get", "patch", "head", "options"]
    serializer_class = DlpThreatListSerializer

    def get_queryset(self):
        qs = DlpThreat.objects.all()
        p = self.request.query_params
        if p.get("severity"):
            qs = qs.filter(severity=p["severity"])
        if p.get("status"):
            qs = qs.filter(status=p["status"])
        if p.get("classification"):
            qs = qs.filter(classification=p["classification"])
        if p.get("agent_id"):
            qs = qs.filter(agent_id=p["agent_id"])
        if p.get("q"):
            qs = qs.filter(Q(file_name__icontains=p["q"]) | Q(file_path__icontains=p["q"]) | Q(actor__icontains=p["q"]))
        if p.get("hours"):
            try:
                qs = qs.filter(detected_at__gte=timezone.now() - timedelta(hours=int(p["hours"])))
            except (ValueError, TypeError):
                pass
        return qs.order_by("-detected_at")

    def get_serializer_class(self):
        if self.action == "retrieve":
            return DlpThreatDetailSerializer
        return DlpThreatListSerializer

    @action(detail=True, methods=["patch"])
    def acknowledge(self, request, pk=None):
        threat = self.get_object()
        threat.status = "acknowledged"
        threat.acknowledged_at = timezone.now()
        threat.acknowledged_by = _get_username(request)
        threat.save(update_fields=["status", "acknowledged_at", "acknowledged_by"])
        return Response({"status": "acknowledged", "id": threat.id})

    @action(detail=True, methods=["patch"])
    def resolve(self, request, pk=None):
        threat = self.get_object()
        threat.status = request.data.get("status", "resolved")
        threat.resolved_at = timezone.now()
        threat.resolved_by = _get_username(request)
        threat.resolution_notes = request.data.get("notes", "")
        threat.save(update_fields=["status", "resolved_at", "resolved_by", "resolution_notes"])
        return Response({"status": threat.status, "id": threat.id})

    @action(detail=True, methods=["post"], url_path="create-report")
    def create_report(self, request, pk=None):
        threat = self.get_object()
        if threat.reporte:
            return Response({"error": "Threat already linked to a report", "reporte_id": threat.reporte.id}, status=status.HTTP_409_CONFLICT)
        reporte = Reporte.objects.create(
            nombre_informante=f"DLP Auto - {threat.agent_hostname}",
            email_informante="",
            descripcion=f"Amenaza DLP detectada: {threat.file_name} ({threat.classification}). {threat.summary}",
            estado_solucion="nuevo",
        )
        threat.reporte = reporte
        threat.save(update_fields=["reporte"])
        return Response(ReporteSerializer(reporte).data, status=status.HTTP_201_CREATED)


# ============================================================================
#  DLP - SCANS
# ============================================================================

class DlpScanSummaryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DlpScanSummary.objects.all()
    serializer_class = DlpScanSummarySerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("agent_id"):
            qs = qs.filter(agent_id=self.request.query_params["agent_id"])
        return qs.order_by("-started_at")


@api_view(["GET"])
def evidence_download(request, pk):
    try:
        threat = DlpThreat.objects.get(pk=pk)
    except DlpThreat.DoesNotExist:
        raise Http404
    if not threat.evidence_file:
        return Response({"error": "No evidence"}, status=status.HTTP_404_NOT_FOUND)
    return FileResponse(threat.evidence_file.open("rb"), as_attachment=True, filename=threat.file_name or Path(threat.evidence_file.name).name)


# ============================================================================
#  BITACORA - CATEGORIAS / SUBCATEGORIAS
# ============================================================================

class CategoriaViewSet(viewsets.ModelViewSet):
    queryset = Categoria.objects.all()
    serializer_class = CategoriaSerializer


class SubcategoriaViewSet(viewsets.ModelViewSet):
    queryset = Subcategoria.objects.select_related("categoria").all()
    serializer_class = SubcategoriaSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("categoria"):
            qs = qs.filter(categoria_id=self.request.query_params["categoria"])
        return qs


# ============================================================================
#  BITACORA - RESPONSABLES / AREAS
# ============================================================================

class ResponsableViewSet(viewsets.ModelViewSet):
    queryset = Responsable.objects.all()
    serializer_class = ResponsableSerializer


class AreaViewSet(viewsets.ModelViewSet):
    queryset = Area.objects.select_related("cuadro_centro", "rsi", "admin").all()
    serializer_class = AreaSerializer


# ============================================================================
#  BITACORA - MEDIDAS
# ============================================================================

class MedidaViewSet(viewsets.ModelViewSet):
    queryset = Medida.objects.all()
    serializer_class = MedidaSerializer


class MedidaIncidenteViewSet(viewsets.ModelViewSet):
    queryset = MedidaIncidente.objects.select_related("medida", "responsable", "incidente").all()
    serializer_class = MedidaIncidenteSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("incidente"):
            qs = qs.filter(incidente_id=self.request.query_params["incidente"])
        return qs


# ============================================================================
#  BITACORA - INVOLUCRADOS
# ============================================================================

class InvolucradoViewSet(viewsets.ModelViewSet):
    queryset = Involucrado.objects.all()
    serializer_class = InvolucradoSerializer


class InvolucradoIncidenteViewSet(viewsets.ModelViewSet):
    queryset = InvolucradoIncidente.objects.select_related("involucrado", "incidente", "medida_impuesta").all()
    serializer_class = InvolucradoIncidenteSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("incidente"):
            qs = qs.filter(incidente_id=self.request.query_params["incidente"])
        return qs


# ============================================================================
#  BITACORA - REPORTES
# ============================================================================

class ReporteViewSet(viewsets.ModelViewSet):
    queryset = Reporte.objects.select_related("area").all()
    serializer_class = ReporteSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("estado"):
            qs = qs.filter(estado_solucion=self.request.query_params["estado"])
        return qs

    @action(detail=True, methods=["post"], url_path="create-incident")
    def create_incident(self, request, pk=None):
        reporte = self.get_object()
        if reporte.estado_solucion != "nuevo":
            return Response({"error": "Reporte already attended"}, status=status.HTTP_409_CONFLICT)
        incidente = Incidente.objects.create(
            nombre_incidente=f"Incidente desde Reporte #{reporte.pk}",
            descripcion=reporte.descripcion,
            estado_solucion="nuevo",
        )
        incidente.reportes.add(reporte)
        reporte.estado_solucion = "atendido"
        reporte.fecha_atencion = timezone.now()
        reporte.save(update_fields=["estado_solucion", "fecha_atencion"])
        return Response(IncidenteDetailSerializer(incidente).data, status=status.HTTP_201_CREATED)


# ============================================================================
#  BITACORA - INCIDENTES
# ============================================================================

class IncidenteViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        qs = Incidente.objects.prefetch_related("reportes", "areas", "subcategorias", "medidas", "involucrados").all()
        p = self.request.query_params
        if p.get("estado"):
            qs = qs.filter(estado_solucion=p["estado"])
        if p.get("q"):
            qs = qs.filter(Q(nombre_incidente__icontains=p["q"]) | Q(codigo_incidente__icontains=p["q"]) | Q(descripcion__icontains=p["q"]))
        if p.get("area"):
            qs = qs.filter(areas__id=p["area"])
        if p.get("categoria"):
            qs = qs.filter(subcategorias__categoria__id=p["categoria"])
        if p.get("hours"):
            try:
                qs = qs.filter(fecha_hora__gte=timezone.now() - timedelta(hours=int(p["hours"])))
            except (ValueError, TypeError):
                pass
        return qs.distinct().order_by("-fecha_hora")

    def get_serializer_class(self):
        if self.action == "retrieve":
            return IncidenteDetailSerializer
        return IncidenteListSerializer

    @action(detail=True, methods=["patch"], url_path="transition")
    def transition(self, request, pk=None):
        incidente = self.get_object()
        new_estado = request.data.get("estado_solucion")
        valid_transitions = {
            "nuevo": ["abierto"],
            "abierto": ["investigacion", "mitigacion", "cerrado"],
            "investigacion": ["mitigacion", "cerrado"],
            "mitigacion": ["cerrado"],
        }
        allowed = valid_transitions.get(incidente.estado_solucion, [])
        if new_estado not in allowed:
            return Response(
                {"error": f"Cannot transition from '{incidente.estado_solucion}' to '{new_estado}'. Allowed: {allowed}"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not incidente.fecha_atencion:
            incidente.fecha_atencion = timezone.now()
        if new_estado == "cerrado":
            incidente.fecha_solucion = timezone.now()
            for r in incidente.reportes.all():
                if not r.fecha_solucion:
                    r.fecha_solucion = timezone.now()
                    r.save(update_fields=["fecha_solucion"])
        incidente.estado_solucion = new_estado
        incidente.save(update_fields=["estado_solucion", "fecha_atencion", "fecha_solucion"])
        return Response(IncidenteDetailSerializer(incidente).data)


# ============================================================================
#  INFRAESTRUCTURA / CMDB
# ============================================================================

class ServicioViewSet(viewsets.ModelViewSet):
    queryset = Servicio.objects.select_related("responsable", "servicio_padre").all()
    serializer_class = ServicioSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        p = self.request.query_params
        if p.get("tipo"):
            qs = qs.filter(tipo=p["tipo"])
        if p.get("red_tipo"):
            qs = qs.filter(red_tipo=p["red_tipo"])
        if p.get("q"):
            qs = qs.filter(Q(nombre__icontains=p["q"]) | Q(host__icontains=p["q"]) | Q(modelo__icontains=p["q"]))
        if p.get("activo") is not None:
            qs = qs.filter(activo=p["activo"].lower() == "true")
        return qs


class ServicioIPViewSet(viewsets.ModelViewSet):
    queryset = ServicioIP.objects.select_related("servicio").all()
    serializer_class = ServicioIPSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("servicio"):
            qs = qs.filter(servicio_id=self.request.query_params["servicio"])
        return qs


class PuertoDispositivoViewSet(viewsets.ModelViewSet):
    queryset = PuertoDispositivo.objects.select_related("dispositivo").all()
    serializer_class = PuertoDispositivoSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("dispositivo"):
            qs = qs.filter(dispositivo_id=self.request.query_params["dispositivo"])
        return qs


class ConexionTopologicaViewSet(viewsets.ModelViewSet):
    queryset = ConexionTopologica.objects.select_related("origen", "destino").all()
    serializer_class = ConexionTopologicaSerializer


class MonitoreoServicioViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = MonitoreoServicio.objects.select_related("servicio").all()
    serializer_class = MonitoreoServicioSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("servicio"):
            qs = qs.filter(servicio_id=self.request.query_params["servicio"])
        return qs.order_by("-timestamp")
