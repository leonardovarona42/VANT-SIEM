import base64
import logging
from datetime import timedelta
from pathlib import Path

from django.db.models import Count, Q
from django.http import FileResponse, Http404
from django.utils import timezone
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, parser_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response

from .models import (
    DlpPolicy, DlpRule, DlpThreat, DlpScanSummary,
    Categoria, Subcategoria, Responsable, Area, Medida,
    Reporte, Incidente, MedidaIncidente, MedidaInvolucrado, Involucrado, InvolucradoIncidente,
    Servicio, ServicioIP, PuertoDispositivo, ConexionTopologica,
    MonitoreoServicio, ConfiguracionMonitoreo,
    RetentionPolicy, BackupRecord,
)
from .serializers import (
    DlpPolicySerializer, DlpRuleSerializer,
    DlpThreatListSerializer, DlpThreatDetailSerializer,
    DlpThreatIngestSerializer, DlpScanSummarySerializer,
    DlpAgentConfigSerializer, DlpThreatIngestMultipartSerializer,
    CategoriaSerializer, SubcategoriaSerializer,
    ResponsableSerializer, AreaSerializer, MedidaSerializer,
    ReporteSerializer, IncidenteListSerializer, IncidenteDetailSerializer,
    MedidaIncidenteSerializer, MedidaInvolucradoSerializer, InvolucradoSerializer, InvolucradoIncidenteSerializer,
    ServicioSerializer, ServicioIPSerializer, PuertoDispositivoSerializer,
    ConexionTopologicaSerializer, MonitoreoServicioSerializer,
    RetentionPolicySerializer, BackupRecordSerializer,
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
    if request:
        header_name = request.META.get("HTTP_X_ACTOR_USERNAME", "")
        if header_name:
            return header_name
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


def _publish_soc_event(event_type, entity_type, entity_id, payload, severity="info", request=None):
    import requests as http_requests
    import os
    try:
        http_requests.post(
            "http://127.0.0.1:8600/api/events/receive/",
            json={
                "event_type": event_type,
                "source_service": "soc",
                "entity_type": entity_type,
                "entity_id": str(entity_id),
                "actor_user_id": getattr(request, "jwt_claims", {}).get("sub", "") if request else "",
                "actor_username": _get_username(request) if request else "system",
                "payload": payload,
                "severity": severity,
            },
            headers={"X-Service-Secret": os.getenv("SERVICE_SECRET", "changeme-service-secret")},
            timeout=5,
        )
    except Exception as e:
        logger.warning("Failed to publish soc event to bus: %s", e)


def _auto_create_reporte_from_threat(threat):
    hostname = threat.agent_hostname or "Desconocido"
    actor = threat.actor or "N/A"
    summary = threat.summary or "Sin detalles"
    keywords_text = ""
    if threat.matched_keywords:
        keywords_text = f"\nPalabras clave detectadas: {', '.join(threat.matched_keywords[:10])}"

    description = (
        f"Amenaza DLP detectada por el agente '{hostname}'.\n\n"
        f"Clasificacion: {threat.classification}\n"
        f"Severidad: {threat.severity.upper()}\n"
        f"Regla: {threat.rule_name or threat.policy_code}\n"
        f"Canal: {threat.channel}\n"
        f"Actor: {actor}\n\n"
        f"Archivo: {threat.file_name}\n"
        f"Ruta: {threat.file_path}\n"
        f"Hash SHA-256: {threat.file_hash or 'N/A'}\n"
        f"Tamano: {threat.file_size} bytes\n"
        f"Fecha/Hora de deteccion: {threat.detected_at.strftime('%d/%m/%Y %H:%M:%S')}\n\n"
        f"Resumen: {summary}"
        f"{keywords_text}"
    )

    reporte = Reporte.objects.create(
        nombre_informante=f"DLP Service ({hostname})",
        email_informante="",
        descripcion=description,
        estado_solucion="nuevo",
    )
    threat.reporte = reporte
    threat.save(update_fields=["reporte"])
    return reporte


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
            reporte = _auto_create_reporte_from_threat(threat)
            try:
                _publish_soc_event(
                    "amenaza_dlp",
                    "dlp_threat",
                    threat.id,
                    {
                        "fingerprint": threat.fingerprint,
                        "agent_id": str(threat.agent_id),
                        "hostname": threat.agent_hostname,
                        "classification": threat.classification,
                        "severity": threat.severity,
                        "rule_name": threat.rule_name or threat.policy_code,
                        "channel": threat.channel,
                        "file_name": threat.file_name,
                        "file_path": threat.file_path,
                        "file_hash": threat.file_hash,
                        "file_size": threat.file_size,
                        "actor": threat.actor,
                        "summary": threat.summary,
                        "detected_at": threat.detected_at.isoformat(),
                        "reporte_id": reporte.id,
                    },
                    severity=threat.severity,
                )
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
@permission_classes([IsAuthenticated])
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
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
    queryset = Categoria.objects.all()
    serializer_class = CategoriaSerializer


class SubcategoriaViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
    queryset = Responsable.objects.all()
    serializer_class = ResponsableSerializer


class AreaViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Area.objects.select_related("cuadro_centro", "rsi", "admin").all()
    serializer_class = AreaSerializer


# ============================================================================
#  BITACORA - MEDIDAS
# ============================================================================

class MedidaViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Medida.objects.all()
    serializer_class = MedidaSerializer
    filterset_fields = ["tipo"]

    def get_queryset(self):
        qs = super().get_queryset()
        tipo = self.request.query_params.get("tipo")
        if tipo:
            qs = qs.filter(tipo=tipo)
        q = self.request.query_params.get("q")
        if q:
            qs = qs.filter(Q(nombre__icontains=q) | Q(descripcion__icontains=q))
        return qs


class MedidaIncidenteViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = MedidaIncidente.objects.select_related("medida", "responsable", "incidente").all()
    serializer_class = MedidaIncidenteSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("incidente"):
            qs = qs.filter(incidente_id=self.request.query_params["incidente"])
        return qs


class MedidaInvolucradoViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = MedidaInvolucrado.objects.select_related("medida", "responsable", "involucrado").all()
    serializer_class = MedidaInvolucradoSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("involucrado"):
            qs = qs.filter(involucrado_id=self.request.query_params["involucrado"])
        return qs


# ============================================================================
#  BITACORA - INVOLUCRADOS
# ============================================================================

class InvolucradoViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Involucrado.objects.all()
    serializer_class = InvolucradoSerializer


class InvolucradoIncidenteViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
    queryset = Reporte.objects.select_related("area").all()
    serializer_class = ReporteSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("estado"):
            qs = qs.filter(estado_solucion=self.request.query_params["estado"])
        return qs

    def perform_create(self, serializer):
        reporte = serializer.save()
        _publish_soc_event(
            "reporte_creado", "reporte", reporte.id,
            {"codigo": reporte.codigo_reporte, "descripcion": reporte.descripcion[:200],
             "area": str(reporte.area) if reporte.area else ""},
            request=self.request,
        )

    def perform_update(self, serializer):
        reporte = serializer.save()
        _publish_soc_event(
            "reporte_editado", "reporte", reporte.id,
            {"codigo": reporte.codigo_reporte, "descripcion": reporte.descripcion[:200]},
            request=self.request,
        )

    def perform_destroy(self, instance):
        payload = {"codigo": instance.codigo_reporte, "descripcion": instance.descripcion[:200]}
        instance.delete()
        _publish_soc_event("reporte_eliminado", "reporte", instance.id, payload, request=self.request)

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
    permission_classes = [IsAuthenticated]
    def get_object(self):
        pk = self.kwargs.get("pk")
        try:
            return Incidente.objects.get(pk=int(pk))
        except (ValueError, TypeError, Incidente.DoesNotExist):
            pass
        try:
            return Incidente.objects.get(codigo_incidente=pk)
        except Incidente.DoesNotExist:
            from rest_framework.exceptions import NotFound
            raise NotFound("Incidente not found")

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

    def perform_create(self, serializer):
        incidente = serializer.save()
        skip_event = self.request.META.get("HTTP_X_SUPPRESS_EVENT", "")
        if not skip_event:
            username = _get_username(self.request)
            _publish_soc_event(
                "incidente_creado", "incidente", incidente.id,
                {"codigo": incidente.codigo_incidente, "nombre": incidente.nombre_incidente,
                 "estado": incidente.estado_solucion, "descripcion": incidente.descripcion[:200],
                 "creado_por": username},
                severity="medium", request=self.request,
            )

    def perform_update(self, serializer):
        incidente = serializer.save()
        _publish_soc_event(
            "incidente_editado", "incidente", incidente.id,
            {"codigo": incidente.codigo_incidente, "nombre": incidente.nombre_incidente,
             "estado": incidente.estado_solucion},
            request=self.request,
        )

    def perform_destroy(self, instance):
        payload = {"codigo": instance.codigo_incidente, "nombre": instance.nombre_incidente}
        instance.delete()
        _publish_soc_event("incidente_eliminado", "incidente", instance.id, payload, severity="high", request=self.request)

    @action(detail=True, methods=["post", "patch"], url_path="transition")
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
        old_estado = incidente.estado_solucion
        if not incidente.fecha_atencion:
            incidente.fecha_atencion = timezone.now()
        if new_estado == "cerrado":
            incidente.fecha_solucion = timezone.now()
            for r in incidente.reportes.all():
                if not r.fecha_solucion:
                    r.fecha_solucion = timezone.now()
                r.estado_solucion = "cerrado"
                r.save(update_fields=["fecha_solucion", "estado_solucion"])
        incidente.estado_solucion = new_estado
        incidente.save(update_fields=["estado_solucion", "fecha_atencion", "fecha_solucion"])
        _publish_soc_event(
            "incidente_estado_cambiado", "incidente", incidente.id,
            {"codigo": incidente.codigo_incidente, "nombre": incidente.nombre_incidente,
             "estado_anterior": old_estado, "estado_nuevo": new_estado,
             "reportes": [{"id": r.id, "nombre": r.nombre_informante, "estado": r.estado_solucion}
                          for r in incidente.reportes.all()]},
            severity="medium", request=request,
        )
        return Response(IncidenteDetailSerializer(incidente).data)

    @action(detail=True, methods=["post", "delete"], url_path="reportes/(?P<reporte_pk>[0-9]+)")
    def manage_reportes(self, request, pk=None, reporte_pk=None):
        incidente = self.get_object()
        if request.method == "POST":
            reporte = Reporte.objects.get(pk=reporte_pk)
            incidente.reportes.add(reporte)
        else:
            incidente.reportes.remove(reporte_pk)
        return Response({"ok": True})

    @action(detail=True, methods=["post", "delete"], url_path="servicios/(?P<servicio_pk>[0-9]+)")
    def manage_servicios(self, request, pk=None, servicio_pk=None):
        incidente = self.get_object()
        if request.method == "POST":
            servicio = Servicio.objects.get(pk=servicio_pk)
            incidente.servicios.add(servicio)
        else:
            incidente.servicios.remove(servicio_pk)
        return Response({"ok": True})

    @action(detail=True, methods=["post", "delete"], url_path="areas/(?P<area_pk>[0-9]+)")
    def manage_areas(self, request, pk=None, area_pk=None):
        incidente = self.get_object()
        if request.method == "POST":
            area = Area.objects.get(pk=area_pk)
            incidente.areas.add(area)
        else:
            incidente.areas.remove(area_pk)
        return Response({"ok": True})

    @action(detail=True, methods=["post", "delete"], url_path="subcategorias/(?P<subcat_pk>[0-9]+)")
    def manage_subcategorias(self, request, pk=None, subcat_pk=None):
        incidente = self.get_object()
        if request.method == "POST":
            subcat = Subcategoria.objects.get(pk=subcat_pk)
            incidente.subcategorias.add(subcat)
        else:
            incidente.subcategorias.remove(subcat_pk)
        return Response({"ok": True})


# ============================================================================
#  INFRAESTRUCTURA / CMDB
# ============================================================================

class ServicioViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
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
    permission_classes = [IsAuthenticated]
    queryset = ServicioIP.objects.select_related("servicio").all()
    serializer_class = ServicioIPSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("servicio"):
            qs = qs.filter(servicio_id=self.request.query_params["servicio"])
        return qs


class PuertoDispositivoViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = PuertoDispositivo.objects.select_related("dispositivo").all()
    serializer_class = PuertoDispositivoSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("dispositivo"):
            qs = qs.filter(dispositivo_id=self.request.query_params["dispositivo"])
        return qs


class ConexionTopologicaViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = ConexionTopologica.objects.select_related("origen", "destino").all()
    serializer_class = ConexionTopologicaSerializer


class MonitoreoServicioViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = MonitoreoServicio.objects.select_related("servicio").all()
    serializer_class = MonitoreoServicioSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.request.query_params.get("servicio"):
            qs = qs.filter(servicio_id=self.request.query_params["servicio"])
        return qs.order_by("-timestamp")


# ============================================================================
#  METRICS ENDPOINTS (for web dashboard list pages)
# ============================================================================

def _compute_time_metrics(qs, time_field_start, time_field_end):
    """Compute avg/min/max in hours between two datetime fields."""
    has_data = qs.filter(**{f"{time_field_end}__isnull": False}).exists()
    if not has_data:
        return {"promedio": 0, "minimo": 0, "maximo": 0, "gauge": 0, "mensual": []}

    tiempos = []
    for obj in qs.filter(**{f"{time_field_end}__isnull": False}):
        t_start = getattr(obj, time_field_start)
        t_end = getattr(obj, time_field_end)
        if t_start and t_end:
            diff = (t_end - t_start).total_seconds() / 3600
            if diff > 0:
                tiempos.append(diff)

    if not tiempos:
        return {"promedio": 0, "minimo": 0, "maximo": 0, "gauge": 0, "mensual": []}

    avg = round(sum(tiempos) / len(tiempos), 1)
    mn = round(min(tiempos), 1)
    mx = round(max(tiempos), 1)

    now = timezone.now()
    month_tiempos = []
    for obj in qs.filter(**{f"{time_field_end}__isnull": False, f"{time_field_start}__month": now.month, f"{time_field_start}__year": now.year}):
        t_start = getattr(obj, time_field_start)
        t_end = getattr(obj, time_field_end)
        if t_start and t_end:
            diff = (t_end - t_start).total_seconds() / 3600
            if diff > 0:
                month_tiempos.append(diff)
    gauge = round(sum(month_tiempos) / len(month_tiempos), 1) if month_tiempos else avg

    from django.db.models.functions import TruncMonth
    monthly_dict = {}
    annotated = qs.filter(**{f"{time_field_end}__isnull": False}).annotate(month=TruncMonth(time_field_start)).values("month").order_by("month")
    for entry in annotated:
        m = entry["month"]
        if m is None:
            continue
        m_tiempos = []
        for obj in qs.filter(**{f"{time_field_end}__isnull": False, f"{time_field_start}__month": m.month, f"{time_field_start}__year": m.year}):
            t_s = getattr(obj, time_field_start)
            t_e = getattr(obj, time_field_end)
            if t_s and t_e:
                d = (t_e - t_s).total_seconds() / 3600
                if d > 0:
                    m_tiempos.append(d)
        monthly_dict[m] = round(sum(m_tiempos) / len(m_tiempos), 1) if m_tiempos else 0

    mensual = [{"mes": k.strftime("%b %Y"), "horas": v} for k, v in sorted(monthly_dict.items())]

    return {"promedio": avg, "minimo": mn, "maximo": mx, "gauge": gauge, "mensual": mensual}


@api_view(["GET"])
def incidentes_metrics(request):
    from django.db.models import Count
    qs = Incidente.objects.all()

    totales = {t["estado_solucion"]: t["total"] for t in qs.values("estado_solucion").annotate(total=Count("id"))}

    total_inc = qs.count()
    with_sol = qs.filter(fecha_solucion__isnull=False)
    resueltos = with_sol.count()
    tasa_resolucion = round((resueltos / total_inc) * 100, 1) if total_inc else 0

    atencion = _compute_time_metrics(qs, "fecha_hora", "fecha_atencion")
    solucion = _compute_time_metrics(qs, "fecha_hora", "fecha_solucion")

    return Response({
        "totales": totales,
        "total": total_inc,
        "tasa_resolucion": tasa_resolucion,
        "atencion": atencion,
        "solucion": solucion,
    })


@api_view(["GET"])
def reportes_metrics(request):
    from django.db.models import Count
    qs = Reporte.objects.all()

    totales = {t["estado_solucion"]: t["total"] for t in qs.values("estado_solucion").annotate(total=Count("id"))}

    total_rep = qs.count()
    with_sol = qs.filter(fecha_solucion__isnull=False)
    resueltos = with_sol.count()
    tasa_resolucion = round((resueltos / total_rep) * 100, 1) if total_rep else 0

    atencion = _compute_time_metrics(qs, "fecha_hora", "fecha_atencion")
    solucion = _compute_time_metrics(qs, "fecha_hora", "fecha_solucion")

    return Response({
        "totales": totales,
        "total": total_rep,
        "tasa_resolucion": tasa_resolucion,
        "atencion": atencion,
        "solucion": solucion,
    })


@api_view(["GET"])
def servicios_metrics(request):
    from django.db.models import Count

    qs = Servicio.objects.all()
    total = qs.count()
    sin_monitoreo = qs.filter(monitorear=False).count()
    monitoreando = qs.filter(monitorear=True).count()
    up = qs.filter(monitorear=True, estado_monitoreo="up").count()
    down = qs.filter(monitorear=True, estado_monitoreo="down").count()
    disponibilidad = round((up / monitoreando) * 100, 1) if monitoreando else 0

    por_tipo = list(qs.values("tipo").annotate(total=Count("id")))

    return Response({
        "total": total,
        "activos": up,
        "inactivos": down,
        "sin_monitoreo": sin_monitoreo,
        "monitoreando": monitoreando,
        "disponibilidad": disponibilidad,
        "por_tipo": {t["tipo"]: t["total"] for t in por_tipo},
    })


# ============================================================================
#  GESTION DE BASE DE DATOS
# ============================================================================

from django.db import connection

class RetentionPolicyViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = RetentionPolicy.objects.all()
    serializer_class = RetentionPolicySerializer


class BackupRecordViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = BackupRecord.objects.all()
    serializer_class = BackupRecordSerializer

    @action(detail=False, methods=["post"])
    def create_backup(self, request):
        from datetime import datetime
        import subprocess, os
        backup = BackupRecord.objects.create(
            backup_type=request.data.get("backup_type", "full"),
            status="running",
            started_at=datetime.now(),
            database_name=request.data.get("database_name", "vantsiem"),
            notes=request.data.get("notes", ""),
        )
        try:
            from django.conf import settings
            db_name = settings.DATABASES["default"]["NAME"]
            db_user = settings.DATABASES["default"]["USER"]
            db_host = settings.DATABASES["default"]["HOST"]
            db_port = settings.DATABASES["default"]["PORT"]
            db_pass = settings.DATABASES["default"]["PASSWORD"]
            backup_dir = "/opt/vant-siem/backups"
            os.makedirs(backup_dir, exist_ok=True)
            os.chmod(backup_dir, 0o755)
            filename = f"vantsiem_{backup.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
            filepath = f"{backup_dir}/{filename}"
            env = os.environ.copy()
            env["PGPASSWORD"] = db_pass
            result = subprocess.run(
                ["pg_dump", "-h", db_host, "-p", str(db_port),
                 "-U", db_user, "-d", db_name, "-f", filepath],
                capture_output=True, text=True, timeout=300, env=env,
            )
            if result.returncode == 0:
                backup.status = "completed"
                backup.file_path = filepath
                backup.file_size = os.path.getsize(filepath)
                backup.completed_at = datetime.now()
            else:
                backup.status = "failed"
                backup.error_message = result.stderr[:500]
        except Exception as e:
            backup.status = "failed"
            backup.error_message = str(e)[:500]
        backup.save()
        return Response(BackupRecordSerializer(backup).data)

    @action(detail=True, methods=["post"])
    def restore(self, request, pk=None):
        backup = self.get_object()
        import subprocess, os
        if not backup.file_path or backup.status != "completed":
            return Response({"error": "Backup no disponible para restauracion"}, status=400)
        try:
            from django.conf import settings
            db_name = settings.DATABASES["default"]["NAME"]
            db_user = settings.DATABASES["default"]["USER"]
            db_host = settings.DATABASES["default"]["HOST"]
            db_port = settings.DATABASES["default"]["PORT"]
            db_pass = settings.DATABASES["default"]["PASSWORD"]
            env = os.environ.copy()
            env["PGPASSWORD"] = db_pass
            result = subprocess.run(
                ["psql", "-h", db_host, "-p", str(db_port),
                 "-U", db_user, "-d", db_name, "-f", backup.file_path],
                capture_output=True, text=True, timeout=300, env=env,
            )
            if result.returncode == 0:
                return Response({"message": "Restauracion completada"})
            else:
                return Response({"error": result.stderr[:500]}, status=500)
        except Exception as e:
            return Response({"error": str(e)[:500]}, status=500)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def db_health(request):
    data = {}
    def run_query(cursor, sql, single=False):
        try:
            cursor.execute(sql)
            if single:
                return cursor.fetchone()[0]
            return cursor.fetchall()
        except Exception:
            return None
    try:
        with connection.cursor() as cursor:
            data["database_size"] = run_query(cursor, "SELECT pg_database_size(current_database())", single=True)
            rows = run_query(cursor, "SELECT schemaname, tablename, pg_total_relation_size(schemaname||'.'||tablename) FROM pg_tables WHERE schemaname='public' ORDER BY 3 DESC LIMIT 20")
            data["table_sizes"] = [{"table": r[1], "size": r[2]} for r in rows] if rows else []
            data["active_connections"] = run_query(cursor, "SELECT numbackends FROM pg_stat_database WHERE datname=current_database()", single=True)
            data["cache_hit_ratio"] = run_query(cursor, "SELECT ROUND(blks_hit::decimal / GREATEST(blks_hit+blks_read,1) * 100, 1) FROM pg_stat_database WHERE datname=current_database()", single=True)
            ver = run_query(cursor, "SELECT version()", single=True)
            data["pg_version"] = (ver or "unknown").split(" on ")[0] if ver else "unknown"
            rows = run_query(cursor, "SELECT datname, pg_database_size(datname) FROM pg_database WHERE datistemplate=false ORDER BY 2 DESC")
            data["databases"] = [{"name": r[0], "size": r[1]} for r in rows] if rows else []
            data["server_start"] = str(run_query(cursor, "SELECT pg_postmaster_start_time()", single=True) or "")
            rows = run_query(cursor, "SELECT schemaname, relname, n_live_tup, n_dead_tup FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 10")
            data["table_stats"] = [{"table": r[1], "live_rows": r[2], "dead_rows": r[3]} for r in rows] if rows else []
            data["status"] = "healthy"
    except Exception as e:
        data["status"] = "error"
        data["error"] = str(e)
    return Response(data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def db_optimize(request):
    action = request.data.get("action", "vacuum")
    table = request.data.get("table", "")
    try:
        with connection.cursor() as cursor:
            cursor.execute("SET statement_timeout = '300s'")
            cursor.execute("SET idle_in_transaction_session_timeout = '10s'")
            connection.set_autocommit(True)
            try:
                if action == "vacuum":
                    if table:
                        cursor.execute(f"VACUUM ANALYZE {table}")
                    else:
                        cursor.execute("VACUUM ANALYZE")
                elif action == "analyze":
                    if table:
                        cursor.execute(f"ANALYZE {table}")
                    else:
                        cursor.execute("ANALYZE")
                elif action == "reindex":
                    if not table:
                        return Response({"error": "Especifique una tabla para reindexar"}, status=400)
                    cursor.execute(f"REINDEX TABLE {table}")
                else:
                    return Response({"error": f"Accion desconocida: {action}"}, status=400)
            finally:
                connection.set_autocommit(False)
        return Response({"message": f"{action} completado en {table or 'todas las tablas'}"})
    except Exception as e:
        return Response({"error": str(e)}, status=500)
