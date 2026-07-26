from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()

# DLP
router.register(r"policies", views.DlpPolicyViewSet, basename="dlp-policy")
router.register(r"threats/dlp", views.DlpThreatViewSet, basename="dlp-threat")
router.register(r"scans", views.DlpScanSummaryViewSet, basename="dlp-scan")

# Bitacora
router.register(r"categorias", views.CategoriaViewSet, basename="categoria")
router.register(r"subcategorias", views.SubcategoriaViewSet, basename="subcategoria")
router.register(r"responsables", views.ResponsableViewSet, basename="responsable")
router.register(r"areas", views.AreaViewSet, basename="area")
router.register(r"medidas", views.MedidaViewSet, basename="medida")
router.register(r"medidas-incidente", views.MedidaIncidenteViewSet, basename="medida-incidente")
router.register(r"involucrados", views.InvolucradoViewSet, basename="involucrado")
router.register(r"involucrado-incidente", views.InvolucradoIncidenteViewSet, basename="involucrado-incidente")
router.register(r"reportes", views.ReporteViewSet, basename="reporte")
router.register(r"incidentes", views.IncidenteViewSet, basename="incidente")

# Infraestructura
router.register(r"servicios", views.ServicioViewSet, basename="servicio")
router.register(r"servicio-ips", views.ServicioIPViewSet, basename="servicio-ip")
router.register(r"puertos", views.PuertoDispositivoViewSet, basename="puerto")
router.register(r"conexiones", views.ConexionTopologicaViewSet, basename="conexion")
router.register(r"monitoreo", views.MonitoreoServicioViewSet, basename="monitoreo")

urlpatterns = [
    path("api/health/", views.health_check, name="soc-health"),
    path("api/stats/", views.soc_statistics, name="soc-stats"),
    path("api/agent/dlp/config/", views.agent_dlp_config, name="soc-agent-config"),
    path("api/agent/dlp/threats/", views.ingest_dlp_threats, name="soc-agent-ingest"),
    path("api/agent/dlp/threats/upload/", views.ingest_dlp_threats_multipart, name="soc-agent-ingest-upload"),
    path("api/evidence/<int:pk>/download/", views.evidence_download, name="soc-evidence-download"),
    path("api/", include(router.urls)),
]
