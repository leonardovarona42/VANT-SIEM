"""
Incidents Service Event Handlers
Handles events from other services to create/update incidents
"""
import logging
from django.utils import timezone

logger = logging.getLogger('vant-siem.incidents')


def on_dlp_incident(event):
    from EVENT_M.models import Incident, Reporte, Categoria
    from inventory.models import AegisDlpIncident

    payload = event.get('payload', {})
    dlp_incident_id = payload.get('dlp_incident_id')

    if not dlp_incident_id:
        return

    try:
        dlp_inc = AegisDlpIncident.objects.get(id=dlp_incident_id)
    except AegisDlpIncident.DoesNotExist:
        logger.error("DLP incident %s not found", dlp_incident_id)
        return

    if dlp_inc.reporte_id:
        logger.info("Incident already linked for DLP %s", dlp_incident_id)
        return

    categoria = Categoria.objects.filter(nombre='DLP').first()
    if not categoria:
        categoria = Categoria.objects.create(nombre='DLP', descripcion='Data Loss Prevention')

    incidente = Incident.objects.create(
        categoria=categoria,
        subcategoria=None,
        estado='abierto',
        fecha_creacion=timezone.now(),
        descripcion=f"DLP: {payload.get('filename', 'unknown')} - {payload.get('classification', 'unknown')}",
    )

    reporte = Reporte.objects.create(
        incidente=incidente,
        fecha_reporte=timezone.now(),
        detalles=f"Archivo: {payload.get('filename')}\nClasificacion: {payload.get('classification')}\nHost: {payload.get('host_name')}\nUsuario: {payload.get('user')}",
    )

    dlp_inc.reporte_id = reporte.id
    dlp_inc.save()

    logger.info("Created incident %s for DLP %s", incidente.codigo, dlp_incident_id)


def on_log_alert(event):
    from EVENT_M.models import Incident, Categoria
    from django.utils import timezone

    payload = event.get('payload', {})
    alert_type = payload.get('alert_type')
    severity = payload.get('severity', 'medium')

    if severity not in ('high', 'critical'):
        return

    categoria = Categoria.objects.filter(nombre='IDS').first()
    if not categoria:
        categoria = Categoria.objects.create(nombre='IDS', descripcion='Intrusion Detection System')

    incidente = Incident.objects.create(
        categoria=categoria,
        estado='abierto',
        fecha_creacion=timezone.now(),
        descripcion=f"IDS Alert: {alert_type} - Severity: {severity}",
    )

    logger.info("Created incident %s for IDS alert", incidente.codigo)


def on_ai_prediction(event):
    from EVENT_M.models import Incident
    pass

    payload = event.get('payload', {})
    prediction_id = payload.get('prediction_id')

    if not prediction_id:
        return

    try:
        prediction = IncidentPrediction.objects.get(id=prediction_id)
        if prediction.incidente:
            return

        incidente = Incident.objects.create(
            estado='abierto',
            fecha_creacion=timezone.now(),
            descripcion=f"AI Prediction: {prediction.riesgo_predicho} (confidence: {prediction.confianza:.0%})",
        )

        prediction.incidente = incidente
        prediction.save()

        logger.info("Created incident %s for AI prediction %s", incidente.codigo, prediction_id)
    except IncidentPrediction.DoesNotExist:
        logger.error("Prediction %s not found", prediction_id)
