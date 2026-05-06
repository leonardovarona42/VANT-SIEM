from celery import shared_task
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def process_event_async(self, event_data):
    try:
        from EVENT_M.models import Incident, Reporte
        event_type = event_data.get('type')
        if event_type == 'incident':
            incident = Incident.objects.create(**event_data.get('data', {}))
            return {'status': 'success', 'incident_id': incident.id}
        elif event_type == 'report':
            reporte = Reporte.objects.create(**event_data.get('data', {}))
            return {'status': 'success', 'reporte_id': reporte.id}
        else:
            return {'status': 'unknown_event_type', 'type': event_type}
    except Exception as exc:
        logger.error(f'Event processing failed: {exc}')
        raise self.retry(exc=exc)


@shared_task
def generate_incident_report(incident_id):
    from EVENT_M.models import Incident
    try:
        incident = Incident.objects.get(id=incident_id)
        return {
            'status': 'generated',
            'incident_id': incident_id,
            'code': incident.codigo,
            'status': incident.estado,
        }
    except Incident.DoesNotExist:
        return {'status': 'not_found', 'incident_id': incident_id}
    except Exception as exc:
        logger.error(f'Report generation failed for incident {incident_id}: {exc}')
        return {'status': 'error', 'error': str(exc)}


@shared_task
def cleanup_resolved_incidents(days=365):
    from EVENT_M.models import Incident
    from django.utils import timezone
    from datetime import timedelta

    cutoff = timezone.now() - timedelta(days=days)
    deleted, _ = Incident.objects.filter(
        estado='resuelto',
        fecha_resolucion__lt=cutoff
    ).delete()
    return {'status': 'cleaned', 'deleted_count': deleted}
