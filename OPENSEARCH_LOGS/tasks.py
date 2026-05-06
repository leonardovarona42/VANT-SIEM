import logging
from datetime import timedelta
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def cleanup_old_logs(self, days=None):
    from .models import LogEvent, LogRetentionPolicy

    policies = LogRetentionPolicy.objects.filter(auto_delete=True)
    total_deleted = 0

    for policy in policies:
        if days is not None:
            cutoff_days = days
        else:
            cutoff_days = policy.retention_days

        cutoff = timezone.now() - timedelta(days=cutoff_days)
        qs = LogEvent.objects.filter(
            source_type=policy.source_type,
            event_time__lt=cutoff,
        )
        count = qs.count()
        if count > 0:
            qs.delete()
            total_deleted += count
            logger.info(f'Cleaned up {count} {policy.source_type} logs older than {cutoff_days} days')

        policy.last_cleanup_at = timezone.now()
        policy.save(update_fields=['last_cleanup_at'])

    if not policies:
        default_cutoff = timezone.now() - timedelta(days=90)
        count = LogEvent.objects.filter(event_time__lt=default_cutoff).count()
        if count > 0:
            LogEvent.objects.filter(event_time__lt=default_cutoff).delete()
            total_deleted += count
            logger.info(f'Cleaned up {count} logs older than 90 days (default)')

    return {'deleted': total_deleted, 'policies_checked': policies.count()}


@shared_task(bind=True, max_retries=3)
def register_source_from_ingest(self, source_data):
    from .models import LogSource

    source_id = source_data.get('source_id')
    if not source_id:
        return {'error': 'source_id required'}

    source, created = LogSource.objects.get_or_create(
        source_id=source_id,
        defaults={
            'source_type': source_data.get('source_type', 'generic_syslog'),
            'vendor': source_data.get('vendor', 'Unknown'),
            'model': source_data.get('model', ''),
            'host_name': source_data.get('host_name', ''),
            'host_ip': source_data.get('host_ip'),
            'protocol': source_data.get('protocol', 'http_post'),
            'port': source_data.get('port'),
        }
    )

    if not created:
        source.touch()

    return {'source_id': source_id, 'created': created}


@shared_task
def get_ingestion_stats(hours=24):
    from .models import LogEvent, LogSource
    from django.db.models import Count

    cutoff = timezone.now() - timedelta(hours=hours)

    stats = {
        'total_events': LogEvent.objects.filter(event_time__gte=cutoff).count(),
        'sources_active': LogSource.objects.filter(last_seen_at__gte=cutoff).count(),
        'by_source_type': list(
            LogEvent.objects.filter(event_time__gte=cutoff)
            .values('source_type')
            .annotate(count=Count('id'))
            .order_by('-count')
        ),
        'by_severity': list(
            LogEvent.objects.filter(event_time__gte=cutoff)
            .values('severity')
            .annotate(count=Count('id'))
            .order_by('-count')
        ),
    }

    return stats
