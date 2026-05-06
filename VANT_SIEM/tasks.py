from celery import shared_task
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def process_pending_notifications(self):
    from VANT_SIEM.enhanced_notification_service import NotificationProcessor
    try:
        processor = NotificationProcessor()
        result = processor.process_queue()
        return {'status': 'success', 'processed': result}
    except Exception as exc:
        logger.error(f'Notification processing failed: {exc}')
        raise self.retry(exc=exc)


@shared_task(bind=True)
def send_notification_async(self, notification_id):
    from VANT_SIEM.enhanced_notification_service import send_notification
    try:
        result = send_notification(notification_id)
        return {'status': 'success', 'notification_id': notification_id, 'result': result}
    except Exception as exc:
        logger.error(f'Failed to send notification {notification_id}: {exc}')
        raise self.retry(exc=exc, max_retries=3)


@shared_task
def cleanup_old_notifications(days=30):
    from VANT_SIEM.models import NotificationLog
    from django.utils import timezone
    from datetime import timedelta

    cutoff = timezone.now() - timedelta(days=days)
    deleted, _ = NotificationLog.objects.filter(sent_at__lt=cutoff).delete()
    return {'status': 'cleaned', 'deleted_count': deleted}
