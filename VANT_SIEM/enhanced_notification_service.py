"""
Servicio Mejorado de Notificaciones para VANT-SIEM

Este módulo proporciona un sistema avanzado de notificaciones con soporte para múltiples canales,
procesamiento asíncrono, plantillas personalizables y gestión de colas.
"""

import threading
import time
import json
import requests
from django.conf import settings
from django.utils import timezone
from django.db import transaction, models
from django.core.mail import send_mail
from django.template import Template, Context
from .models import (
    Notification, NotificationChannel, NotificationQueue,
    NotificationTemplate, NotificationSettings, NotificationLog
)
from .logging_system import event_logger


class EnhancedNotificationService:
    """Servicio principal para gestión de notificaciones"""

    def __init__(self):
        self.is_running = False
        self.worker_thread = None
        self.queue_lock = threading.Lock()

    def start_service(self):
        """Iniciar el servicio de notificaciones"""
        if self.is_running:
            return False, "El servicio ya está ejecutándose"

        self.is_running = True
        self.worker_thread = threading.Thread(target=self._process_queue_worker, daemon=True)
        self.worker_thread.start()

        # Log del evento
        event_logger.log_event(
            user=None,
            event_type='SYSTEM_ALERT',
            description='Servicio de notificaciones iniciado',
            details={'service': 'notification_service'}
        )

        return True, "Servicio de notificaciones iniciado"

    def stop_service(self):
        """Detener el servicio de notificaciones"""
        if not self.is_running:
            return False, "El servicio no está ejecutándose"

        self.is_running = False

        if self.worker_thread and self.worker_thread.is_alive():
            self.worker_thread.join(timeout=5)

        # Log del evento
        event_logger.log_event(
            user=None,
            event_type='SYSTEM_ALERT',
            description='Servicio de notificaciones detenido',
            details={'service': 'notification_service'}
        )

        return True, "Servicio de notificaciones detenido"

    def send_notification(self, notification, channels=None, priority=1, scheduled_at=None):
        """
        Enviar notificación a través de múltiples canales

        Args:
            notification: Instancia de Notification
            channels: Lista de NotificationChannel (opcional)
            priority: Prioridad (1-5, 5 es más alta)
            scheduled_at: Fecha de envío programado
        """
        if channels is None:
            # Obtener canales activos por defecto
            channels = NotificationChannel.objects.filter(is_active=True)

        # Obtener configuración
        settings_obj, _ = NotificationSettings.objects.get_or_create(
            defaults={'enable_async_processing': True}
        )

        for channel in channels:
            # Crear entrada en cola
            queue_item = NotificationQueue.objects.create(
                notification=notification,
                channel=channel,
                user=notification.user,
                priority=min(max(priority, 1), 5),
                scheduled_at=scheduled_at,
                max_retries=settings_obj.max_retries
            )

            # Si no es programado y el procesamiento asíncrono está habilitado, procesar inmediatamente
            if not scheduled_at and settings_obj.enable_async_processing:
                # El worker se encargará de procesarlo
                pass
            else:
                # Procesar inmediatamente
                self._process_queue_item(queue_item)

    def _process_queue_worker(self):
        """Worker thread para procesamiento de cola"""
        while self.is_running:
            try:
                # Obtener elementos pendientes ordenados por prioridad
                pending_items = NotificationQueue.objects.filter(
                    status='PENDING',
                    scheduled_at__isnull=True
                ).select_related('notification', 'channel', 'user').order_by('-priority', 'created_at')[:10]

                for item in pending_items:
                    with self.queue_lock:
                        if not self.is_running:
                            break
                        self._process_queue_item(item)

                # Dormir un poco antes de la siguiente iteración
                time.sleep(1)

            except Exception as e:
                print(f"Error en worker de notificaciones: {e}")
                time.sleep(5)

    def _process_queue_item(self, queue_item):
        """Procesar un elemento de la cola"""
        try:
            # Marcar como procesando
            queue_item.status = 'PROCESSING'
            queue_item.save(update_fields=['status'])

            # Obtener plantilla apropiada
            template = NotificationTemplate.objects.filter(
                template_type=queue_item.channel.channel_type,
                event_type=queue_item.notification.event_type,
                is_active=True
            ).first()

            if template:
                # Renderizar contenido usando plantilla
                content = self._render_template(template, queue_item.notification)
            else:
                # Usar contenido básico
                content = {
                    'subject': queue_item.notification.title,
                    'body': queue_item.notification.message
                }

            # Enviar según el tipo de canal
            success = self._send_to_channel(queue_item.channel, content, queue_item.notification)

            if success:
                queue_item.status = 'SENT'
                queue_item.sent_at = timezone.now()
            else:
                queue_item.status = 'FAILED'
                queue_item.retry_count += 1

                # Reintentar si no se ha alcanzado el máximo
                if queue_item.retry_count < queue_item.max_retries:
                    queue_item.status = 'RETRY'
                    # Programar reintento con backoff exponencial
                    retry_delay = 60 * (2 ** queue_item.retry_count)  # 1min, 2min, 4min, etc.
                    queue_item.scheduled_at = timezone.now() + timezone.timedelta(seconds=retry_delay)

            queue_item.save()

            # Crear log
            NotificationLog.objects.create(
                notification=queue_item.notification,
                channel=queue_item.channel,
                user=queue_item.user,
                status=queue_item.status,
                channel_type=queue_item.channel.channel_type,
                sent_at=queue_item.sent_at,
                error_message='' if success else 'Error al enviar notificación'
            )

        except Exception as e:
            queue_item.status = 'FAILED'
            queue_item.error_message = str(e)
            queue_item.save()

            NotificationLog.objects.create(
                notification=queue_item.notification,
                channel=queue_item.channel,
                user=queue_item.user,
                status='FAILED',
                channel_type=queue_item.channel.channel_type,
                error_message=str(e)
            )

    def _render_template(self, template, notification):
        """Renderizar contenido usando plantilla"""
        # Variables disponibles en el contexto
        context = {
            'notification': notification,
            'user': notification.user,
            'title': notification.title,
            'message': notification.message,
            'event_type': notification.event_type,
            'created_at': notification.created_at,
        }

        # Agregar variables personalizadas de la plantilla
        if template.available_variables:
            for var_name, var_value in template.available_variables.items():
                context[var_name] = var_value

        # Renderizar asunto
        if template.subject_template:
            subject_template = Template(template.subject_template)
            subject = subject_template.render(Context(context))
        else:
            subject = notification.title

        # Renderizar cuerpo
        body_template = Template(template.body_template)
        body = body_template.render(Context(context))

        return {
            'subject': subject,
            'body': body
        }

    def _send_to_channel(self, channel, content, notification):
        """Enviar notificación a un canal específico"""
        try:
            if channel.channel_type == 'EMAIL':
                return self._send_email(channel, content, notification)
            elif channel.channel_type == 'SMS':
                return self._send_sms(channel, content, notification)
            elif channel.channel_type == 'SLACK':
                return self._send_slack(channel, content, notification)
            elif channel.channel_type == 'TEAMS':
                return self._send_teams(channel, content, notification)
            elif channel.channel_type == 'WEBHOOK':
                return self._send_webhook(channel, content, notification)
            elif channel.channel_type == 'BROWSER_PUSH':
                return self._send_push(channel, content, notification)
            else:
                return False
        except Exception as e:
            print(f"Error enviando a canal {channel.channel_type}: {e}")
            return False

    def _send_email(self, channel, content, notification):
        """Enviar notificación por email"""
        try:
            # Obtener configuración de email
            from .models import EmailConfiguration
            email_config = EmailConfiguration.objects.filter(is_active=True).first()

            if not email_config:
                return False

            # Enviar email
            send_mail(
                subject=content['subject'],
                message=content['body'],
                from_email=email_config.from_email,
                recipient_list=[notification.user.email],
                fail_silently=False
            )

            return True
        except Exception as e:
            print(f"Error enviando email: {e}")
            return False

    def _send_sms(self, channel, content, notification):
        """Enviar notificación por SMS"""
        # Implementación básica - requeriría integración con proveedor SMS
        print(f"SMS a {notification.user.username}: {content['body']}")
        return True

    def _send_slack(self, channel, content, notification):
        """Enviar notificación a Slack"""
        try:
            settings_obj, _ = NotificationSettings.objects.get_or_create()
            webhook_url = settings_obj.slack_webhook_url

            if not webhook_url:
                return False

            payload = {
                "channel": settings_obj.slack_default_channel,
                "text": f"*{content['subject']}*\n{content['body']}",
                "username": "VANT-SIEM"
            }

            response = requests.post(webhook_url, json=payload, timeout=10)
            return response.status_code == 200

        except Exception as e:
            print(f"Error enviando a Slack: {e}")
            return False

    def _send_teams(self, channel, content, notification):
        """Enviar notificación a Microsoft Teams"""
        try:
            settings_obj, _ = NotificationSettings.objects.get_or_create()
            webhook_url = settings_obj.teams_webhook_url

            if not webhook_url:
                return False

            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "summary": content['subject'],
                "title": content['subject'],
                "text": content['body']
            }

            response = requests.post(webhook_url, json=payload, timeout=10)
            return response.status_code == 200

        except Exception as e:
            print(f"Error enviando a Teams: {e}")
            return False

    def _send_webhook(self, channel, content, notification):
        """Enviar notificación a webhook personalizado"""
        try:
            webhook_url = channel.config.get('url')
            if not webhook_url:
                return False

            payload = {
                'notification': {
                    'id': notification.id,
                    'title': content['subject'],
                    'message': content['body'],
                    'event_type': notification.event_type,
                    'user': notification.user.username,
                    'created_at': notification.created_at.isoformat()
                }
            }

            headers = {'Content-Type': 'application/json'}
            response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
            return response.status_code in [200, 201, 202]

        except Exception as e:
            print(f"Error enviando webhook: {e}")
            return False

    def _send_push(self, channel, content, notification):
        """Enviar notificación push al navegador"""
        # Implementación básica - requeriría integración con service worker
        print(f"Push notification a {notification.user.username}: {content['subject']}")
        return True

    def cleanup_old_notifications(self):
        """Limpiar notificaciones antiguas"""
        try:
            settings_obj, _ = NotificationSettings.objects.get_or_create()

            # Calcular fecha límite
            cutoff_date = timezone.now() - timezone.timedelta(days=settings_obj.cleanup_days)

            # Eliminar notificaciones antiguas
            deleted_count = Notification.objects.filter(created_at__lt=cutoff_date).delete()

            # Log del evento
            event_logger.log_event(
                user=None,
                event_type='SYSTEM_ALERT',
                description=f'Limpieza de notificaciones completada: {deleted_count} eliminadas',
                details={'deleted_count': deleted_count[0] if isinstance(deleted_count, tuple) else deleted_count}
            )

            return True, f"{deleted_count} notificaciones eliminadas"

        except Exception as e:
            return False, str(e)

    def get_queue_stats(self):
        """Obtener estadísticas de la cola"""
        from django.db.models import Count

        stats = NotificationQueue.objects.aggregate(
            pending=Count('id', filter=models.Q(status='PENDING')),
            processing=Count('id', filter=models.Q(status='PROCESSING')),
            sent=Count('id', filter=models.Q(status='SENT')),
            failed=Count('id', filter=models.Q(status='FAILED')),
            retry=Count('id', filter=models.Q(status='RETRY')),
        )

        return {
            'pending': stats['pending'] or 0,
            'processing': stats['processing'] or 0,
            'sent': stats['sent'] or 0,
            'failed': stats['failed'] or 0,
            'retry': stats['retry'] or 0,
            'total': sum(stats.values()) or 0
        }


# Instancia global del servicio
enhanced_notification_service = EnhancedNotificationService()