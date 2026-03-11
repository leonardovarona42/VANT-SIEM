"""
Signals para integración automática con Ollama
"""
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from opensearch_ui.models import IDSAlert
from .models import OllamaConfig
from .ollama_service import ollama_service
from .logging_system import event_logger

@receiver(post_save, sender=IDSAlert)
def handle_new_alert(sender, instance, created, **kwargs):
    """
    Manejar alertas nuevas y generar reportes automáticos si está configurado
    """
    if not created:
        return

    try:
        # Obtener configuración activa de Ollama
        config = OllamaConfig.get_active_config()
        if not config or not config.is_active or not config.auto_generate_reports:
            return

        # Verificar si supera los umbrales
        recent_alerts = IDSAlert.objects.filter(
            timestamp__gte=timezone.now() - timezone.timedelta(hours=1),
            acknowledged=False
        ).count()

        should_generate = False
        if instance.severity == 'Critical' and recent_alerts >= config.alert_threshold_critical:
            should_generate = True
        elif instance.severity == 'High' and recent_alerts >= config.alert_threshold_high:
            should_generate = True

        if should_generate:
            # Generar reporte usando Ollama
            report_result = ollama_service.generate_threat_report(hours=1)

            if report_result.get('success'):
                # Log del evento automático
                event_logger.log_event(
                    user=None,  # Sistema
                    event_type='AUTO_AI_REPORT',
                    description=f'Reporte IA automático generado por alerta crítica: {instance.message[:100]}',
                    details={
                        'alert_id': instance.id,
                        'alert_severity': instance.severity,
                        'alert_count': recent_alerts,
                        'report_generated': True
                    }
                )

                # Enviar email si está configurado
                if config.auto_send_emails:
                    try:
                        from .email_service import send_system_alert

                        subject = f"VANT-SIEM - Reporte IA Automático: Alerta {instance.severity}"
                        body = f"""
                        <html>
                        <body>
                            <h2>Reporte Automático de IA - Alerta Crítica Detectada</h2>
                            <p><strong>Alerta Original:</strong> {instance.message}</p>
                            <p><strong>Severidad:</strong> {instance.severity}</p>
                            <p><strong>IP Origen:</strong> {instance.src_ip}</p>
                            <p><strong>IP Destino:</strong> {instance.dst_ip}</p>
                            <p><strong>Alertas Recientes:</strong> {recent_alerts}</p>

                            <h3>Análisis de IA</h3>
                            <p>{report_result.get('report', {}).get('executive_summary', 'Análisis generado automáticamente')}</p>

                            <h3>Recomendaciones</h3>
                            <ul>
                        """

                        recommendations = report_result.get('report', {}).get('recommendations', [])
                        if isinstance(recommendations, list):
                            for rec in recommendations[:3]:
                                body += f"<li>{rec}</li>"
                        else:
                            body += f"<li>{recommendations}</li>"

                        body += f"""
                            </ul>

                            <hr>
                            <p><em>Reporte generado automáticamente por VANT-SIEM con análisis de IA</em></p>
                        </body>
                        </html>
                        """

                        # Enviar a todos los superusuarios
                        from django.contrib.auth.models import User
                        superusers = User.objects.filter(is_superuser=True, is_active=True)
                        for user in superusers:
                            send_system_alert(
                                user=user,
                                alert_type='AUTO_AI_REPORT',
                                subject=subject,
                                body=body,
                                priority='HIGH'
                            )

                    except Exception as e:
                        event_logger.log_event(
                            user=None,
                            event_type='AUTO_EMAIL_FAILED',
                            description=f'Error enviando email automático: {str(e)}',
                            details={'alert_id': instance.id}
                        )

                # Crear incidente automáticamente si está configurado
                if config.auto_create_incidents:
                    try:
                        from EVENT_M.models import Incidente, Categoria

                        # Buscar categoría de seguridad
                        categoria_seguridad = Categoria.objects.filter(nombre__icontains='seguridad').first()
                        if not categoria_seguridad:
                            categoria_seguridad = Categoria.objects.filter(nombre__icontains='ciber').first()
                        if not categoria_seguridad:
                            categoria_seguridad = Categoria.objects.first()

                        # Crear incidente
                        incidente = Incidente.objects.create(
                            titulo=f"Incidente Automático: {instance.message[:100]}",
                            descripcion=f"""
                            Incidente creado automáticamente por sistema de IA basado en alerta crítica.

                            Alerta Original: {instance.message}
                            Severidad: {instance.severity}
                            IP Origen: {instance.src_ip}
                            IP Destino: {instance.dst_ip}

                            Análisis de IA: {report_result.get('report', {}).get('executive_summary', 'Análisis generado automáticamente')}

                            Recomendaciones: {', '.join(report_result.get('report', {}).get('recommendations', [])[:3])}
                            """,
                            estado='ABIERTO',
                            prioridad='ALTA',
                            categoria=categoria_seguridad,
                            creado_por=None  # Sistema
                        )

                        event_logger.log_event(
                            user=None,
                            event_type='AUTO_INCIDENT_CREATED',
                            description=f'Incidente automático creado por IA: {incidente.titulo}',
                            details={
                                'alert_id': instance.id,
                                'incident_id': incidente.id,
                                'categoria': categoria_seguridad.nombre if categoria_seguridad else 'N/A'
                            },
                            target_model='Incidente',
                            target_id=incidente.id
                        )

                    except Exception as e:
                        event_logger.log_event(
                            user=None,
                            event_type='AUTO_INCIDENT_FAILED',
                            description=f'Error creando incidente automático: {str(e)}',
                            details={'alert_id': instance.id}
                        )

    except Exception as e:
        # Log de error pero no fallar la creación de la alerta
        try:
            event_logger.log_event(
                user=None,
                event_type='AUTO_AI_ERROR',
                description=f'Error en procesamiento automático de IA: {str(e)}',
                details={'alert_id': instance.id}
            )
        except:
            pass  # Evitar loops de error
