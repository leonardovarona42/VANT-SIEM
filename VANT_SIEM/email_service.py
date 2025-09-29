"""
Servicio de envío de correos para VANT-SIEM
"""
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from django.conf import settings
from django.utils import timezone
from .models import EmailConfiguration, EmailAlert, EmailLog, User
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """Servicio para envío de correos del sistema"""
    
    def __init__(self):
        self.active_config = None
        self._load_active_config()
    
    def _load_active_config(self):
        """Cargar la configuración activa de correo"""
        try:
            self.active_config = EmailConfiguration.objects.filter(is_active=True).first()
        except Exception as e:
            logger.error(f"Error al cargar configuración de correo: {e}")
    
    def send_alert(self, user, alert_type, subject, body, priority='MEDIUM', context=None):
        """
        Enviar alerta por correo a un usuario específico
        
        Args:
            user: Usuario destinatario
            alert_type: Tipo de alerta
            subject: Asunto del correo
            body: Cuerpo del correo
            priority: Prioridad de la alerta
            context: Contexto adicional para la plantilla
        """
        if not self.active_config:
            logger.warning("No hay configuración de correo activa")
            return False
        
        # Verificar si el usuario tiene habilitada esta alerta
        try:
            alert_config = EmailAlert.objects.get(user=user, alert_type=alert_type)
            if not alert_config.enabled:
                logger.info(f"Alerta {alert_type} deshabilitada para usuario {user.username}")
                return False
        except EmailAlert.DoesNotExist:
            logger.info(f"No hay configuración de alerta {alert_type} para usuario {user.username}")
            return False
        
        # Crear log de correo
        email_log = EmailLog.objects.create(
            to_email=user.email,
            to_user=user,
            subject=subject,
            alert_type=alert_type,
            priority=priority,
            status='PENDING'
        )
        
        try:
            # Enviar correo
            success = self._send_email(user.email, subject, body)
            
            if success:
                email_log.status = 'SENT'
                email_log.sent_at = timezone.now()
                email_log.save()
                logger.info(f"Correo enviado exitosamente a {user.email}")
                return True
            else:
                email_log.status = 'FAILED'
                email_log.error_message = "Error desconocido al enviar correo"
                email_log.save()
                return False
                
        except Exception as e:
            email_log.status = 'FAILED'
            email_log.error_message = str(e)
            email_log.save()
            logger.error(f"Error al enviar correo a {user.email}: {e}")
            return False
    
    def _send_email(self, to_email, subject, body):
        """
        Enviar correo usando la configuración activa

        Args:
            to_email: Email destinatario
            subject: Asunto
            body: Cuerpo del correo
        """
        return self._send_email_with_timeout(to_email, subject, body, timeout=30)

    def _send_email_with_timeout(self, to_email, subject, body, timeout=30, config=None):
        """
        Enviar correo usando la configuración especificada (o activa) con timeout

        Args:
            to_email: Email destinatario
            subject: Asunto
            body: Cuerpo del correo
            timeout: Timeout en segundos para operaciones SMTP
            config: Configuración de correo a usar (si no se especifica, usa la activa)
        """
        if config is None:
            config = self.active_config

        if not config:
            return False

        try:
            # Crear mensaje
            msg = MIMEMultipart()
            msg['From'] = f"{config.from_name} <{config.from_email}>"
            msg['To'] = to_email
            msg['Subject'] = subject

            # Agregar cuerpo
            msg.attach(MIMEText(body, 'html'))

            # Configurar servidor SMTP con timeout
            if config.use_ssl:
                server = smtplib.SMTP_SSL(config.smtp_server, config.smtp_port, timeout=timeout)
            else:
                server = smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=timeout)
                if config.use_tls:
                    server.starttls()

            # Autenticación con timeout
            server.login(config.username, config.password)

            # Enviar correo
            text = msg.as_string()
            server.sendmail(config.from_email, to_email, text)
            server.quit()

            return True

        except smtplib.SMTPConnectError as e:
            logger.error(f"Error de conexión SMTP: {e}")
            return False
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"Error de autenticación SMTP: {e}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"Error SMTP general: {e}")
            return False
        except Exception as e:
            logger.error(f"Error en _send_email_with_timeout: {e}")
            return False
    
    def send_bulk_alert(self, alert_type, subject, body, priority='MEDIUM', context=None):
        """
        Enviar alerta a todos los usuarios que tengan habilitada esta alerta
        
        Args:
            alert_type: Tipo de alerta
            subject: Asunto del correo
            body: Cuerpo del correo
            priority: Prioridad de la alerta
            context: Contexto adicional
        """
        # Obtener usuarios que tienen habilitada esta alerta
        enabled_alerts = EmailAlert.objects.filter(
            alert_type=alert_type,
            enabled=True
        ).select_related('user')
        
        sent_count = 0
        failed_count = 0
        
        for alert_config in enabled_alerts:
            if self.send_alert(
                alert_config.user, 
                alert_type, 
                subject, 
                body, 
                priority, 
                context
            ):
                sent_count += 1
            else:
                failed_count += 1
        
        logger.info(f"Bulk alert enviado: {sent_count} exitosos, {failed_count} fallidos")
        return sent_count, failed_count
    
    def test_configuration(self, config_id=None):
        """
        Probar una configuración de correo enviando un correo de prueba

        Args:
            config_id: ID de la configuración a probar (si no se especifica, usa la activa)
        """
        if config_id:
            config = EmailConfiguration.objects.get(id=config_id)
        else:
            config = self.active_config

        if not config:
            return False, "No hay configuración de correo disponible"

        # Crear log previo de intento de envío de prueba
        email_log = EmailLog.objects.create(
            to_email=config.from_email,
            to_user=None,
            subject="VANT-SIEM - Prueba de Configuración",
            alert_type='SYSTEM_ERROR',
            priority='LOW',
            status='PENDING'
        )

        try:
            # Crear mensaje de prueba
            subject = "VANT-SIEM - Prueba de Configuración"
            body = """
            <html>
            <body>
                <h2>Prueba de Configuración de Correo</h2>
                <p>Este es un correo de prueba para verificar que la configuración de correo está funcionando correctamente.</p>
                <p><strong>Configuración:</strong> {}</p>
                <p><strong>Servidor SMTP:</strong> {}:{}</p>
                <p><strong>Fecha:</strong> {}</p>
                <hr>
                <p><em>VANT-SIEM - Sistema de Gestión de Incidentes de Seguridad</em></p>
            </body>
            </html>
            """.format(
                config.name,
                config.smtp_server,
                config.smtp_port,
                timezone.now().strftime("%d/%m/%Y %H:%M:%S")
            )

            # Enviar a la dirección configurada como remitente con timeout
            success = self._send_email_with_timeout(config.from_email, subject, body, timeout=10, config=config)

            if success:
                email_log.status = 'SENT'
                email_log.sent_at = timezone.now()
                email_log.save()
                return True, "Correo de prueba enviado exitosamente"
            else:
                email_log.status = 'FAILED'
                email_log.error_message = "Error al enviar correo de prueba"
                email_log.save()
                return False, "Error al enviar correo de prueba"

        except Exception as e:
            email_log.status = 'FAILED'
            email_log.error_message = str(e)
            email_log.save()
            return False, f"Error en prueba de configuración: {str(e)}"


# Instancia global del servicio
email_service = EmailService()


def send_user_alert(user, alert_type, subject, body, priority='MEDIUM', context=None):
    """
    Función helper para enviar alerta a un usuario específico
    """
    return email_service.send_alert(user, alert_type, subject, body, priority, context)


def send_system_alert(alert_type, subject, body, priority='MEDIUM', context=None):
    """
    Función helper para enviar alerta del sistema a todos los usuarios habilitados
    """
    return email_service.send_bulk_alert(alert_type, subject, body, priority, context)
