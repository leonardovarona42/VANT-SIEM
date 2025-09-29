import json
import os
from datetime import datetime
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
import threading

class EventLogger:
    """Sistema de logging de eventos para VANT-SIEM - Solo controlable por superusuarios"""
    
    def __init__(self):
        self.log_file = os.path.join(settings.BASE_DIR, 'logs', 'eventos.json')
        self.lock = threading.Lock()
        self.is_enabled = True  # Estado del sistema de logging
        self._ensure_log_file()
    
    def _ensure_log_file(self):
        """Asegurar que el archivo de log existe"""
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
    
    def _read_logs(self):
        """Leer logs existentes"""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            # Si hay error de codificación, recrear el archivo
            self._recreate_log_file()
            return []
    
    def _recreate_log_file(self):
        """Recrear el archivo de logs si hay problemas de codificación"""
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
        except Exception:
            # Si no se puede escribir, crear un archivo vacío
            with open(self.log_file, 'w', encoding='utf-8') as f:
                f.write('[]')
    
    def _write_logs(self, logs):
        """Escribir logs al archivo"""
        try:
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(logs, f, ensure_ascii=False, indent=2)
        except Exception as e:
            # Si hay error al escribir, intentar recrear el archivo
            print(f"Error escribiendo logs: {e}")
            self._recreate_log_file()
            try:
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    json.dump(logs, f, ensure_ascii=False, indent=2)
            except Exception:
                # Si aún falla, crear archivo vacío
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    f.write('[]')
    
    def start_logging(self, user):
        """Iniciar el sistema de logging (solo superusuarios)"""
        if not user or not user.is_superuser:
            return False, "Solo los superusuarios pueden iniciar el sistema de logging"
        
        if self.is_enabled:
            return False, "El sistema de logging ya está activo"
        
        self.is_enabled = True
        
        # Log del evento de inicio
        self.log_event(
            user=user,
            event_type='LOGGING_SYSTEM_STARTED',
            description=f'Sistema de logging iniciado por {user.username}',
            details={'action': 'start_logging'}
        )
        
        return True, "Sistema de logging iniciado correctamente"
    
    def stop_logging(self, user):
        """Detener el sistema de logging (solo superusuarios)"""
        if not user or not user.is_superuser:
            return False, "Solo los superusuarios pueden detener el sistema de logging"
        
        if not self.is_enabled:
            return False, "El sistema de logging ya está detenido"
        
        # Log del evento de parada antes de detener
        self.log_event(
            user=user,
            event_type='LOGGING_SYSTEM_STOPPED',
            description=f'Sistema de logging detenido por {user.username}',
            details={'action': 'stop_logging'}
        )
        
        self.is_enabled = False
        return True, "Sistema de logging detenido correctamente"
    
    def get_logging_status(self, user):
        """Obtener el estado del sistema de logging"""
        if not user or not user.is_superuser:
            return None, "Solo los superusuarios pueden consultar el estado del sistema de logging"
        
        return {
            'is_enabled': self.is_enabled,
            'log_file': self.log_file,
            'total_events': len(self._read_logs())
        }, "Estado obtenido correctamente"
    
    def log_event(self, user, event_type, description, details=None, target_model=None, target_id=None):
        """
        Registrar un evento en el sistema de logs
        
        Args:
            user: Usuario que realizó la acción
            event_type: Tipo de evento (CREATE, UPDATE, DELETE, LOGIN, LOGOUT, etc.)
            description: Descripción del evento
            details: Detalles adicionales del evento
            target_model: Modelo afectado (opcional)
            target_id: ID del objeto afectado (opcional)
        """
        # Solo registrar si el sistema está habilitado
        if not self.is_enabled:
            return
        
        with self.lock:
            logs = self._read_logs()
            
            event = {
                'id': len(logs) + 1,
                'timestamp': timezone.now().isoformat(),
                'user': {
                    'id': user.id if user else None,
                    'username': user.username if user else 'Anonymous',
                    'email': user.email if user else None,
                    'is_superuser': user.is_superuser if user else False,
                    'is_staff': user.is_staff if user else False,
                },
                'event_type': event_type,
                'description': description,
                'details': details or {},
                'target_model': target_model,
                'target_id': target_id,
                'ip_address': None,  # Se puede agregar si se necesita
                'user_agent': None,  # Se puede agregar si se necesita
            }
            
            logs.append(event)
            
            # Mantener solo los últimos 10000 eventos para evitar archivos muy grandes
            if len(logs) > 10000:
                logs = logs[-10000:]
            
            self._write_logs(logs)
            
            # Crear notificación si es necesario
            self._create_notification_if_needed(event)
    
    def _create_notification_if_needed(self, event):
        """Crear notificación basada en el tipo de evento"""
        from .models import Notification
        
        # Eventos que requieren notificación al superusuario
        admin_events = ['USER_CREATE_REQUEST', 'USER_APPROVAL_REQUEST', 'CRITICAL_OPERATION']
        
        if event['event_type'] in admin_events:
            # Notificar a todos los superusuarios
            superusers = User.objects.filter(is_superuser=True)
            for superuser in superusers:
                Notification.objects.create(
                    user=superuser,
                    title=f"Nueva {event['event_type'].replace('_', ' ').title()}",
                    message=event['description'],
                    event_type=event['event_type'],
                    is_read=False
                )
    
    def get_recent_events(self, limit=50):
        """Obtener eventos recientes"""
        logs = self._read_logs()
        return logs[-limit:] if logs else []
    
    def get_events_by_user(self, user_id, limit=50):
        """Obtener eventos de un usuario específico"""
        logs = self._read_logs()
        user_events = [log for log in logs if log['user']['id'] == user_id]
        return user_events[-limit:] if user_events else []
    
    def get_events_by_type(self, event_type, limit=50):
        """Obtener eventos por tipo"""
        logs = self._read_logs()
        type_events = [log for log in logs if log['event_type'] == event_type]
        return type_events[-limit:] if type_events else []

# Instancia global del logger
event_logger = EventLogger()
