import time
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import User
from django.shortcuts import redirect
from django.conf import settings
from .logging_system import event_logger

class LoggingMiddleware(MiddlewareMixin):
    """Middleware para logging automático de eventos y protección de rutas"""
    
    def process_request(self, request):
        """Enforce auth and start timing for logging"""
        request._logging_start_time = time.time()
        
        # Protección de vistas: requerir autenticación salvo rutas permitidas
        path = request.path or ''
        allowed_prefixes = [
            '/siem/dashboard/login/',
            '/siem/login/',
            (settings.STATIC_URL or '/static/'),
            (getattr(settings, 'MEDIA_URL', '/media/') or '/media/'),
        ]
        is_allowed = any(path.startswith(pfx) for pfx in allowed_prefixes if pfx)
        
        if not request.user.is_authenticated and not is_allowed:
            return redirect('/siem/dashboard/login/')
        
        return None
    
    def process_response(self, request, response):
        """Procesar response y crear log si es necesario"""

        # Solo logear para usuarios autenticados
        if not getattr(request, 'user', None) or not request.user.is_authenticated:
            return response

        # Obtener información del request
        method = request.method
        path = request.path
        user = request.user

        # Excluir APIs de polling frecuente que no necesitan logging detallado
        excluded_paths = [
            '/siem/ids/api/notifications/',  # API de notificaciones (polling cada 5s)
            '/siem/dashboard/metrics/',      # Métricas del dashboard (polling frecuente)
            '/siem/incidentes/timeline/',    # Timeline de incidentes
        ]

        # Verificar si la ruta está excluida
        if any(excluded_path in path for excluded_path in excluded_paths):
            return response

        # Determinar tipo de evento basado en la URL y método
        event_type = self._get_event_type(method, path)

        if event_type:
            # Crear descripción del evento
            description = self._get_event_description(method, path, response.status_code)

            # Log del evento
            event_logger.log_event(
                user=user,
                event_type=event_type,
                description=description,
                details={
                    'method': method,
                    'path': path,
                    'status_code': response.status_code,
                    'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                    'ip_address': request.META.get('REMOTE_ADDR', ''),
                }
            )

        return response
    
    def _get_event_type(self, method, path):
        """Determinar el tipo de evento basado en el método y path"""
        # Eventos de autenticación
        if 'login' in path:
            return 'LOGIN'
        elif 'logout' in path:
            return 'LOGOUT'
        
        # Eventos de gestión de usuarios
        elif 'user-management' in path:
            if method == 'GET':
                return 'VIEW_USERS'
            elif method == 'POST':
                return 'USER_OPERATION'
        
        # Eventos de notificaciones
        elif 'notifications' in path:
            return 'NOTIFICATION_ACCESS'
        
        # Eventos de logs
        elif 'logs' in path:
            return 'LOG_ACCESS'
        
        # Eventos de permisos
        elif 'permissions' in path:
            return 'PERMISSION_ACCESS'
        
        # Eventos de EVENT_M (reportes, incidentes, etc.)
        elif 'eventos' in path:
            if 'reporte' in path:
                if method == 'POST':
                    return 'CREATE_REPORTE'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_REPORTE'
                elif method == 'DELETE':
                    return 'DELETE_REPORTE'
                else:
                    return 'VIEW_REPORTE'
            elif 'incidente' in path:
                if method == 'POST':
                    return 'CREATE_INCIDENTE'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_INCIDENTE'
                elif method == 'DELETE':
                    return 'DELETE_INCIDENTE'
                else:
                    return 'VIEW_INCIDENTE'
            elif 'categoria' in path:
                if method == 'POST':
                    return 'CREATE_CATEGORIA'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_CATEGORIA'
                elif method == 'DELETE':
                    return 'DELETE_CATEGORIA'
                else:
                    return 'VIEW_CATEGORIA'
            elif 'subcategoria' in path:
                if method == 'POST':
                    return 'CREATE_SUBCATEGORIA'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_SUBCATEGORIA'
                elif method == 'DELETE':
                    return 'DELETE_SUBCATEGORIA'
                else:
                    return 'VIEW_SUBCATEGORIA'
            elif 'servicio' in path:
                if method == 'POST':
                    return 'CREATE_SERVICIO'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_SERVICIO'
                elif method == 'DELETE':
                    return 'DELETE_SERVICIO'
                else:
                    return 'VIEW_SERVICIO'
            elif 'responsable' in path:
                if method == 'POST':
                    return 'CREATE_RESPONSABLE'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_RESPONSABLE'
                elif method == 'DELETE':
                    return 'DELETE_RESPONSABLE'
                else:
                    return 'VIEW_RESPONSABLE'
            elif 'area' in path:
                if method == 'POST':
                    return 'CREATE_AREA'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_AREA'
                elif method == 'DELETE':
                    return 'DELETE_AREA'
                else:
                    return 'VIEW_AREA'
            elif 'medida' in path:
                if method == 'POST':
                    return 'CREATE_MEDIDA'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_MEDIDA'
                elif method == 'DELETE':
                    return 'DELETE_MEDIDA'
                else:
                    return 'VIEW_MEDIDA'
            elif 'involucrado' in path:
                if method == 'POST':
                    return 'CREATE_INVOLUCRADO'
                elif method == 'PUT' or method == 'PATCH':
                    return 'UPDATE_INVOLUCRADO'
                elif method == 'DELETE':
                    return 'DELETE_INVOLUCRADO'
                else:
                    return 'VIEW_INVOLUCRADO'
        
        return None
    
    def _get_event_description(self, method, path, status_code):
        """Crear descripción del evento"""
        method_names = {
            'GET': 'consultó',
            'POST': 'creó',
            'PUT': 'actualizó',
            'PATCH': 'actualizó',
            'DELETE': 'eliminó'
        }
        
        action = method_names.get(method, 'accedió a')
        resource = path.split('/')[-2] if path.split('/')[-2] else path.split('/')[-1]
        
        if status_code >= 400:
            return f"Error {status_code} al {action} {resource}"
        else:
            return f"Usuario {action} {resource} exitosamente"
