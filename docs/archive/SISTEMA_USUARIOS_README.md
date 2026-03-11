# Sistema de Gestión de Usuarios y Notificaciones - Vigilance & Neutralization threads SIEM

## 🚀 Características Implementadas

### 1. **Sistema de Gestión de Usuarios con Aprobación**
- ✅ **Creación de Usuarios**: Los usuarios pueden solicitar la creación de nuevas cuentas
- ✅ **Aprobación de Superusuarios**: Solo los superusuarios pueden aprobar/rechazar solicitudes
- ✅ **Estados de Solicitud**: Pendiente, Aprobado, Rechazado
- ✅ **Información Completa**: Username, email, nombre, apellidos, permisos de staff/superuser

### 2. **Sistema de Permisos Granular**
- ✅ **17 Tipos de Permisos**: Desde ver reportes hasta gestionar permisos
- ✅ **Control Individual**: Cada usuario puede tener permisos específicos
- ✅ **Interfaz Visual**: Switches para activar/desactivar permisos
- ✅ **Auditoría**: Registro de quién otorgó cada permiso y cuándo

### 3. **Sistema de Notificaciones en Tiempo Real**
- ✅ **Campanita en Navbar**: Indicador visual de notificaciones no leídas
- ✅ **Actualización Automática**: Cada 5 segundos
- ✅ **Tipos de Notificaciones**: 8 tipos diferentes (creación de usuarios, operaciones críticas, etc.)
- ✅ **Gestión Completa**: Marcar como leídas, ver historial, marcar todas como leídas

### 4. **Sistema de Logging Avanzado**
- ✅ **Logs en JSON**: Almacenamiento en `logs/eventos.json`
- ✅ **Logging Automático**: Middleware que registra todas las operaciones
- ✅ **Información Detallada**: Usuario, timestamp, tipo de evento, detalles, IP, etc.
- ✅ **Filtros Avanzados**: Por tipo de evento, usuario, fecha, límite de resultados
- ✅ **Vista de Detalles**: Modal con información completa de cada evento

### 5. **Interfaz de Usuario Profesional**
- ✅ **Dashboard Integrado**: Todas las funcionalidades accesibles desde el navbar
- ✅ **Tema Consistente**: Diseño oscuro profesional para sistemas SIEM
- ✅ **Responsive Design**: Adaptable a todos los dispositivos
- ✅ **Iconos FontAwesome**: Indicadores visuales claros
- ✅ **Bootstrap 5**: Componentes modernos y funcionales

## 📁 Estructura de Archivos Creados

```
VANT_SIEM/
├── models.py                 # Modelos: Notification, UserPermission, UserApprovalRequest, NotificationPreference
├── views.py                  # Vistas para gestión de usuarios, notificaciones y logs, dashboards IDS
├── urls.py                   # URLs del sistema
├── middleware.py             # Middleware para logging automático
├── logging_system.py         # Sistema de logging en JSON
└── templates/
    ├── user_management.html      # Gestión de usuarios y solicitudes
    ├── create_user_request.html  # Formulario de solicitud de usuario
    ├── user_permissions.html     # Gestión de permisos por usuario
    ├── notifications.html        # Vista de notificaciones
    ├── system_logs.html          # Vista de logs del sistema
    ├── threats_dashboard.html    # Dashboard general de amenazas IDS/IPS
    └── vendor_dashboard.html     # Dashboard específico (Snort o Suricata)

logs/
└── eventos.json             # Archivo de logs en formato JSON
```

## 🔧 Funcionalidades Técnicas

### **Sistema de Logging**
- **Archivo JSON**: `logs/eventos.json` con estructura optimizada
- **Rotación Automática**: Mantiene solo los últimos 10,000 eventos
- **Thread-Safe**: Uso de locks para escritura concurrente
- **Eventos Registrados**: Login, logout, CRUD operations, gestión de usuarios, etc.

### **Sistema de Notificaciones**
- **APIs REST**: Endpoints para obtener, marcar como leídas
- **Actualización AJAX**: Sin recargar la página
- **Badge Dinámico**: Contador de notificaciones no leídas
- **Tipos Configurables**: 8 tipos de notificaciones diferentes

### **Sistema de Permisos**
- **Granularidad**: 17 tipos de permisos específicos
- **AJAX Updates**: Cambios en tiempo real sin recargar
- **Auditoría Completa**: Registro de quién otorgó cada permiso
- **Validación**: Verificación de permisos en cada operación

## 🎯 URLs Implementadas

### **Gestión de Usuarios**
- `/users/` - Lista de usuarios y solicitudes
- `/users/create-request/` - Crear solicitud de usuario
- `/users/approve/<id>/` - Aprobar solicitud
- `/users/reject/<id>/` - Rechazar solicitud
- `/users/<id>/permissions/` - Gestionar permisos

### **Notificaciones**
- `/notifications/` - Vista de notificaciones
- `/api/notifications/` - API para obtener notificaciones
- `/notifications/<id>/read/` - Marcar como leída
- `/notifications/mark-all-read/` - Marcar todas como leídas

### **Logs**
- `/logs/` - Vista de logs del sistema

## 🔐 Seguridad Implementada

### **Control de Acceso**
- ✅ **Verificación de Superusuario**: Solo superusuarios pueden gestionar usuarios
- ✅ **Permisos Granulares**: Control específico por funcionalidad
- ✅ **Logging de Seguridad**: Registro de todos los cambios de permisos
- ✅ **Validación de Datos**: Verificación de duplicados y datos válidos

### **Auditoría**
- ✅ **Logs Completos**: Todas las operaciones registradas
- ✅ **Información de Usuario**: IP, user agent, timestamp
- ✅ **Trazabilidad**: Seguimiento completo de cambios
- ✅ **Retención**: Mantenimiento de historial de eventos

## 🚀 Cómo Usar el Sistema

### **1. Crear Usuario**
1. Ir a **Settings** en el navbar
2. Hacer clic en **"Crear Usuario"**
3. Llenar el formulario con los datos del usuario
4. La solicitud se envía para aprobación

### **2. Aprobar/Rechazar Usuarios**
1. En **Settings** → **Solicitudes Pendientes**
2. Ver la lista de solicitudes
3. Hacer clic en **✓** para aprobar o **✗** para rechazar
4. El usuario recibe notificación del resultado

### **3. Gestionar Permisos**
1. En **Settings** → **Usuarios Activos**
2. Hacer clic en el icono de **🔑** junto al usuario
3. Activar/desactivar permisos con los switches
4. Los cambios se aplican inmediatamente

### **4. Ver Notificaciones**
1. Hacer clic en la **🔔** en el navbar
2. Ver notificaciones no leídas (marcadas en amarillo)
3. Hacer clic en una notificación para marcarla como leída
4. Usar **"Marcar Todas como Leídas"** para limpiar todas

### **5. Revisar Logs**
1. En **Settings** → **Logs del Sistema** (solo superusuarios)
2. Usar filtros para encontrar eventos específicos
3. Hacer clic en **👁** para ver detalles completos
4. Exportar o analizar patrones de actividad

## 🎨 Características Visuales

### **Dashboard SIEM Profesional**
- **Tema Oscuro**: Perfecto para sistemas de seguridad
- **Colores Corporativos**: Azul, amarillo, rojo para diferentes estados
- **Iconos Intuitivos**: FontAwesome para mejor UX
- **Responsive**: Funciona en desktop, tablet y móvil

### **Indicadores Visuales**
- **Badges de Estado**: Colores para diferentes tipos de eventos
- **Contadores Dinámicos**: Número de notificaciones no leídas
- **Animaciones Suaves**: Transiciones y efectos hover
- **Feedback Inmediato**: Toasts y mensajes de confirmación

## 🔄 Integración con EVENT_M

El sistema está completamente integrado con el módulo EVENT_M:
- **Logging Automático**: Todas las operaciones CRUD se registran
- **Notificaciones**: Eventos importantes generan notificaciones
- **Permisos**: Control granular sobre cada funcionalidad
- **Auditoría**: Seguimiento completo de cambios en datos

## 📊 Métricas y Monitoreo

### **Dashboard en Tiempo Real**
- **Gráficos Dinámicos**: Chart.js con actualización automática
- **Métricas de Seguridad**: Reportes, incidentes, involucrados
- **Tendencias**: Análisis de patrones temporales
- **Alertas Visuales**: Indicadores de actividad reciente

### **Sistema de Alertas**
- **Notificaciones Automáticas**: Para eventos críticos
- **Configuración Flexible**: Usuarios pueden personalizar qué recibir
- **Escalación**: Superusuarios reciben todas las alertas importantes
- **Historial**: Mantenimiento de todas las notificaciones

---

## 🎯 Resultado Final

**Vigilance & Neutralization threads SIEM** ahora es un sistema SIEM empresarial completo con:
- ✅ **Gestión de Usuarios** con aprobación y permisos granulares
- ✅ **Sistema de Notificaciones** en tiempo real
- ✅ **Logging Avanzado** con auditoría completa
- ✅ **Interfaz Profesional** con dashboard dinámico
- ✅ **Seguridad Empresarial** con control de acceso
- ✅ **Monitoreo en Tiempo Real** con métricas y alertas

¡El sistema está listo para uso en producción! 🚀
