# 🔧 Sistema de Logging e Ingesta IDS (Snort/Suricata)

## 🚀 Características del Sistema

### **✅ Control Exclusivo de Superusuario**
- **Inicio Automático**: El sistema se inicia automáticamente al arrancar la aplicación
- **Control Restringido**: Solo los superusuarios pueden iniciar/detener el sistema
- **Interfaz Dedicada**: Panel de control exclusivo para superusuarios
- **Auditoría Completa**: Todos los cambios de estado se registran

### **✅ Funcionalidades Implementadas**

#### **1. Inicio Automático**
- El sistema se inicia automáticamente cuando Django arranca
- No requiere intervención manual para comenzar a funcionar
- Se inicializa en el estado "ACTIVO" por defecto

#### **2. Control de Superusuario**
- **Iniciar Sistema**: Botón para activar el logging
- **Detener Sistema**: Botón para desactivar el logging
- **Estado en Tiempo Real**: Indicador visual del estado actual
- **Confirmaciones**: Diálogos de confirmación para acciones críticas

#### **3. Interfaz de Control**
- **Panel Dedicado**: `/logging-control/` - Solo accesible por superusuarios
- **Estado Visual**: Badges de color para indicar estado (Verde=Activo, Rojo=Detenido)
- **Métricas**: Total de eventos registrados
- **Información del Sistema**: Detalles técnicos y características

#### **4. APIs de Control**
- **`/api/logging/start/`**: Iniciar sistema de logging
- **`/api/logging/stop/`**: Detener sistema de logging
- **`/api/logging/status/`**: Obtener estado actual del sistema

## 🛰️ Ingesta IDS en tiempo real

- Servicios internos controlables desde Settings → «Servicios IDS».
- Soporta:
  - Snort 2.9/3.0 (fast alerts por archivo y syslog UDP)
  - Suricata (EVE JSON por archivo)
- Auto-detección de separadores y formato de timestamp.
- Deduplicación por hash SHA-256 del log completo.
- Poda automática cada 4 horas del contenido ya ingerido en los archivos originales.

### Configuración rápida

1) Cree una configuración en: Amenazas IDS-IPS → Configuraciones IDS/IPS.
2) Inicie/Detenga el procesamiento en: Settings → Servicios IDS.
3) Ajuste ruta y patrón de archivos según su OS (Windows/Linux) y versión (Snort 2.9/3.0 o Suricata).

### Dashboards

- Dashboard general de amenazas.
- Dashboard Snort y Dashboard Suricata con estadísticas filtradas por vendor.

## 🔐 Seguridad y Permisos

### **Control de Acceso**
```python
# Solo superusuarios pueden controlar el sistema
if not user or not user.is_superuser:
    return False, "Solo los superusuarios pueden controlar el sistema de logging"
```

### **Auditoría de Cambios**
- **Evento de Inicio**: `LOGGING_SYSTEM_STARTED`
- **Evento de Parada**: `LOGGING_SYSTEM_STOPPED`
- **Registro Completo**: Usuario, timestamp, acción realizada

### **Validaciones**
- Verificación de permisos en cada operación
- Confirmaciones antes de acciones críticas
- Manejo de errores y mensajes informativos

## 🎯 Cómo Usar el Sistema

### **1. Acceder al Control de Logging**
1. Iniciar sesión como **superusuario**
2. Ir a **Settings** → **Logs del Sistema**
3. Hacer clic en **"Control de Logging"**

### **2. Controlar el Sistema**
1. **Ver Estado**: El panel muestra el estado actual (ACTIVO/DETENIDO)
2. **Iniciar**: Hacer clic en "Iniciar Sistema de Logging" (si está detenido)
3. **Detener**: Hacer clic en "Detener Sistema de Logging" (si está activo)
4. **Confirmar**: Confirmar la acción en el diálogo

### **3. Monitorear el Sistema**
- **Estado en Tiempo Real**: Se actualiza automáticamente cada 30 segundos
- **Total de Eventos**: Contador de eventos registrados
- **Archivo de Logs**: Ruta del archivo de logs

## 🔧 Configuración Técnica

### **Inicialización Automática**
```python
# En VANT_SIEM/apps.py
def ready(self):
    from .logging_system import event_logger
    print("🚀 VANT-SIEM: Sistema de logging inicializado automáticamente")
```

### **Estado del Sistema**
```python
class EventLogger:
    def __init__(self):
        self.is_enabled = True  # Estado del sistema de logging
        self.lock = threading.Lock()
        self._ensure_log_file()
```

### **Control de Estado**
```python
def log_event(self, user, event_type, description, details=None, target_model=None, target_id=None):
    # Solo registrar si el sistema está habilitado
    if not self.is_enabled:
        return
    # ... resto del código
```

## 📁 Archivos del Sistema

### **Archivos Principales**
- `VANT_SIEM/logging_system.py` - Lógica del sistema de logging
- `VANT_SIEM/views.py` - Vistas de control del sistema
- `VANT_SIEM/urls.py` - URLs del sistema de control
- `VANT_SIEM/templates/logging_control.html` - Interfaz de control

### **Archivos de Configuración**
- `VANT_SIEM/apps.py` - Configuración de la aplicación
- `CORE/settings.py` - Configuración de Django
- `VANT_SIEM/management/commands/init_logs.py` - Comando de inicialización

### **Archivos de Logs**
- `logs/eventos.json` - Archivo principal de logs
- `logs/` - Directorio de logs del sistema

## 🚨 Comandos de Gestión

### **Inicializar Sistema**
```bash
python manage.py init_logs
```

### **Verificar Estado**
```bash
python manage.py check
```

### **Ejecutar Servidor**
```bash
python manage.py runserver
```

## 🔄 Flujo de Funcionamiento

### **1. Inicio de la Aplicación**
1. Django carga la aplicación VANT_SIEM
2. Se ejecuta `VantSiemConfig.ready()`
3. Se inicializa el sistema de logging automáticamente
4. El sistema queda en estado "ACTIVO"

### **2. Operación Normal**
1. Los usuarios realizan acciones en el sistema
2. El middleware registra automáticamente los eventos
3. Los eventos se almacenan en `logs/eventos.json`
4. Se mantiene un máximo de 10,000 eventos

### **3. Control por Superusuario**
1. El superusuario accede al panel de control
2. Puede iniciar/detener el sistema según necesidad
3. Todos los cambios se registran en los logs
4. El estado se actualiza en tiempo real

## 🎨 Interfaz de Usuario

### **Panel de Control**
- **Estado Visual**: Badges de color para estado actual
- **Botones de Control**: Iniciar/Detener con confirmaciones
- **Métricas**: Total de eventos y información del sistema
- **Actualización Automática**: Estado se actualiza cada 30 segundos

### **Características Visuales**
- **Tema Oscuro**: Consistente con el diseño SIEM
- **Iconos Intuitivos**: FontAwesome para mejor UX
- **Feedback Inmediato**: Toasts de confirmación
- **Responsive**: Funciona en todos los dispositivos

## 🔍 Monitoreo y Auditoría

### **Eventos Registrados**
- **Inicio del Sistema**: `LOGGING_SYSTEM_STARTED`
- **Parada del Sistema**: `LOGGING_SYSTEM_STOPPED`
- **Operaciones de Usuario**: Login, logout, CRUD operations
- **Cambios de Permisos**: Modificaciones de permisos de usuario

### **Información de Auditoría**
- **Usuario**: Quién realizó la acción
- **Timestamp**: Cuándo se realizó
- **Tipo de Evento**: Qué tipo de acción
- **Detalles**: Información adicional del evento
- **IP y User Agent**: Información de la sesión

## 🚀 Beneficios del Sistema

### **Seguridad**
- **Control Restringido**: Solo superusuarios pueden modificar el sistema
- **Auditoría Completa**: Registro de todos los cambios
- **Validaciones**: Verificación de permisos en cada operación

### **Funcionalidad**
- **Inicio Automático**: No requiere intervención manual
- **Control Granular**: Iniciar/detener según necesidad
- **Monitoreo en Tiempo Real**: Estado actualizado automáticamente

### **Usabilidad**
- **Interfaz Intuitiva**: Panel de control fácil de usar
- **Feedback Visual**: Estado claro y comprensible
- **Confirmaciones**: Prevención de acciones accidentales

---

## 🎯 Resultado Final

**VANT-SIEM** ahora tiene un **sistema de logging completamente controlado por superusuarios** con:

- ✅ **Inicio Automático** al arrancar la aplicación
- ✅ **Control Exclusivo** de superusuarios
- ✅ **Interfaz Dedicada** para gestión del sistema
- ✅ **Auditoría Completa** de todos los cambios
- ✅ **Monitoreo en Tiempo Real** del estado del sistema
- ✅ **Seguridad Empresarial** con validaciones y permisos

¡El sistema está listo para uso en producción con control total del superusuario! 🚀
