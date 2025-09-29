# Manual de Usuario - VANT-SIEM CORE

## Introducción

VANT-SIEM CORE es una plataforma integral de Security Information and Event Management (SIEM) que proporciona herramientas completas para la gestión, análisis y respuesta a incidentes de seguridad. Este manual le guiará a través de todas las funcionalidades disponibles en el sistema.

## Inicio de Sesión

1. Acceda a la URL principal del sistema: `http://[servidor]/siem/login/`
2. Introduzca sus credenciales de usuario
3. Haga clic en "Iniciar Sesión"

### Recuperación de Contraseña
- Contacte a un administrador del sistema para restablecer su contraseña
- Los superusuarios pueden gestionar contraseñas desde el panel de administración

## Reporte Externo de Incidentes

Si no tiene acceso al sistema pero necesita reportar un incidente de seguridad, puede utilizar el formulario público de reporte externo:

### Acceso al Formulario Externo
- **URL**: `http://[servidor]/eventos/reporte_externo/`
- **No requiere autenticación**: Cualquier persona puede acceder y enviar reportes

### Envío de Reporte Externo
1. Complete el formulario con:
   - **Nombre del informante**: Su nombre completo
   - **Correo electrónico**: Para confirmación y seguimiento
   - **Área afectada**: Seleccione el área correspondiente
   - **Descripción detallada**: Incluya todos los detalles relevantes del incidente

2. Haga clic en "Enviar Reporte de Incidente"

3. Recibirá confirmación inmediata con el ID del reporte

### Características del Reporte Externo
- **Confidencialidad**: Los reportes son tratados de forma confidencial
- **Seguimiento**: Se le notificará sobre el progreso del reporte
- **Sin registro**: No requiere crear una cuenta en el sistema
- **Disponibilidad 24/7**: Accesible en cualquier momento

## Navegación Principal

### Dashboard General
- **URL**: `/siem/dashboard/`
- **Contenido**: Vista general del estado del sistema, estadísticas y alertas recientes
- **Funcionalidades**:
  - Resumen de incidentes activos
  - Estado de servicios monitoreados
  - Alertas de seguridad recientes
  - Métricas de rendimiento del sistema

### Gestión de Incidentes (EVENT_M)

#### Reportes de Seguridad
1. **Acceso**: Navegación → "Reportes" o `/event-m/reports/`
2. **Crear Reporte**:
   - Haga clic en "Nuevo Reporte"
   - Complete el formulario con:
     - Nombre del informante y email
     - Área afectada
     - Descripción detallada del incidente
3. **Estados de Reporte**:
   - **Nuevo**: Reporte recién creado
   - **Atendido**: Reporte en proceso de investigación
   - **Rechazado**: Reporte no válido o duplicado

#### Gestión de Incidentes
1. **Acceso**: `/event-m/incidents/`
2. **Crear Incidente**:
   - Desde un reporte: Haga clic en "Investigar" en un reporte
   - O directamente: "Nuevo Incidente"
3. **Estados del Incidente**:
   - **Nuevo**: Incidente creado
   - **Abierto**: En investigación activa
   - **Investigación**: Análisis detallado
   - **Mitigación**: Implementando soluciones
   - **Cerrado**: Incidente resuelto

#### Categorización
- **Categorías**: Clasificación general (ej: Acceso no autorizado, Malware)
- **Subcategorías**: Detalles específicos con nivel de peligrosidad (1-10)
- **Servicios**: Sistemas afectados con monitoreo opcional

#### Responsables y Áreas
- **Áreas**: Divisiones organizacionales con responsables asignados
- **Responsables**: Contactos con información completa (nombres, emails, teléfonos)
- **Medidas**: Acciones correctivas con seguimiento de cumplimiento

### Análisis IDS/IPS

#### Configuración de Fuentes
1. **Acceso**: `/ids-ingest/config/`
2. **Crear Configuración**:
   - **Tipo**: Snort o Suricata
   - **Ruta del Log**: Ubicación del archivo de log
   - **Formato**: Automático o específico
   - **Retención**: Días para mantener datos
3. **Activar/Desactivar**: Control de ingesta por configuración

#### Dashboards de Amenazas

##### Dashboard General
- **URL**: `/siem/dashboard/threats/`
- **Vista**: Eventos consolidados de todos los IDS
- **Filtros**: Por severidad, fecha, IP, protocolo

##### Dashboard Snort
- **URL**: `/ids-ingest/snort/`
- **Específico**: Eventos de Snort con métricas detalladas
- **Campos Adicionales**: TTL, TOS, flags TCP, etc.

##### Dashboard Suricata
- **URL**: `/ids-ingest/suricata/`
- **Específico**: Eventos de Suricata con análisis EVE JSON
- **Tipos**: Alertas, flujos, estadísticas, logs del sistema

#### Gestión de Alertas
- **Acceso**: `/ids-ingest/alerts/`
- **Funcionalidades**:
  - Visualización de alertas críticas
  - Reconocimiento de alertas
  - Historial de reconocimientos
  - Filtros por severidad y estado

#### Estadísticas
- **URL**: `/ids-ingest/statistics/`
- **Métricas**:
  - Eventos por severidad y día
  - Distribución por protocolo
  - IPs más activas
  - Tendencias temporales

### Sistema SIEM Principal

#### Gestión de Usuarios
**Solo Superusuarios**

1. **Solicitudes Pendientes**: `/users/`
   - Revisar solicitudes de nuevos usuarios
   - Aprobar o rechazar con justificación

2. **Usuarios Activos**: Gestión de usuarios existentes
   - Ver lista completa
   - Gestionar permisos individuales

3. **Permisos Granulares**:
   - Ver/Crear/Editar/Eliminar reportes
   - Ver/Crear/Editar/Eliminar incidentes
   - Gestionar usuarios y permisos
   - Acceso a dashboards y logs
   - Exportar datos

#### Notificaciones Mejoradas
- **Campanita en Navbar**: Indicador de notificaciones no leídas
- **Múltiples Canales**: Email, SMS, Slack, Teams, Webhooks, Push
- **Tipos de Notificación**:
  - Solicitudes de usuario
  - Operaciones críticas
  - Alertas del sistema
  - Eventos de seguridad
  - Alertas IDS/IPS
  - Reportes de monitoreo
- **Gestión**:
  - Marcar como leídas individualmente
  - Marcar todas como leídas
  - Historial completo
  - Preferencias por canal

#### Sistema de Logs
**Solo Superusuarios**
- **Acceso**: `/logs/` o Settings → "Logs del Sistema"
- **Filtros**: Por tipo de evento, usuario, fecha, IP
- **Detalles**: Vista modal con información completa
- **Auditoría**: Registro de todas las operaciones del sistema

#### Configuración de Correo
**Solo Superusuarios**
1. **Acceso**: `/email/config/`
2. **Configurar Servidor**:
   - Servidor SMTP y puerto
   - Credenciales de autenticación
   - Configuración TLS/SSL
3. **Alertas por Correo**:
   - Crear plantillas de alertas
   - Configurar destinatarios
   - Tipos de eventos a notificar

### Análisis de Amenazas

#### Configuración de APIs
**Solo Superusuarios**
1. **Acceso**: `/analysis/config/`
2. **Servicios Disponibles**:
   - **VirusTotal**: Análisis de hashes, URLs, dominios
   - **AbuseIPDB**: Consulta de reputación de IPs
   - **MacVendors**: Identificación de fabricante por MAC
3. **Configuración**:
   - Claves API para cada servicio
   - Activación/desactivación individual

#### Herramientas de Análisis
- **Análisis de IP**: `/analysis/ip/[IP]`
- **Análisis de MAC**: `/analysis/mac/[MAC]`
- **Análisis de Indicadores**: Búsqueda general
- **Reportes**: Resultados detallados con scores y reputación

### Monitoreo de Servicios

#### Configuración
**Solo Superusuarios**
1. **Acceso**: `/event-m/monitoring/config/`
2. **Parámetros**:
   - Intervalo de verificación (segundos)
   - Servicios a monitorear
   - Umbrales de alerta

#### Dashboard de Monitoreo
- **Estado Actual**: Servicios activos/inactivos
- **Latencia**: Tiempos de respuesta
- **Historial**: Gráfico de disponibilidad
- **Alertas**: Notificaciones automáticas

### Configuración del Sistema

#### Servicios IDS
**Solo Superusuarios**
- **Acceso**: Settings → "Servicios IDS"
- **Control**: Iniciar/detener ingesta automática
- **Estado**: Monitoreo en tiempo real
- **Estadísticas**: Eventos procesados por hora

#### Control de Logging
**Solo Superusuarios**
- **Acceso**: Settings → "Logs del Sistema" → "Control de Logging"
- **Estados**: Activo/Inactivo
- **Métricas**: Total de eventos registrados
- **Auditoría**: Registro de cambios de estado

#### Configuración de Notificaciones
**Solo Superusuarios**
- **Acceso**: Settings → "Notificaciones"
- **Configuración Global**:
  - Procesamiento asíncrono
  - Reintentos automáticos
  - Limpieza automática
- **Canales de Notificación**:
  - Email: Configuración SMTP
  - SMS: Proveedores como Twilio
  - Slack: Webhooks
  - Microsoft Teams: Webhooks
  - Push Notifications: VAPID keys
- **Plantillas**: Templates personalizables por tipo de evento
- **Estadísticas**: Métricas de envío y fallos

## Flujos de Trabajo Típicos

### Investigación de un Incidente

1. **Recepción del Reporte**
   - Usuario reporta incidente vía formulario
   - Notificación automática a analistas

2. **Creación del Incidente**
   - Analista revisa reporte
   - Crea incidente con detalles completos
   - Asigna responsables y medidas

3. **Investigación**
   - Consulta dashboards IDS/IPS
   - Análisis de logs relacionados
   - Consulta APIs externas (VirusTotal, etc.)
   - Documenta hallazgos

4. **Mitigación**
   - Implementa medidas correctivas
   - Actualiza estado del incidente
   - Notifica a interesados

5. **Cierre**
   - Verifica efectividad de medidas
   - Documenta lecciones aprendidas
   - Cierra incidente

### Respuesta a Amenaza IDS

1. **Detección**
   - Sistema IDS genera alerta
   - Notificación automática al SIEM

2. **Análisis**
   - Revisar detalles de la alerta
   - Correlacionar con otros eventos
   - Consultar reputación de IPs/MACs

3. **Acción**
   - Reconocer alerta
   - Implementar bloqueo si necesario
   - Crear incidente si requiere investigación

4. **Seguimiento**
   - Monitorear efectividad
   - Ajustar reglas IDS si necesario

## Permisos y Seguridad

### Niveles de Acceso
- **Usuario Básico**: Acceso limitado según permisos asignados
- **Analista**: Acceso a dashboards y creación de incidentes
- **Administrador**: Gestión de usuarios y configuraciones
- **Superusuario**: Control total del sistema

### Mejores Prácticas
- **Principio de Menor Privilegio**: Otorgar solo permisos necesarios
- **Auditoría**: Revisar logs regularmente
- **Actualizaciones**: Mantener contraseñas seguras
- **Reportes**: Documentar todos los incidentes

## Solución de Problemas

### Problemas Comunes

#### No puede acceder al sistema
- Verificar credenciales
- Contactar administrador para reset de contraseña
- Verificar conectividad de red

#### Dashboards no se actualizan
- Verificar configuración IDS activa
- Revisar rutas de archivos de log
- Comprobar permisos de lectura

#### Alertas no se envían
- Verificar configuración SMTP
- Revisar logs de correo
- Comprobar conectividad de red

#### APIs de análisis fallan
- Verificar claves API válidas
- Comprobar límites de rate
- Revisar conectividad a servicios externos

### Contacto de Soporte
- **Administrador del Sistema**: Para problemas técnicos
- **Equipo de Seguridad**: Para consultas sobre procedimientos
- **Desarrolladores**: Para bugs o mejoras del sistema

## Glosario

- **SIEM**: Security Information and Event Management
- **IDS**: Intrusion Detection System
- **IPS**: Intrusion Prevention System
- **EVE JSON**: Formato de log estructurado de Suricata
- **TTL**: Time To Live (campo IP)
- **TOS**: Type of Service (campo IP)
- **MAC**: Media Access Control address

---

**VANT-SIEM CORE** - Su aliado en la ciberseguridad empresarial.
