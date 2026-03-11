# Sistema Avanzado de Rotación de Logs

## 📋 Descripción General

El Sistema Avanzado de Rotación de Logs es una herramienta profesional integrada en Vigilance & Neutralization threads SIEM que permite gestionar eficientemente tanto los datos almacenados en la base de datos como los archivos de logs originales de Snort y Suricata.

## 🎯 Características Principales

### 🔄 Rotación de Base de Datos
- **Eliminación selectiva** de registros antiguos según criterios configurables
- **Períodos de retención** personalizables (7 días a 1 año)
- **Backup opcional** antes de la eliminación
- **Modo simulación** para preview seguro
- **Filtros avanzados** por tipo de datos (Snort, Suricata, Alertas, Todos)

### 📁 Rotación de Archivos
- **Gestión de archivos originales** de Snort y Suricata
- **Múltiples acciones**: Comprimir, Mover, Eliminar, Archivar
- **Preservación de estructura** de directorios
- **Directorios de destino** configurables
- **Escaneo inteligente** de archivos del sistema

### 📊 Herramientas de Mantenimiento
- **Optimización de BD**: Mejora rendimiento de consultas
- **Reconstrucción de índices**: Acelera búsquedas
- **Limpieza de temporales**: Libera espacio en disco
- **Generación de reportes**: Documentación automática

## 🚀 Acceso al Sistema

### URL de Acceso
```
http://localhost:8000/ids-ingest/service/
```

### Requisitos de Acceso
- **Usuario autenticado** con permisos de superusuario
- **Acceso administrativo** al módulo IDS/INGEST

## 📖 Guía de Uso

### 1. Rotación de Base de Datos

#### Acceso a la Funcionalidad
1. Ingresar al sistema con credenciales de administrador
2. Navegar a `/ids-ingest/service/`
3. Seleccionar la pestaña **"Base de Datos"**

#### Configuración de Parámetros

##### Tipo de Datos
- **Todos**: Afecta Snort, Suricata y Alertas
- **Solo Snort**: Solo registros de Snort
- **Solo Suricata**: Solo registros de Suricata
- **Solo Alertas**: Solo registros de alertas críticas

##### Período de Retención
- **7 días**: Retención mínima recomendada
- **14 días**: Balance entre espacio y utilidad
- **30 días**: Período estándar
- **90 días**: Retención extendida
- **180 días**: Para análisis históricos
- **1 año**: Retención máxima

##### Opciones Avanzadas
- **Crear backup**: Genera respaldo antes de eliminar
- **Simulación**: Muestra qué se eliminaría sin ejecutar

#### Ejecución
1. Configurar parámetros deseados
2. Hacer clic en **"Ejecutar Rotación DB"**
3. Confirmar la operación en el diálogo
4. Revisar resultados en el modal informativo

### 2. Rotación de Archivos del Sistema

#### Acceso a la Funcionalidad
1. Seleccionar la pestaña **"Sistema de Archivos"**

#### Configuración de Parámetros

##### Tipo de Archivo
- **Todos**: Snort y Suricata
- **Archivos Snort**: Solo logs de Snort
- **Archivos Suricata**: Solo logs de Suricata
- **Alertas**: Solo archivos de alertas
- **Logs**: Todos los archivos de logs

##### Acción a Realizar
- **Comprimir**: Reduce tamaño manteniendo archivos
- **Mover**: Traslada a directorio de backup
- **Eliminar**: Borra archivos permanentemente
- **Archivar**: Comprime y organiza por fecha

##### Directorio de Destino
- Ruta completa donde mover/archivar archivos
- Dejar vacío para usar directorio por defecto
- Compatible con rutas Windows y Linux

##### Opciones Avanzadas
- **Preservar estructura**: Mantiene jerarquía de directorios
- **Simulación**: Preview de operaciones

#### Ejecución
1. Configurar tipo de archivo y acción
2. Opcionalmente configurar directorio destino
3. Hacer clic en **"Ejecutar Rotación FS"**
4. Confirmar operación
5. Revisar estadísticas de archivos procesados

### 3. Herramientas de Mantenimiento

#### Optimización de Base de Datos
- **Ubicación**: Pestaña "Estadísticas" → "Optimizar DB"
- **Función**: Reorganiza tablas para mejor rendimiento
- **Tiempo estimado**: 30-60 segundos
- **Beneficio**: Hasta 15% mejora en consultas

#### Reconstrucción de Índices
- **Ubicación**: Pestaña "Estadísticas" → "Rebuild Indexes"
- **Función**: Recrear índices de búsqueda
- **Tiempo estimado**: 1-5 minutos
- **Beneficio**: Consultas más rápidas

#### Limpieza de Archivos Temporales
- **Ubicación**: Pestaña "Estadísticas" → "Limpiar Temp"
- **Función**: Eliminar archivos temporales del sistema
- **Beneficio**: Liberar espacio en disco

#### Generación de Reportes
- **Ubicación**: Pestaña "Estadísticas" → "Reporte"
- **Función**: Crear reporte descargable de operaciones
- **Formato**: Archivo de texto con estadísticas completas

## 🔧 Configuración Avanzada

### Variables de Entorno
```bash
# Directorio por defecto para backups
LOG_BACKUP_DIR=/var/backup/vant-siem

# Retención máxima permitida (días)
MAX_RETENTION_DAYS=365

# Tamaño máximo de archivos de log (MB)
MAX_LOG_SIZE_MB=100
```

### Permisos Requeridos
- **Lectura/Escritura** en directorios de logs
- **Acceso administrativo** a base de datos
- **Permisos de superusuario** en Django

## 📊 Monitoreo y Estadísticas

### Métricas Disponibles
- **Configuraciones activas**: Número total de servicios IDS
- **Archivos procesados**: Conteo por período de 24 horas
- **Espacio estimado**: Cálculo de uso de disco
- **Últimas operaciones**: Historial de rotaciones ejecutadas

### Dashboard de Estadísticas
- **Cards informativos**: Métricas clave visuales
- **Historial de operaciones**: Timeline de actividades
- **Alertas del sistema**: Notificaciones de mantenimiento

## ⚠️ Consideraciones de Seguridad

### Backup Obligatorio
- **Siempre crear backup** antes de rotaciones masivas
- **Verificar integridad** de backups generados
- **Probar restauración** periódicamente

### Permisos de Usuario
- **Solo superusuarios** pueden ejecutar rotaciones
- **Auditoría completa** de todas las operaciones
- **Confirmaciones explícitas** para acciones destructivas

### Validaciones de Seguridad
- **Verificación de rutas**: Previene acceso a directorios no autorizados
- **Límites de retención**: Evita eliminación accidental de datos recientes
- **Timeouts de operación**: Previene bloqueos del sistema

## 🔄 Automatización

### Tareas Programadas
```python
# En settings.py - Configuración de tareas periódicas
CELERY_BEAT_SCHEDULE = {
    'daily-log-rotation': {
        'task': 'ids_ingest.tasks.rotate_old_logs',
        'schedule': crontab(hour=2, minute=0),  # 2:00 AM diario
    },
    'weekly-db-optimization': {
        'task': 'ids_ingest.tasks.optimize_database',
        'schedule': crontab(hour=3, minute=0, day_of_week=0),  # Domingo 3:00 AM
    },
}
```

### Scripts de Automatización
```bash
# Rotación semanal automática
python manage.py rotate_logs --retention=7 --backup

# Optimización mensual
python manage.py optimize_db --full

# Limpieza diaria de temporales
python manage.py cleanup_temp --force
```

## 🐛 Solución de Problemas

### Problemas Comunes

#### Error de Permisos
```
Solución: Verificar permisos de usuario y directorios
```

#### Base de Datos Bloqueada
```
Solución: Cerrar conexiones activas antes de optimización
```

#### Archivos en Uso
```
Solución: Detener servicios IDS antes de rotación de archivos
```

#### Espacio Insuficiente
```
Solución: Liberar espacio o configurar directorio de backup alternativo
```

### Logs de Depuración
```bash
# Ver logs del sistema de rotación
tail -f logs/ids_ingest.log | grep rotation

# Logs de operaciones de BD
tail -f logs/django.log | grep "Database rotation"
```

## 📈 Mejores Prácticas

### Estrategias de Rotación
1. **Diaria**: Archivos temporales y logs operativos
2. **Semanal**: Datos de más de 7 días
3. **Mensual**: Optimización de base de datos
4. **Trimestral**: Reconstrucción completa de índices

### Monitoreo Continuo
- **Alertas automáticas** cuando el espacio es bajo
- **Reportes semanales** de uso del sistema
- **Auditoría de operaciones** de rotación

### Backup Strategy
- **Backups incrementales** diarios
- **Backups completos** semanales
- **Retención de backups** por 90 días
- **Verificación automática** de integridad

## 🔗 APIs y Endpoints

### Endpoints REST
```
POST /ids-ingest/service/rotate-database/
POST /ids-ingest/service/preview-db-rotation/
POST /ids-ingest/service/rotate-files/
POST /ids-ingest/service/scan-files/
POST /ids-ingest/service/preview-file-rotation/
POST /ids-ingest/service/optimize-db/
POST /ids-ingest/service/rebuild-indexes/
POST /ids-ingest/service/cleanup-temp/
POST /ids-ingest/service/generate-report/
POST /ids-ingest/service/rotation-history/
```

### Parámetros de API
```json
{
  "data_type": "all|snort|suricata|alerts",
  "retention_days": 30,
  "create_backup": true,
  "dry_run": false
}
```

## 📞 Soporte

### Contacto
- **Issues**: Crear issue en repositorio con tag `rotation-system`
- **Documentación**: Consultar este documento
- **Soporte técnico**: Contactar equipo de desarrollo

### Versiones Soportadas
- **Vigilance & Neutralization threads SIEM**: 1.0+
- **Django**: 5.0+
- **PostgreSQL**: 12+
- **Snort**: 2.9+, 3.0+
- **Suricata**: 6.0+

---

**Última actualización**: Diciembre 2025
**Versión del sistema**: 1.0.0