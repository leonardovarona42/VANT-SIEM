# Arquitectura y Diagramas de Flujo - VANT-SIEM CORE

## Diagrama General de Arquitectura

```mermaid
graph TB
    subgraph "Usuarios"
        U1[👤 Usuario Regular]
        U2[👨‍💼 Analista]
        U3[👑 Superusuario]
    end

    subgraph "Interfaz Web - Django"
        WEB[🌐 Django Web Interface]
        subgraph "Aplicaciones Django"
            CORE[(CORE<br/>Configuración)]
            EVENT_M[(EVENT_M<br/>Gestión de Incidentes)]
            VANT_SIEM[(VANT_SIEM<br/>SIEM Principal)]
            IDS_INGEST[(ids_ingest<br/>Procesamiento IDS)]
        end
    end

    subgraph "Base de Datos"
        DB[(PostgreSQL<br/>Base de Datos)]
    end

    subgraph "Fuentes de Datos"
        IDS1[🔍 Snort 2.9/3.0]
        IDS2[🔍 Suricata]
        LOGS[📄 Archivos de Log]
    end

    subgraph "APIs Externas"
        VT[🔗 VirusTotal]
        AB[🔗 AbuseIPDB]
        MAC[🔗 MacVendors]
    end

    subgraph "Servicios del Sistema"
        EMAIL[📧 Servicio de Correo]
        LOGGING[📝 Sistema de Logging]
        MONITOR[📊 Monitoreo de Servicios]
    end

    U1 --> WEB
    U2 --> WEB
    U3 --> WEB

    WEB --> CORE
    WEB --> EVENT_M
    WEB --> VANT_SIEM
    WEB --> IDS_INGEST

    CORE --> DB
    EVENT_M --> DB
    VANT_SIEM --> DB
    IDS_INGEST --> DB

    IDS_INGEST --> IDS1
    IDS_INGEST --> IDS2
    IDS_INGEST --> LOGS

    VANT_SIEM --> VT
    VANT_SIEM --> AB
    VANT_SIEM --> MAC

    VANT_SIEM --> EMAIL
    VANT_SIEM --> LOGGING
    EVENT_M --> MONITOR

    style WEB fill:#e1f5fe
    style DB fill:#f3e5f5
    style IDS1 fill:#e8f5e8
    style IDS2 fill:#e8f5e8
```

## Flujo de Gestión de Incidentes

```mermaid
flowchart TD
    A[👤 Usuario Reporta Incidente] --> B{¿Es válido?}
    B -->|Sí| C[Crear Reporte<br/>Estado: Nuevo]
    B -->|No| D[Rechazar Reporte]

    C --> E[Analista Revisa Reporte]
    E --> F{¿Requiere<br/>Investigación?}
    F -->|Sí| G[Crear Incidente<br/>Estado: Nuevo]
    F -->|No| H[Marcar Atendido]

    G --> I[Asignar Responsables<br/>Estado: Abierto]
    I --> J[Investigación Activa<br/>Estado: Investigación]

    J --> K{¿Amenaza<br/>Confirmada?}
    K -->|Sí| L[Implementar Medidas<br/>Estado: Mitigación]
    K -->|No| M[Cerrar Incidente<br/>Estado: Cerrado]

    L --> N{¿Medidas<br/>Efectivas?}
    N -->|Sí| O[Cerrar Incidente<br/>Estado: Cerrado]
    N -->|No| P[Revisar Medidas]

    P --> L

    style A fill:#e3f2fd
    style G fill:#fff3e0
    style L fill:#e8f5e8
    style O fill:#c8e6c9
```

## Flujo de Procesamiento IDS/IPS

```mermaid
flowchart TD
    A[📄 Archivo de Log<br/>Snort/Suricata] --> B[👀 Verificar Cambios]
    B --> C{¿Hay Nuevos<br/>Eventos?}

    C -->|Sí| D[📖 Leer Nuevos Eventos]
    C -->|No| E[⏳ Esperar<br/>Intervalo]

    D --> F[🔍 Parser Específico<br/>por IDS]
    F --> G{¿Formato<br/>Válido?}

    G -->|Sí| H[📊 Extraer Metadatos<br/>IP, Puerto, Protocolo]
    G -->|No| I[⚠️ Registrar Error<br/>Continuar]

    H --> J[🔒 Generar Hash Único]
    J --> K{¿Ya Existe<br/>en BD?}

    K -->|Sí| L[⏭️ Saltar<br/>Duplicado]
    K -->|No| M[💾 Guardar Evento]

    M --> N{¿Severidad<br/>Crítica/Alta?}
    N -->|Sí| O[🚨 Generar Alerta<br/>Notificar]
    N -->|No| P[📈 Actualizar Estadísticas]

    O --> Q[📧 Notificar<br/>por Correo]
    P --> R[📊 Dashboard<br/>Actualización]

    L --> S[🔄 Próximo Evento]
    I --> S
    Q --> S
    R --> S

    S --> T{¿Más Eventos<br/>en Archivo?}
    T -->|Sí| D
    T -->|No| U[📝 Actualizar Posición<br/>de Lectura]

    U --> V[⏰ Programar<br/>Próxima Verificación]
    V --> B

    E --> B

    style A fill:#e8f5e8
    style O fill:#ffebee
    style Q fill:#fff3e0
```

## Flujo de Autenticación y Autorización

```mermaid
flowchart TD
    A[🔐 Solicitar Acceso] --> B{¿Usuario<br/>Registrado?}

    B -->|No| C[📝 Formulario de<br/>Solicitud de Usuario]
    B -->|Sí| D[👤 Verificar Credenciales]

    C --> E[📧 Enviar Solicitud<br/>a Superusuario]
    E --> F[👑 Superusuario<br/>Revisa Solicitud]

    F --> G{¿Aprobar?}
    G -->|Sí| H[✅ Crear Usuario<br/>Asignar Permisos]
    G -->|No| I[❌ Rechazar<br/>Notificar Usuario]

    D --> J{¿Credenciales<br/>Válidas?}
    J -->|Sí| K[🎫 Generar Sesión]
    J -->|No| L[⚠️ Error de Login<br/>Registrar Intento]

    K --> M[🔍 Verificar Permisos<br/>por URL/Acción]
    M --> N{¿Tiene<br/>Permisos?}

    N -->|Sí| O[✅ Acceso Concedido<br/>Registrar Actividad]
    N -->|No| P[❌ Acceso Denegado<br/>Redirigir]

    H --> Q[📧 Notificar Usuario<br/>Credenciales]
    I --> R[📧 Notificar Rechazo]

    O --> S[📊 Dashboard<br/>Personalizado]
    P --> T[🚫 Página de Error]

    style C fill:#fff3e0
    style H fill:#e8f5e8
    style O fill:#c8e6c9
    style P fill:#ffebee
```

## Flujo de Análisis de Amenazas

```mermaid
flowchart TD
    A[🎯 Indicador de Amenaza<br/>IP/MAC/Dominio/Hash] --> B[🔍 Verificar en<br/>Base de Datos Local]

    B --> C{¿Encontrado<br/>en Cache?}
    C -->|Sí| D[📋 Mostrar Resultados<br/>del Cache]
    C -->|No| E[🌐 Consultar APIs<br/>Externas]

    E --> F[🔗 VirusTotal API]
    E --> G[🔗 AbuseIPDB API]
    E --> H[🔗 MacVendors API]

    F --> I[📊 Procesar Respuesta VT]
    G --> J[📊 Procesar Respuesta AbuseIPDB]
    H --> K[📊 Procesar Respuesta MacVendors]

    I --> L[💾 Almacenar en BD<br/>con Timestamp]
    J --> L
    K --> L

    L --> M[📈 Calcular Score<br/>de Riesgo]
    M --> N[🎨 Generar Reporte<br/>Visual]

    N --> O[📊 Mostrar en<br/>Dashboard]
    D --> O

    O --> P{¿Acción<br/>Requerida?}
    P -->|Sí| Q[🚨 Crear Incidente<br/>o Alerta]
    P -->|No| R[📝 Registrar<br/>Consulta]

    Q --> S[🔄 Integrar con<br/>Gestión de Incidentes]
    R --> T[📈 Actualizar<br/>Estadísticas]

    style E fill:#e3f2fd
    style L fill:#f3e5f5
    style O fill:#e8f5e8
```

## Diagrama de Componentes del Sistema

```mermaid
graph TB
    subgraph "Capa de Presentación"
        UI1[🌐 Templates HTML]
        UI2[🎨 CSS Bootstrap + Custom]
        UI3[⚡ JavaScript + Chart.js]
        UI4[📱 Responsive Design]
    end

    subgraph "Capa de Aplicación"
        DJ1[🔧 Django Views]
        DJ2[📋 Django Forms]
        DJ3[🛡️ Django Middleware]
        DJ4[📧 Email Service]
        DJ5[📝 Logging System]
    end

    subgraph "Capa de Dominio"
        MD1[📊 Django Models]
        MD2[🔄 Business Logic]
        MD3[✅ Validators]
        MD4[🔐 Permissions]
    end

    subgraph "Capa de Datos"
        DB1[(PostgreSQL<br/>Main DB)]
        DB2[📄 JSON Files<br/>Logs]
        DB3[🔗 External APIs<br/>Cache]
    end

    subgraph "Capa de Servicios"
        SV1[🔍 IDS Parsers]
        SV2[📊 Statistics Engine]
        SV3[🚨 Alert System]
        SV4[📈 Monitoring Service]
    end

    UI1 --> DJ1
    UI2 --> DJ1
    UI3 --> DJ1
    UI4 --> DJ1

    DJ1 --> MD2
    DJ2 --> MD2
    DJ3 --> MD2
    DJ4 --> MD2
    DJ5 --> MD2

    MD2 --> MD1
    MD2 --> MD3
    MD2 --> MD4

    MD1 --> DB1
    MD2 --> DB2
    MD2 --> DB3

    SV1 --> MD2
    SV2 --> MD2
    SV3 --> MD2
    SV4 --> MD2

    style UI1 fill:#e3f2fd
    style DJ1 fill:#f3e5f5
    style MD1 fill:#fff3e0
    style DB1 fill:#e8f5e8
    style SV1 fill:#fce4ec
```

## Flujo de Datos del Sistema

```mermaid
flowchart LR
    subgraph "Entradas"
        E1[👤 Usuarios Web]
        E2[📄 Logs IDS/IPS]
        E3[🔗 APIs Externas]
        E4[📧 Correos]
        E5[📊 Métricas Sistema]
    end

    subgraph "Procesamiento"
        P1[🔐 Autenticación]
        P2[📝 Logging]
        P3[🔍 Parsing IDS]
        P4[📊 Análisis]
        P5[🚨 Alertas]
    end

    subgraph "Almacenamiento"
        S1[(PostgreSQL)]
        S2[📄 JSON Logs]
        S3[🔄 Cache APIs]
    end

    subgraph "Salidas"
        O1[🌐 Dashboards]
        O2[📧 Notificaciones]
        O3[📊 Reportes]
        O4[📈 Estadísticas]
        O5[🔗 APIs REST]
    end

    E1 --> P1
    E2 --> P3
    E3 --> P4
    E4 --> P5
    E5 --> P4

    P1 --> P2
    P3 --> P4
    P4 --> P5

    P2 --> S1
    P3 --> S1
    P4 --> S1
    P5 --> S1
    P4 --> S2
    P4 --> S3

    S1 --> O1
    S1 --> O3
    S1 --> O4
    S1 --> O5
    S2 --> O1
    S3 --> O1

    P5 --> O2

    style E1 fill:#e3f2fd
    style P1 fill:#f3e5f5
    style S1 fill:#e8f5e8
    style O1 fill:#fff3e0
```

## Leyenda de Iconos

| Icono | Significado             |
| ----- | ----------------------- |
| 👤    | Usuario/Actor           |
| 🌐    | Interfaz Web            |
| 📊    | Dashboard/Análisis      |
| 💾    | Base de Datos           |
| 🔍    | Sistema IDS             |
| 📧    | Correo Electrónico      |
| 🚨    | Alertas/Notificaciones  |
| 🔐    | Seguridad/Autenticación |
| 📝    | Logging/Auditoría       |
| ⚙️    | Configuración           |
| 🔄    | Procesos/Flujos         |
| ✅    | Éxito/Confirmación      |
| ❌    | Error/Rechazo           |
| ⏳    | Espera/Tiempo           |
| 📈    | Estadísticas/Métricas   |

---

**Estos diagramas proporcionan una visión completa de la arquitectura y flujos de VANT-SIEM CORE, facilitando el entendimiento del sistema para desarrolladores, administradores y usuarios finales.**
