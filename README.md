# VANT-SIEM v3.0
## Vigilance And Neutralization of Threats - Security Information & Event Management

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Django-5.2.5-green?style=for-the-badge&logo=django" alt="Django">
  <img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/PostgreSQL-14-blue?style=for-the-badge&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

---

## Descripcion

**VANT-SIEM** es una plataforma de gestion de seguridad empresarial diseñada para la **deteccion**, **analisis** y **respuesta operativa** a incidentes de ciberseguridad. La version **3.0** consolida una arquitectura de microservicios con bases de datos aisladas, modulo DLP completo, gestion de inventario de agentes endpoint, y topologia de red visual.

### Novedades v3.0

- **Modulo DLP completo** - Politicas, reglas, incidentes, escaneos con UI de gestion
- **Inventario de agentes** - Registro, heartbeat, config push, comandos remotos
- **Database Router** para 4 bases de datos PostgreSQL aisladas
- **VANT-Agent JSON parsing** - Soporte nativo para archivos JSON array con dedup
- **TimescaleDB** integrado para `logs_events_raw` con hypertables
- **Topologia visual** - Esquemas fisicos y logicos con grafo interactivo (vis-network)
- **Arbol de redes** - Vista jerarquica con stats de uso de IPs
- **VANT-Agent** separado en [repo propio](https://github.com/leonardovarona42/VANT-Agent)

---

## Arquitectura de Microservicios

### Bases de Datos

| Base de datos | Contenido | App Django |
|---------------|-----------|------------|
| `vant_siem` | Usuarios, auth, config, dashboard, EVENT_M | `default` |
| `vant_logs` | LogEvent, LogSource, retencion | `OPENSEARCH_LOGS` |
| `vant_inventory` | Agent, AgentSoftware, AgentCommand | `INVENTORY` |
| `vant_dlp` | DlpPolicy, DlpRule, DlpIncident, DlpScanSummary | `DLP` |

### Rutas URL

| Prefijo | App | Puerto | Funcion |
|---------|-----|--------|---------|
| `/siem/dashboard/` | VANT_SIEM | 8000 | Dashboard principal, config, notificaciones |
| `/eventos/` | EVENT_M | 8000 | Incidentes, reportes, redes, topologia |
| `/logs/` | OPENSEARCH_LOGS | 8000/9201 | Logs, fuentes, dashboard, ingest |
| `/inventory/` | INVENTORY | 8000 | Agentes, inventario, comandos, config push |
| `/dlp/` | DLP | 8000 | Politicas, reglas, incidentes DLP, escaneos |
| `/assets/` | ASSETS | 8002 | API de assets (standalone) |

### Diagrama

```
┌────────────────────────────────────────────────────────────────────┐
│                        VANT-SIEM v3.0                               │
├────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ VANT_SIEM   │  │ EVENT_M  │  │OPENSEARCH│  │INVENTORY │       │
│  │ :8000       │  │ :8000    │  │ LOGS     │  │          │       │
│  │ Dashboard   │  │Incidentes│  │ :9201    │  │ Agentes  │       │
│  │ Auth        │  │ Red/IPAM │  │ Ingest   │  │ Config   │       │
│  │ Notifs      │  │Topologia │  │ Fuentes  │  │ Comandos │       │
│  └──────┬──────┘  └──────────┘  └────┬─────┘  └────┬─────┘       │
│         │                              │            │              │
│  ┌──────▼──────────────────────────────▼────────────▼─────┐       │
│  │                    DLP Module                           │       │
│  │  Politicas → Reglas → Escaneo → Incidentes → Reportes  │       │
│  └──────────────────────┬─────────────────────────────────┘       │
│                           │                                        │
│              ┌────────────┼─────────────┐                         │
│              │            │             │                          │
│     ┌────────▼──┐ ┌───────▼──────┐ ┌───▼───────┐                  │
│     │vant_siem  │ │ vant_logs    │ │vant_inv.  │                  │
│     │(users)    │ │ (events)     │ │ (agents)  │                  │
│     │(auth)     │ │ TimescaleDB  │ │ (software)│                  │
│     │(EVENT_M)  │ │ (hypertable) │ │ (cmds)    │                  │
│     └───────────┘ └──────────────┘ └───────────┘                  │
│     ┌─────────────────────┐                                       │
│     │    vant_dlp         │                                       │
│     │ (policies)          │                                       │
│     │ (rules)             │                                       │
│     │ (incidents)         │                                       │
│     │ (scan_summaries)    │                                       │
│     └─────────────────────┘                                       │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  VANT-Agent (repo separado)                                   │  │
│  │  collectors → POST /logs/api/bulk/ (:9201)                   │  │
│  │  dlp scan   → POST /dlp/api/agent/dlp/threats/ (:8000)       │  │
│  │  inventory  → POST /inventory/api/inventory/submit/          │  │
│  │  heartbeat  → POST /inventory/api/heartbeat/                 │  │
│  │  config     → PULL  /inventory/api/agent/{id}/config/        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

---

## Modulos Django (Monolito)

### Apps principales

| App | Base de datos | Descripcion |
|-----|--------------|-------------|
| **CORE** | - | Settings, db_router, service bus, events, celery |
| **VANT_SIEM** | `vant_siem` | Auth, LDAP, notificaciones, dashboard, config email |
| **EVENT_M** | `vant_siem` | Incidentes, reportes, medidas, redes, topologia |
| **OPENSEARCH_LOGS** | `vant_logs` | Ingesta de logs, fuentes, retencion, UI |
| **INVENTORY** | `vant_inventory` | Agentes endpoint, inventario, comandos, config push |
| **DLP** | `vant_dlp` | Politicas, reglas, incidentes, escaneos |
| **ASSETS** | `vant_assets` | API de assets (standalone/distributed) |

### DLP - Data Loss Prevention

**Modelos:**

| Modelo | Funcion |
|--------|---------|
| `DlpPolicy` | Politicas de escaneo (paths, extensiones, tamano max) |
| `DlpRule` | Reglas de deteccion (keyword, regex, metadata) |
| `DlpIncident` | Incidentes detectados (archivo, hash, actor, canal) |
| `DlpScanSummary` | Resumen de ejecuciones del motor DLP |

**Vistas UI:**

| URL | Vista | Descripcion |
|-----|-------|-------------|
| `/dlp/dashboard/` | `dlp_dashboard` | Dashboard con estadisticas y incidentes recientes |
| `/dlp/incidents/` | `incidents_list` | Lista de incidentes con filtros y paginacion |
| `/dlp/incidents/<pk>/` | `incident_detail` | Detalle de incidente, reconocer, resolver |
| `/dlp/policies/` | `policies_list` | Gestion de politicas DLP |
| `/dlp/policies/<code>/rules/` | `policy_rules` | Reglas de una politica |
| `/dlp/scans/` | `scan_summaries` | Historial de escaneos |

**API endpoints para agente:**

| Endpoint | Metodo | Funcion |
|----------|--------|---------|
| `/dlp/api/agent/dlp/config/` | GET | Obtener politicas y reglas activas |
| `/dlp/api/agent/dlp/threats/` | POST | Enviar incidentes detectados |
| `/dlp/api/statistics/` | GET | Estadisticas agregadas (admin) |

### INVENTORY - Gestion de Agentes

**Modelos:**

| Modelo | Funcion |
|--------|---------|
| `Agent` | Agentes endpoint registrados |
| `AgentSoftware` | Software instalado en endpoints |
| `AgentCommand` | Comandos remotos pendientes |

**Vistas UI:**

| URL | Vista | Descripcion |
|-----|-------|-------------|
| `/inventory/` | `inventory_dashboard` | Dashboard de agentes |
| `/inventory/agents/` | `agents_list` | Lista de agentes |
| `/inventory/agent/<id>/` | `agent_detail` | Detalle de agente, inventario |
| `/inventory/agent/<id>/config/` | `agent_config_view` | Configuracion y push |

### EVENT_M - Gestion de Eventos y Redes

**Vistas principales:**

| URL | Vista | Descripcion |
|-----|-------|-------------|
| `/eventos/redes/` | `RedServicioListView` | Arbol de redes con expand/collapse |
| `/eventos/red/<pk>/` | `RedDetailView` | Detalle de subred: IPs, stats, % uso |
| `/eventos/esquema/fisico/` | `TopologiaFisicaView` | Grafo topologico fisico |
| `/eventos/esquema/logico/` | `TopologiaLogicaView` | Grafo topologico logico |

---

## Cumplimiento Legal

### Resolucion 105 - MINCOM

VANT-SIEM cumple con la **Resolucion 105** del **Ministerio de Comunicaciones** de Cuba:

| Requisito | Cumplimiento |
|-----------|-------------|
| Registro de incidentes | Bitacora en tiempo real con trazabilidad |
| Identificacion de responsables | Gestion de involucrados y areas |
| Trazabilidad temporal | Timestamps, historial de estados |
| Analisis y estadisticas | Dashboard, reportes, tendencias |
| Confidencialidad | Control de acceso, LDAP, DLP |
| Documentacion | Reportes formales auditables |
| Ciclo de vida del incidente | Workflow completo |
| Prevencion de fugas | DLP con politicas y reglas configurables |

---

## Inicio Rapido

### Standalone

```bash
# 1. Entorno virtual
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux

# 2. Dependencias
pip install -r requirements.txt

# 3. Configurar .env (copiar de .env.example)
cp .env.example .env

# 4. Crear bases de datos
createdb -U postgres vant_siem
createdb -U postgres vant_logs
createdb -U postgres vant_inventory
createdb -U postgres vant_dlp

# 5. Migraciones
python manage.py migrate                          # default + vant_siem
python manage.py migrate --database=vant_logs     # logs
python manage.py migrate --database=vant_inventory # inventory
python manage.py migrate --database=vant_dlp      # dlp

# 6. Iniciar
python manage.py runserver 0.0.0.0:8000

# 7. Celery (en otra terminal)
celery -A CORE worker --loglevel=info
celery -A CORE beat --loglevel=info
```

### Docker

```bash
cd docker_deployment
docker compose up -d
# Escalar logs: docker compose up -d --scale logs-service=3
```

### Scripts de operacion (Linux)

```bash
./startup.sh    # Iniciar todos los servicios
./status.sh     # Ver estado
./stop.sh       # Detener
```

---

## VANT-Agent

El agente de endpoint se distribuye como repositorio separado:
👉 [leonardovarona42/VANT-Agent](https://github.com/leonardovarona42/VANT-Agent)

**Modulos del agente:**

| Modulo | Funcion | Envio a |
|--------|---------|---------|
| `windows_eventlog` | Windows Event Log (Security, PowerShell) | `/logs/api/bulk/` |
| `file_log` | Archivos de log (JSON, JSONL, texto plano) | `/logs/api/bulk/` |
| `aegis_dlp` | Escaneo DLP (keywords, regex, metadata) | `/dlp/api/agent/dlp/threats/` |
| `inventory` | Inventario de hardware/software | `/inventory/api/inventory/submit/` |
| `heartbeat` | Heartbeat + pull de comandos | `/inventory/api/heartbeat/` |

**Caracteristicas del agente:**
- Ejecutable Windows con PyInstaller + PyQt6 tray mode
- Configuracion remota via push de comandos
- Dedup por `id`/`event_id` en JSON y machine_name/MAC en eventos
- Parseo nativo de JSON array con encoding UTF-8 BOM

---

## Documentacion

| Documento | Descripcion |
|-----------|-------------|
| [MICROSERVICES.md](MICROSERVICES.md) | Arquitectura de microservicios y DB routing |
| [ROADMAP.md](ROADMAP.md) | Plan de desarrollo y estado |
| [docker_deployment/README.md](docker_deployment/README.md) | Deploy con Docker |

---

## Tecnologias

![Django](https://img.shields.io/badge/Django-5.2.5-green)
![Python](https://img.shields.io/badge/Python-3.13-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14-blue)
![TimescaleDB](https://img.shields.io/badge/TimescaleDB-2.17-orange)
![Celery](https://img.shields.io/badge/Celery-5.x-red)
![Redis](https://img.shields.io/badge/Redis-broker-orange)
![vis-network](https://img.shields.io/badge/vis--network-topology-yellow)
![Tailwind](https://img.shields.io/badge/Tailwind-CSS-purple)

---

## Licencia

MIT License - © 2025-2026 VANT-SIEM - Developed by **LLVT**

---

<div align="center">

**VANT-SIEM v3.0** - *Vigilance And Neutralization of Threats*

*Plataforma integral de ciberseguridad con arquitectura de microservicios*

</div>
