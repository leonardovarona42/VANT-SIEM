# VANT-SIEM Microservices Architecture

> Version: 3.0 | Última actualización: 2026-05-07

## Servicios

| Servicio | Puerto | Base de datos | Funcion | Escala |
|----------|--------|---------------|---------|--------|
| **Web Portal** | 8000 | `vant_siem` | UI, auth, dashboard, EVENT_M, agregacion | 1 instancia |
| **Logs** | 9201 | `vant_logs` | Ingesta de logs (Snort, Suricata, firewall, DHCP, file_log) | 2+ instancias |
| **Inventory** | - | `vant_inventory` | Agentes endpoint, inventario, comandos, config push | 1 instancia |
| **DLP** | - | `vant_dlp` | Politicas, reglas, incidentes, escaneos | 1 instancia |
| **Assets** | 8002 | `vant_assets` | API de assets (standalone/distributed) | 1 instancia |
| **Celery Worker** | - | - | Tareas async (notificaciones, limpieza) | Escala horizontal |
| **Celery Beat** | - | - | Scheduler de tareas periodicas | 1 instancia |

## Integracion con EVENT_M (puerto 8000)

La app `EVENT_M` integrada en el Web Portal gestiona:

- **Incidentes**: deteccion, workflow, reportes, compliance, medidas, involucrados
- **Red/IPAM**: modelo `Servicio` unificado (hosts, switches, routers, firewalls, VLANs, subredes, topologia)
- **Esquemas**: vista fisica y logica de topologia de red

## Modulo DLP

El modulo DLP (Data Loss Prevention) opera como app Django con base de datos propia:

- **Politicas**: configuracion de paths de escaneo, extensiones monitoreadas, tamano maximo
- **Reglas**: patrones keyword, regex o metadata con clasificacion y severidad
- **Incidentes**: detecciones con fingerprint unico, archivo, hash, actor, canal
- **Escaneos**: resumen de ejecuciones del motor DLP en agentes endpoint

El agente `aegis_dlp` obtiene politicas via `GET /dlp/api/agent/dlp/config/` y reporta incidentes via `POST /dlp/api/agent/dlp/threats/`.

## Arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│                      VANT-SIEM Platform                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │              Web Portal (:8000)                              │   │
│  │  ┌──────┐  ┌──────────┐  ┌────────┐  ┌────────┐ ┌───────┐  │   │
│  │  │ Auth │  │Dashboard │  │EVENT_M │  │  DLP   │ │Invent.│  │   │
│  │  │ UI   │  │Stats     │  │Inc/Red │  │Policies│ │Agents │  │   │
│  │  │      │  │Aggregator│  │Topolog.│  │Incidents│ │Cmds  │  │   │
│  │  └──────┘  └──────────┘  └────────┘  └────────┘ └───────┘  │   │
│  └────────────────────────┬────────────────────────────────────┘   │
│                           │                                         │
│           ┌───────────────┼───────────────┐                        │
│           │               │               │                        │
│    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐                │
│    │ Logs (:9201)│ │ Inventory   │ │ Assets      │                │
│    │ Ingesta     │ │ (:8000)     │ │ (:8002)     │                │
│    │ Snort/Suri  │ │ Agents      │ │ API         │                │
│    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘                │
│           │               │               │                        │
│     ┌─────▼───────────────▼───────────────▼─────┐                │
│     │        Service Bus (Redis pub/sub)          │                │
│     │ vant:log.alert | vant:asset.dlp | ...     │                │
│     └─────────────────────────────────────────────┘                │
│                                                                      │
│     ┌───────────────────────────────────────────────────┐          │
│     │       PostgreSQL (4 DBs aisladas)                   │          │
│     │                                                      │          │
│     │ vant_siem │ vant_logs │ vant_inventory │ vant_dlp  │          │
│     │ (users)   │ (events)  │ (agents)       │ (policies)│          │
│     │ (auth)    │ Timescale │ (software)     │ (rules)   │          │
│     │ (config)  │ hypertable│ (commands)     │ (incidents)│         │
│     │ (EVENT_M) │ (logs)    │                │ (scans)   │          │
│     └───────────────────────────────────────────────────┘          │
└──────────────────────────────────────────────────────────────────┘

    VANT-Agent (repo separado)
    ┌────────────────────────────────────────────────────────────┐
    │ collectors    → POST /logs/api/bulk/ (:9201)               │
    │ dlp scan      → POST /dlp/api/agent/dlp/threats/ (:8000)   │
    │ dlp config    → GET  /dlp/api/agent/dlp/config/ (:8000)    │
    │ inventory     → POST /inventory/api/inventory/submit/      │
    │ heartbeat     → POST /inventory/api/heartbeat/             │
    │ config pull   → GET  /inventory/api/agent/{id}/config/     │
    └────────────────────────────────────────────────────────────┘
```

## Aislamiento de bases de datos

| BD | Contenido | App | Backup | Riesgo si se pierde |
|----|-----------|-----|--------|-------------------|
| `vant_siem` | Usuarios, auth, config UI, EVENT_M (incidentes, red) | `VANT_SIEM`, `EVENT_M` | Diario | Se pierden credenciales + incidentes |
| `vant_logs` | Snort, Suricata, firewall, DHCP, file_log | `OPENSEARCH_LOGS` | Semanal | Alto volumen, aceptable |
| `vant_inventory` | Agentes, software, comandos | `INVENTORY` | Diario | Se recupera re-sync de agentes |
| `vant_dlp` | Politicas, reglas, incidentes DLP, escaneos | `DLP` | Diario | Se pierden incidentes DLP |

## Database Router

`CORE/db_router.py` define 3 routers:

| Router | Apps | Database |
|--------|------|----------|
| `LogsRouter` | `OPENSEARCH_LOGS` | `vant_logs` |
| `InventoryRouter` | `INVENTORY` | `vant_inventory` |
| `DlpRouter` | `DLP` | `vant_dlp` |

Cualquier app no enrutada usa `default` (`vant_siem`).

## Escenarios de fallo

| Fallo | Impacto sin aislamiento | Impacto con microservicios |
|-------|------------------------|---------------------------|
| Logs saturados (50GB/dia) | **Tumba toda la app** | Solo Logs Service degrada |
| BD de logs corrupta | **Pierdes todo** | Solo pierdes logs |
| BD de DLP corrupta | **Pierdes todo** | Solo pierdes incidentes DLP |
| Escalar logs | Escalas todo | Solo logs-service: 2→5 |

## EVENT_M - Modelo de Red Unificado

El modelo `Servicio` unifica todas las entidades de red en un solo modelo con campo `tipo`:

```
Servicio.tipo:
├── host         → Servidores, PCs (host/IP, plataforma, firmware)
├── switch       → Switches (num_puertos, modelo, fabricante)
├── router       → Routers (num_puertos, modelo, fabricante)
├── firewall     → Firewalls (num_puertos, modelo, fabricante)
├── access_point → APs wireless
├── ups          → UPS / energia
├── storage      → Almacenamiento
├── vlan         → VLANs (vlan_id, network, subnet_mask, gateway)
├── segmento     → Segmentos de red (servicio_padre, network)
├── subred       → Subredes (network, subnet_mask, gateway, DHCP)
├── red          → Redes principales (network, subnet_mask, gateway)
├── cluster      → Clusters (servicios_hijos M2M)
├── plataforma   → Plataformas de virtualizacion
└── servicio_externo → APIs externas (url_servicio, api_key)
```

### Topologia

- `ConexionTopologica` define conexiones entre servicios
- `PuertoDispositivo` modela puertos fisicos de switches/routers/firewalls
- `servicio_padre` permite jerarquias (clusters, segmentos padre)
- Esquemas fisicos y logicos con coordenadas independientes

### Vistas de Red

| URL | Vista | Descripcion |
|-----|-------|-------------|
| `/eventos/redes/` | `RedServicioListView` | Arbol de redes con expand/collapse |
| `/eventos/red/<pk>/` | `RedDetailView` | Detalle: IPs, hosts activos, % uso, stats |
| `/eventos/esquema/fisico/` | `TopologiaFisicaView` | Grafo topologico fisico |
| `/eventos/esquema/logico/` | `TopologiaLogicaView` | Grafo topologico logico |

## DLP - Politicas y Reglas

### Politicas (`DlpPolicy`)

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `code` | CharField | Identificador unico (ej: `estado_clasificado`) |
| `scan_paths` | JSONField | Lista de directorios a escanear |
| `monitored_extensions` | JSONField | Extensiones de archivo a monitorear |
| `max_file_size_mb` | IntegerField | Tamano maximo de archivo para escanear |

### Reglas (`DlpRule`)

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `pattern` | TextField | Patron keyword o regex a buscar |
| `match_type` | CharField | `keyword`, `regex`, `metadata` |
| `classification` | CharField | Clasificacion del dato detectado |
| `severity` | CharField | `critical`, `high`, `medium`, `low` |

### Incidentes (`DlpIncident`)

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `fingerprint` | CharField | Hash unico del incidente (dedup) |
| `file_name` / `file_path` | CharField/TextField | Archivo detectado |
| `file_hash` | CharField | SHA-256 del archivo |
| `actor` | CharField | Usuario propietario del archivo |
| `channel` | CharField | Via de deteccion: `filesystem`, `email`, `cloud`, `usb`, `web`, `network` |
| `status` | CharField | `open`, `acknowledged`, `resolved`, `false_positive` |

## Standalone (sin Docker)

```bash
# Web Portal (auto-spawnea Logs + Assets como subprocess)
python manage.py runserver 0.0.0.0:8000

# Celery Worker
celery -A CORE worker --loglevel=info

# Celery Beat
celery -A CORE beat --loglevel=info
```

O en Linux: `./startup.sh`

## Docker

```bash
cd docker_deployment
docker compose up -d

# Escalar logs
docker compose up -d --scale logs-service=3
```

## Event-driven communication

```
Logs Service (detecta alerta critical)
    │
    ├── publish("log.alert", {alert_type, severity})
    │
    ▼
Service Bus (Redis: vant:log.alert)
    │
    └── Web Portal (EVENT_M) → crea Incidente + notificacion

DLP Agent (detecta documento clasificado)
    │
    ├── POST /dlp/api/agent/dlp/threats/
    │
    ▼
DLP Service → crea DlpIncident + notificacion
    │
    └── publish("asset.dlp", {filename, classification})
        ▼
        Web Portal (EVENT_M) → crea Reporte de seguridad

Web Portal/EVENT_M (detecta cambio en red)
    │
    ├── publish("network.change", {service_id, change_type})
    │
    ▼
Service Bus (Redis: vant:network.change)
    │
    └── Assets Service → actualiza inventario
```

## Auto-start de microservicios

`CORE/management/commands/runserver.py` spawnea automaticamente:

| Servicio | Puerto | Comando |
|----------|--------|---------|
| Logs Service | 9201 | `run_logs_service` |
| Assets Service | 8002 | `run_assets_service` |

El Web Portal (8000) incluye EVENT_M, DLP, e INVENTORY que operan internamente.

## Variables de entorno

Ver `.env.example` para referencia completa.

| Variable | Default | Descripcion |
|----------|---------|-------------|
| `VANT_SERVICE_NAME` | `vant-siem` | Nombre del servicio |
| `MICROSERVICE_MODE` | `standalone` | `standalone` \| `docker` |
| `SERVICE_BUS_URL` | `redis://localhost:6379/10` | Redis pub/sub |
| `LOGS_SERVICE_URL` | `http://localhost:9201` | Servicio de logs |
| `ASSETS_SERVICE_URL` | `http://localhost:8002` | Servicio de assets |
| `CELERY_BROKER_URL` | `redis://localhost:6379/0` | Celery broker |
| `CELERY_RESULT_BACKEND` | `redis://localhost:6379/1` | Celery backend |
| `DLP_DB_NAME` | `vant_dlp` | Base de datos DLP |
| `DLP_DB_HOST` | `localhost` | Host de la BD DLP |
| `DLP_DB_PORT` | `5432` | Puerto de la BD DLP |
