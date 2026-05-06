# VANT-SIEM Microservices Architecture

> Version: 3.0 | Última actualización: 2026-05-06

## Servicios

| Servicio | Puerto | Base de datos | Funcion | Escala |
|----------|--------|---------------|---------|--------|
| **Web Portal** | 8000 | `vant_siem` | UI, auth, dashboard, incidentes, red, agregacion | 1 instancia |
| **Logs** | 9201 | `vant_logs` | Ingesta de logs (Snort, Suricata, firewall, DHCP) | 2+ instancias |
| **Assets** | 8002 | `vant_assets` | Inventario, DLP policies, agentes | 1 instancia |
| **Celery Worker** | - | - | Tareas async (notificaciones, limpieza) | Escala horizontal |
| **Celery Beat** | - | - | Scheduler de tareas periodicas | 1 instancia |

## Integracion con EVENT_M (puerto 8000)

La app `EVENT_M` integrada en el Web Portal gestiona:

- **Incidentes**: deteccion, workflow, reportes, compliance, medidas, involucrados
- **Red/IPAM**: modelo `Servicio` unificado (hosts, switches, routers, firewalls, VLANs, subredes, topologia)
- **Esquemas**: vista fisica y logica de topologia de red

Esto elimina la necesidad de microservicios separados para incidentes y red.

## Arquitectura

```
┌───────────────────────────────────────────────────────────┐
│                      VANT-SIEM Platform                    │
├───────────────────────────────────────────────────────────┤
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Web Portal (:8000)                       │  │
│  │  ┌──────┐  ┌──────────┐  ┌────────────────────────┐  │  │
│  │  │ Auth │  │Dashboard │  │   EVENT_M App          │  │  │
│  │  │ UI   │  │Stats     │  │ - Incidentes/Workflow  │  │  │
│  │  │      │  │Aggregator│  │ - IPAM/VLANs/Subnets   │  │  │
│  │  │      │  │          │  │ - Topologia/Schemas    │  │  │
│  │  └──────┘  └──────────┘  └────────────────────────┘  │  │
│  └───────────────────────┬────────────────────────────────┘  │
│                          │                                    │
│           ┌──────────────┼──────────────┐                    │
│           │              │              │                    │
│    ┌──────▼──────┐ ┌────▼─────┐        │                    │
│    │ Logs (:9201)│ │Assets    │        │                    │
│    │ Ingesta     │ │(:8002)   │        │                    │
│    │ Snort/Suri  │ │Invent/DLP│        │                    │
│    └──────┬──────┘ └────┬─────┘        │                    │
│           │              │              │                    │
│     ┌─────▼──────────────▼──────────────▼──┐               │
│     │        Service Bus (Redis pub/sub)    │               │
│     │ vant:log.alert | vant:asset.dlp      │               │
│     └───────────────────────────────────────┘               │
│                                                              │
│     ┌───────────────────────────────────────────┐           │
│     │       PostgreSQL (3 DBs aisladas)          │           │
│     │                                            │           │
│     │ vant_siem │ vant_logs │ vant_assets        │           │
│     │ (users)   │ (snort)   │ (devices)          │           │
│     │ (auth)    │ (suricata)│ (dlp pol)          │           │
│     │ (config)  │ (firewall)│ (inventory)        │           │
│     │ (EVENT_M) │ (logs)    │                    │           │
│     └───────────────────────────────────────────┘           │
└───────────────────────────────────────────────────────────┘

    VANT-Agent (repo separado)
    ┌────────────────────────────────────────────────────┐
    │ collectors → POST /logs/bulk (:9201)               │
    │ dlp scan   → POST /assets/dlp/incident (:8002)     │
    │ inventory  → POST /assets/inventory (:8002)        │
    │ heartbeat  → POST /assets/heartbeat (:8002)        │
    └────────────────────────────────────────────────────┘
```

## Aislamiento de bases de datos

| BD | Contenido | Backup | Riesgo si se pierde |
|----|-----------|--------|-------------------|
| `vant_siem` | Usuarios, auth, config UI, EVENT_M (incidentes, red), logs del sistema | Diario | Se pierden credenciales + incidentes |
| `vant_logs` | Snort, Suricata, firewall, DHCP logs | Semanal | Alto volumen, aceptable |
| `vant_assets` | Dispositivos, inventario, DLP policies | Diario | Se recupera re-sync |

## Escenarios de fallo

| Fallo | Impacto sin aislamiento | Impacto con microservicios |
|-------|------------------------|---------------------------|
| Logs saturados (50GB/dia) | **Tumba toda la app** | Solo Logs Service degrada |
| BD de logs corrupta | **Pierdes todo** | Solo pierdes logs |
| AI en entrenamiento (RAM alta) | **Bloquea toda la app** | Solo AI Service lento |
| EVENT_M cae | No hay incidentes ni red | Web Portal degradado |
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

### Campos de red (tipos: vlan, segmento, subred, red)

| Campo | Tipo | Descripcion |
|-------|------|-------------|
| `network` | GenericIPAddressField | Direccion de red (ej: 10.10.0.0) |
| `subnet_mask` | CharField | Mascara CIDR (ej: /24 o 255.255.255.0) |
| `gateway` | GenericIPAddressField | Gateway por defecto |
| `red_tipo` | CharField | Tipo de red: interna, dmz, gestion, usuarios, etc. |
| `vlan_id` | IntegerField | Tag VLAN (1-4094) |
| `dns_primario` | GenericIPAddressField | DNS primario |
| `dns_secundario` | GenericIPAddressField | DNS secundario |
| `dhcp_activo` | BooleanField | DHCP habilitado |
| `dhcp_rango_inicio` | GenericIPAddressField | Rango DHCP inicio |
| `dhcp_rango_fin` | GenericIPAddressField | Rango DHCP fin |

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

Assets Service (detecta DLP)
    │
    ├── publish("asset.dlp", {filename, classification})
    │
    ▼
Service Bus (Redis: vant:asset.dlp)
    │
    └── Web Portal (EVENT_M) → crea Incidente + Reporte

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

El Web Portal (8000) incluye EVENT_M que gestiona incidentes y red internamente.

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
