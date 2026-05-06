# VANT-SIEM v2.1
## Vigilance And Neutralization of Threats - Security Information & Event Management

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Django-6.0-green?style=for-the-badge&logo=django" alt="Django">
  <img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

---

## Descripcion

**VANT-SIEM** es una plataforma de gestion de seguridad empresarial diseñada para la **deteccion**, **analisis** y **respuesta operativa** a incidentes de ciberseguridad. La version **2.1** introduce una arquitectura de microservicios con bases de datos aisladas, bus de eventos, y un modulo de gestion de redes unificado.

### Novedades v2.1

- **Arquitectura de microservicios** con 5 bases de datos PostgreSQL aisladas
- **Service Bus** (Redis pub/sub) para comunicacion entre servicios
- **Gestion de Redes unificada** - Subredes, VLANs, segmentos y hosts en un solo modelo `Servicio`
- **Topologia visual** - Esquemas fisicos y logicos con grafo interactivo (vis-network)
- **Arbol de redes** - Vista jerarquica con stats de uso de IPs
- **Detalle de subred** - Tabla de IPs asignadas, hosts activos, porcentaje de uso
- **Fullscreen** en esquemas de topologia
- **Celery** para tareas async y scheduled jobs
- **Eliminacion de modulos legacy** (IRIS, Ollama, OpenSearch UI inline)
- **VANT-Agent** separado en [repo propio](https://github.com/leonardovarona42/VANT-Agent)

---

## Arquitectura de Microservicios

### Servicios

| Servicio | Puerto | Base de datos | Funcion |
|----------|--------|---------------|---------|
| **Web Portal** | 8000 | `vant_siem` | UI, auth, dashboard, agregacion |
| **Logs** | 9201 | `vant_logs` | Ingesta de logs (Snort, Suricata, firewall) |
| **Incidents** | 8001 | `vant_incidents` | Gestion de incidentes, reportes, EVENT_M |
| **Network** | 8004 | `vant_network` | IPAM, VLANs, subnets, topologia |
| **Assets** | 8002 | `vant_assets` | Inventario, DLP, agentes |
| **Celery Worker** | - | - | Tareas async |
| **Celery Beat** | - | - | Scheduler |

### Diagrama

```
┌───────────────────────────────────────────────────────────────────┐
│                        VANT-SIEM v2.1                              │
├───────────────────────────────────────────────────────────────────┤
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌────────┐ ┌──────┐ ┌───┐            │
│  │ WEB  │ │ LOGS │ │INCID │ │ ASSETS │ │ NET  │ │Cel│            │
│  │:8000 │ │:9201 │ │:8001 │ │ :8002  │ │:8004 │ │   │            │
│  │UI    │ │Log   │ │Inc   │ │Invent. │ │IPAM  │ │Cel│            │
│  │Auth  │ │Ingest│ │Report│ │DLP     │ │VLANs │ │Beat│           │
│  │Dash  │ │Snort │ │EventM│ │Agents  │ │Topol │ │   │            │
│  └──┬───┘ └──┬───┘ └──┬───┘ └───┬────┘ └──┬───┘ └─┬─┘            │
│     │          │          │         │         │      │              │
│     └──────────┼──────────┼─────────┼─────────┘      │              │
│                │          │         │                │              │
│         ┌──────▼──────────▼─────────▼────────────────▼──┐         │
│         │         Service Bus (Redis pub/sub)            │         │
│         │   vant:log.alert | vant:asset.dlp | ...       │         │
│         └────────────────────────────────────────────────┘         │
│                                                                     │
│         ┌─────────────────────────────────────────────────────┐    │
│         │            PostgreSQL (5 bases aisladas)             │    │
│         │  vant_siem │ vant_logs │ vant_incidents │ ...       │    │
│         └─────────────────────────────────────────────────────┘    │
└───────────────────────────────────────────────────────────────────┘
```

Ver [MICROSERVICES.md](MICROSERVICES.md) para detalles completos.

---

## Modulos Django (Monolito)

En modo standalone, los modulos operan como apps Django dentro de un solo proceso:

| App | Descripcion |
|-----|-------------|
| **CORE** | Settings, routing, service bus, events, celery config |
| **VANT_SIEM** | Auth, LDAP, notificaciones, dashboard, config email, logs |
| **EVENT_M** | Incidentes, reportes, medidas, involucrados, servicios, redes, topologia |

### EVENT_M - Gestion de Eventos y Redes

**Modelos principales:**

| Modelo | Funcion |
|--------|---------|
| `Categoria` / `Subcategoria` | Clasificacion de incidentes |
| `Servicio` | Host, switch, router, firewall, VLAN, subred, segmento, cluster, servicio externo |
| `ServicioIP` | IPs asignadas a un servicio |
| `PuertoDispositivo` | Puertos fisicos de dispositivos de red |
| `ConexionTopologica` | Conexiones entre servicios para topologia |
| `Responsable` / `Area` | Personas y areas organizativas |
| `Reporte` | Reportes formales de seguridad |
| `Incidente` | Incidentes con ciclo de vida completo |
| `Medida` | Medidas de seguridad |

**Servicio como modelo unificado de red:**

El modelo `Servicio` ahora maneja todos los tipos de entidad de red:

| Tipo | Campos relevantes |
|------|------------------|
| `host` | host (IP), plataforma, firmware |
| `switch` | num_puertos, modelo, fabricante |
| `router` | num_puertos, modelo, fabricante |
| `firewall` | num_puertos, modelo, fabricante |
| `vlan` | vlan_id, network, subnet_mask, gateway |
| `subred` | network, subnet_mask, gateway, DHCP |
| `segmento` | network, subnet_mask, servicio_padre |
| `red` | network, subnet_mask, gateway |
| `cluster` | servicios_hijos (M2M) |
| `servicio_externo` | url_servicio, api_key |

**Vistas:**

| URL | Vista | Descripcion |
|-----|-------|-------------|
| `/eventos/servicios/` | `ServicioListView` | CRUD de todos los servicios |
| `/eventos/redes/` | `RedServicioListView` | Arbol de redes con expand/collapse |
| `/eventos/red/<pk>/` | `RedDetailView` | Detalle de subred: IPs, stats, hosts |
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
| Confidencialidad | Control de acceso, LDAP |
| Documentacion | Reportes formales auditables |
| Ciclo de vida del incidente | Workflow completo |

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

# 4. Migraciones
python manage.py migrate

# 5. Iniciar
python manage.py runserver 0.0.0.0:8000

# 6. Celery (en otra terminal)
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

Incluye: `asset_audit` (inventario), `aegis_dlp` (prevencion fuga de datos), colectores de logs.

---

## Documentacion

| Documento | Descripcion |
|-----------|-------------|
| [MICROSERVICES.md](MICROSERVICES.md) | Arquitectura de microservicios |
| [ROADMAP.md](ROADMAP.md) | Plan de desarrollo y estado |
| [docker_deployment/README.md](docker_deployment/README.md) | Deploy con Docker |

---

## Tecnologias

![Django](https://img.shields.io/badge/Django-6.0-green)
![Python](https://img.shields.io/badge/Python-3.13-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14+-blue)
![Celery](https://img.shields.io/badge/Celery-5.x-red)
![Redis](https://img.shields.io/badge/Redis-broker-orange)
![vis-network](https://img.shields.io/badge/vis--network-topology-yellow)
![Bootstrap](https://img.shields.io/badge/Tailwind-CSS-purple)

---

## Licencia

MIT License - © 2025-2026 VANT-SIEM - Developed by **LLVT**

---

<div align="center">

**VANT-SIEM v2.1** - *Vigilance And Neutralization of Threats*

*Plataforma integral de ciberseguridad con arquitectura de microservicios*

</div>
