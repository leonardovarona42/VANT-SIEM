# VANT-SERVICES

## VANT-SIEM - Arquitectura de Microservicios

**Vigilance And Neutralization of Threats - Security Information & Event Management**

<p align="center">
  <img src="https://img.shields.io/badge/Version-4.5-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Web-v1.0-green?style=for-the-badge" alt="Web">
  <img src="https://img.shields.io/badge/Django-5.1.15-green?style=for-the-badge&logo=django" alt="Django">
  <img src="https://img.shields.io/badge/Python-3.13-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/PostgreSQL-blue?style=for-the-badge&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/Redis-orange?style=for-the-badge&logo=redis" alt="Redis">
</p>

---

## Descripcion

**VANT-SERVICES** es la evolución de **VANT-SIEM** hacia una arquitectura de **microservicios Django** con bases de datos aisladas. Cada servicio es un proyecto Django independiente, desplegado con **gunicorn + systemd** y expuesto a traves de un **nginx** central en una sola IP.

La plataforma cubre el ciclo completo de seguridad:

1. **Recoleccion** - Agentes endpoint (`VANT-Agent`) y fuentes de log (firewalls, Suricata) envian eventos al servicio de logs.
2. **Almacenamiento** - `vant-logs` normaliza y almacena eventos (TimescaleDB/PostgreSQL) con retencion configurable.
3. **Inteligencia** - Enriquecimiento (IP/MAC/VirusTotal), analiticas geo y dashboards.
4. **SOC** - Gestion de incidentes, reportes, bitacora, topologia de red y monitoreo de servicios.
5. **DLP** - Deteccion de fuga de datos (politicas, reglas, amenazas) en `vant-soc` (y `vant-aegis`).
6. **SOAR** - Orquestacion y respuesta: analisis ML de eventos, predicciones y generacion automatica de reportes SOC.
7. **Presentacion** - `vant-web` es el dashboard unico que agrega y proxya todos los servicios bajo `/siem/dashboard/`.

---

## Servicios y Puertos

| Servicio | Puerto | Base de datos | Funcion |
|----------|--------|---------------|---------|
| `vant-auth` | 8100 | `vant_auth` | Autenticacion JWT, usuarios, tokens de agentes |
| `vant-web` | 8200 | `vant_web` | Dashboard principal (proxy a todos los servicios) |
| `vant-inventory` | 8300 | `vant_inventory` | Agentes endpoint, inventario, comandos, heartbeat |
| `vant-logs` | 8400 | `vant_logs` | Ingesta, normalizacion y consulta de eventos de log |
| `vant-soc` | 8500 | `vant_soc` | Incidentes, reportes, bitacora, DLP, topologia |
| `vant-bus` | 8600 | `vant_bus` | Bus de eventos, notificaciones, salud de servicios |
| `vant-intelligence` | 8700 | `vant_intelligence` | Reputacion IP/MAC/VT, analiticas geo, API keys |
| `vant-soar` | 8800 | `vant_soar` | Prediccion ML de incidentes, playbooks, reportes automaticos |
| `vant-aegis` | 8550 | `vant_soc` | Modulo DLP standalone (puerto dedicado) |

> `vant-aegis` usa puerto dedicado **8550** (bind en su `gunicorn.conf.py`) tras el conflicto de puerto resuelto. Ver [Issues conocidos](#issues-conocidos).

Servicios adicionales (systemd, sin API propia):

| Unidad | Funcion |
|--------|---------|
| `vantsiem-soar-worker` | Worker SOAR: consume `logs_events_raw` -> features -> predicciones -> bus |
| `vantsiem-soc-soar` | Consumidor SOC: lee el stream Redis `threats` y crea reportes automaticos |
| `vantsiem-icmp-monitor` | Monitor ICMP de servicios |
| `vantsiem-health-check` | Health check general (inactivo) |

---

## Arquitectura

Plataforma de **microservicios Django** en un unico servidor (`192.168.12.43`), expuestos por un nginx central en el 443. `vant-web` es el dashboard unico que proxya a todos los servicios bajo `/siem/dashboard/`.

```
nginx :443
  ├── /siem/          -> vant-web        (:8200)
  ├── /auth/          -> vant-auth       (:8100)
  ├── /inventory/api/ -> vant-inventory  (:8300)
  ├── /logs/api/      -> vant-logs       (:8400)
  ├── /soc/api/       -> vant-soc        (:8500)
  ├── /api/alerts/    -> vant-bus        (:8600)
  ├── /intel/api/     -> vant-intelligence (:8700)
  └── /               -> vant-web        (:8200)
```

Detalle completo (diagrama, comunicacion entre servicios, bases de datos, nginx, systemd, operacion, issues): [documentacion/arquitectura.md](documentacion/arquitectura.md).

---

## Bases de Datos

Ver tabla completa de bases y contenido en [documentacion/arquitectura.md](documentacion/arquitectura.md#6-bases-de-datos). Conexion: `PGPASSWORD=... psql -h 127.0.0.1 -U vantsiem <db>`.

---

## Estructura del Repositorio

```
VANT-SERVICES/
├── README.md                  <- Este documento
├── documentacion/             <- Documentacion detallada por servicio
│   ├── README.md              (indice)
│   ├── arquitectura.md        (despliegue, nginx, systemd, .env, operacion)
│   ├── vant-auth.md
│   ├── vant-web.md
│   ├── vant-inventory.md
│   ├── vant-logs.md
│   ├── vant-soc.md
│   ├── vant-aegis.md
│   ├── vant-bus.md
│   ├── vant-intelligence.md
│   ├── vant-soar.md
│   └── vant-common.md
├── shared/
│   └── vant_common/           <- Libreria compartida (auth, bus, http_client, middleware)
├── scripts/                   <- Deploy, units systemd, nginx, start/stop/migrate
│   ├── deploy.py
│   ├── nginx-vantsiem.conf
│   ├── start_all.sh / stop_all.sh / migrate_all.sh
│   └── vantsiem-*.service
├── vant-auth/                 <- Servicio de autenticacion (Django :8100)
├── vant-web/                  <- Dashboard principal (Django :8200)
├── vant-inventory/            <- Agentes endpoint (Django :8300)
├── vant-logs/                 <- Logs SIEM (Django :8400)
├── vant-soc/                  <- SOC + DLP + bitacora (Django :8500)
├── vant-bus/                  <- Bus de eventos (Django :8600)
├── vant-intelligence/         <- Inteligencia / reputacion (Django :8700)
├── vant-soar/                 <- SOAR / ML (Django :8800)
└── vant-aegis/                <- DLP standalone (Django)
```

---

## Inicio Rapido

### Requisitos

- Python 3.13
- PostgreSQL (bases listadas arriba, user `vantsiem`)
- Redis
- Linux (units systemd), o Windows para desarrollo

### Desarrollo local

```bash
# 1. Entorno virtual
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # Linux

# 2. Instalar libreria compartida
pip install -e shared/

# 3. Dependencias de un servicio
cd vant-soar
pip install -r requirements.txt

# 4. Configurar .env (copiar del servidor /opt/vant-siem/.env)

# 5. Migrar
python manage.py migrate

# 6. Iniciar
python manage.py runserver 127.0.0.1:8800
```

### Despliegue en servidor

Ver [documentacion/arquitectura.md](documentacion/arquitectura.md) para el flujo completo (units systemd, nginx, .env, worker SOAR).

```bash
# Desde la estacion de trabajo con paramiko instalado:
python scripts/deploy.py            # despliega todos los servicios a 192.168.12.43
python scripts/deploy.py --server IP
```

---

## Documentacion

| Documento | Contenido |
|-----------|-----------|
| [documentacion/README.md](documentacion/README.md) | Indice general de documentacion |
| [documentacion/arquitectura.md](documentacion/arquitectura.md) | Arquitectura, despliegue, nginx, systemd, .env, operacion |
| [documentacion/vant-auth.md](documentacion/vant-auth.md) | Autenticacion JWT, usuarios, agentes |
| [documentacion/vant-web.md](documentacion/vant-web.md) | Dashboard, proxy, rutas |
| [documentacion/vant-inventory.md](documentacion/vant-inventory.md) | Agentes endpoint |
| [documentacion/vant-logs.md](documentacion/vant-logs.md) | Ingesta y consulta de logs |
| [documentacion/vant-soc.md](documentacion/vant-soc.md) | SOC, bitacora, DLP, topologia |
| [documentacion/vant-aegis.md](documentacion/vant-aegis.md) | DLP standalone |
| [documentacion/vant-bus.md](documentacion/vant-bus.md) | Bus de eventos y notificaciones |
| [documentacion/vant-intelligence.md](documentacion/vant-intelligence.md) | Reputacion y analiticas |
| [documentacion/vant-soar.md](documentacion/vant-soar.md) | SOAR, ML, reportes automaticos |
| [documentacion/vant-common.md](documentacion/vant-common.md) | Libreria compartida `vant_common` |

---

## Operacion

Logs de servicios, comandos de systemd, health checks y verificacion end-to-end: [documentacion/arquitectura.md](documentacion/arquitectura.md#8-operacion).

---

## Issues conocidos

- **`vant-aegis` (resuelto)**: estaba en crash-loop por compartir el puerto 8500 con `vant-soc` y agotar el pool de PostgreSQL. Resuelto hardcodeando el bind 8550 en su `gunicorn.conf.py`; hoy escucha en 8550 y responde healthy. Detalle en [documentacion/vant-aegis.md](documentacion/vant-aegis.md).
- La unidad `vantsiem-soc-soar` depende del stream Redis `threats`; los timeouts de `xreadgroup` son silenciosos (no son errores).

---

## Tecnologias

- Django 5.1.x / DRF 3.15
- Python 3.13
- PostgreSQL
- Redis (Streams)
- scikit-learn 1.5 (SOAR)
- gunicorn + systemd
- nginx

---

## Licencia

MIT License - © 2026 VANT-SIEM v4.5 - Web v1.0 - Developed by **LLVT**

---

<div align="center">

**VANT-SERVICES** - *Vigilance And Neutralization of Threats*

*Plataforma de ciberseguridad como microservicios*

</div>
