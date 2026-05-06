# VANT-SIEM Docker Deployment

## Servicios

| Servicio | Puerto | DB | Replicas |
|----------|--------|-----|----------|
| Web Portal | 8000 | `vant_web` | 1 |
| Incidents | 8001 | `vant_incidents` | 1 |
| Logs | 9201 | `vant_logs` | 2+ |
| Assets | 8002 | `vant_assets` | 1 |
| Network | 8004 | `vant_network` | 1 |
| AI | 8003 | `vant_web` | 1 (GPU opcional) |
| Celery Worker | - | - | escala horizontal |
| Celery Beat | - | - | 1 |

## Quick start

```bash
# Construir y levantar todo
docker compose up -d --build

# Escalar logs para alto volumen
docker compose up -d --scale logs-service=3

# Ver logs
docker compose logs -f web-portal
docker compose logs -f logs-service
```

## Variables de entorno

Crear `.env` en la raíz del proyecto:

```bash
DB_PASSWORD=change-me
MICROSERVICE_MODE=docker
```

## Arquitectura de BDs

Cada servicio tiene su propia BD PostgreSQL para aislamiento de fallos:

```
postgres_web:      Usuarios, auth, config UI, modelos AI
postgres_logs:     Snort, Suricata, firewall, DHCP logs
postgres_incidents: Incidentes, reportes, compliance
postgres_assets:   Dispositivos, inventario, políticas DLP
postgres_network:  Subnets, VLANs, IPAM, sitios
```
