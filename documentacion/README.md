# Documentacion VANT-SERVICES

Indice de documentacion detallada de la plataforma **VANT-SERVICES** (VANT-SIEM microservicios).

## Arquitectura general

| Documento | Contenido |
|-----------|-----------|
| [arquitectura.md](arquitectura.md) | Puertos, despliegue, nginx, systemd, `.env`, operacion, migraciones |

## Servicios

| Servicio | Puerto | Documento | Funcion |
|----------|--------|-----------|---------|
| `vant-auth` | 8100 | [vant-auth.md](vant-auth.md) | Autenticacion JWT, usuarios, tokens de agentes |
| `vant-web` | 8200 | [vant-web.md](vant-web.md) | Dashboard principal y proxy |
| `vant-inventory` | 8300 | [vant-inventory.md](vant-inventory.md) | Agentes endpoint, inventario, comandos |
| `vant-logs` | 8400 | [vant-logs.md](vant-logs.md) | Ingesta y consulta de eventos de log |
| `vant-soc` | 8500 | [vant-soc.md](vant-soc.md) | SOC, bitacora, DLP, topologia de red |
| `vant-bus` | 8600 | [vant-bus.md](vant-bus.md) | Bus de eventos, notificaciones, salud |
| `vant-intelligence` | 8700 | [vant-intelligence.md](vant-intelligence.md) | Reputacion IP/MAC/VT y analiticas geo |
| `vant-soar` | 8800 | [vant-soar.md](vant-soar.md) | SOAR: prediccion ML y reportes automaticos |
| `vant-aegis` | 8550 | [vant-aegis.md](vant-aegis.md) | DLP standalone (puerto dedicado) |

## Compartido

| Modulo | Documento | Funcion |
|--------|-----------|---------|
| `shared/vant_common` | [vant-common.md](vant-common.md) | auth, bus (Redis), http_client, middleware |

## Como leer la documentacion

Cada documento de servicio sigue la misma estructura:

1. **Descripcion** - que hace el servicio y a quien sirve.
2. **Puerto / Base de datos** - donde escucha y que BD usa.
3. **Estructura** - apps y modulos del proyecto Django.
4. **Modelos** - tablas principales.
5. **Endpoints** - rutas `/api/...` (metodo + funcion).
6. **Configuracion** - variables de entorno que le aplican.
7. **Integracion** - como lo consumen otros servicios / el dashboard.
