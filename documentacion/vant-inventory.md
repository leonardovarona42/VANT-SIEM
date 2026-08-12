# vant-inventory

Servicio de **gestion de agentes endpoint**: registro, heartbeat, inventario, comandos remotos, capturas de pantalla y procesos.

- Puerto: **8300**
- Base de datos: `vant_inventory`
- Prefijo URL: `/api/`

## Descripcion

Es el backend de los **VANT-Agent** desplegados en los endpoints. Mantiene el ciclo de vida del agente (registro, heartbeat, config push, comandos), el inventario de hardware/software y telemetria (screen captures, procesos, servicios).

## Estructura

```
vant-inventory/
├── config/
├── inventory_app/
│   ├── models.py      # Agent, HardwareInventory, SoftwareInventory, AgentCommand, ...
│   ├── views.py       # view functions + DRF ViewSets
│   └── urls.py        # /api/... + router
└── manage.py
```

## Modelos

| Modelo | Funcion |
|--------|---------|
| `Agent` | Agente endpoint registrado (id, nombre, IP, version, estado) |
| `HardwareInventory` | Inventario de hardware |
| `SoftwareInventory` | Software instalado |
| `AgentCommand` | Comandos remotos pendientes/enviados |
| `ScreenCapture` | Capturas de pantalla |
| `ProcessSnapshot` | Snapshot de procesos |
| `AgentService` | Servicios monitoreados del agente |

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/api/health/` | GET | Health check |
| `/api/stats/dashboard/` | GET | Estadisticas para dashboard |
| `/api/register/` | POST | Registro de agente |
| `/api/heartbeat/` | POST | Heartbeat (agente -> servidor) |
| `/api/inventory/submit/` | POST | Envio de inventario hardware/software |
| `/api/command-result/` | POST | Resultado de un comando remoto |
| `/api/screen/upload/` | POST | Subir captura de pantalla |
| `/api/screen/latest/<agent_id>/` | GET | Ultima captura |
| `/api/processes/upload/` | POST | Subir snapshot de procesos |
| `/api/processes/latest/<agent_id>/` | GET | Ultimo snapshot |
| `/api/commands/pull/` | POST | Agente descarga comandos pendientes |
| `/api/agents/<agent_id>/command/` | POST | Servidor envia comando |
| `/api/agents/<agent_id>/delete/` | DELETE | Eliminar agente |
| `/api/agents/<agent_id>/services/report/` | POST | Reporte de servicios monitoreados |
| `/api/agents/<agent_id>/services/` | GET | Listar servicios |
| `/api/agents/<agent_id>/services/toggle/` | POST | Activar/desactivar monitoreo de servicio |

Ademas expone un **DRF router** (ViewSets) bajo `/api/` para los modelos.

## Configuracion

| Variable | Uso |
|----------|-----|
| `INVENTORY_SERVICE_URL` | URL interna |
| `AGENT_HEARTBEAT_INTERVAL` | Intervalo recomendado de heartbeat |
| `AGENT_INVENTORY_INTERVAL` | Intervalo de inventario |
| `SERVICE_SECRET` | Autorizacion |

## Integracion

- `VANT-Agent` usa: `register`, `heartbeat`, `inventory/submit`, `commands/pull`, `screen/upload`, `processes/upload`, `services/report`.
- El dashboard `vant-web` consume todo via `get_agents()`, `send_agent_command()`, etc.
