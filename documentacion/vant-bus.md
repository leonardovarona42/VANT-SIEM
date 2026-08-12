# vant-bus

Servicio de **bus de eventos, notificaciones y salud de servicios**.

- Puerto: **8600**
- Base de datos: `vant_bus`
- Prefijo URL: `/api/`

## Descripcion

Centraliza el registro de **eventos de sistema** (SystemEvent), la gestion de **grupos, suscripciones y notificaciones** (email/telegram/webhook), la **configuracion y salud de servicios** y los **canales de alerta**. Se apoya en **Redis Streams** para el transporte de eventos en tiempo real (`vant_common.bus.EventBus`).

## Estructura

```
vant-bus/
├── config/
├── bus_app/
│   ├── event_bus.py       # capa Redis Streams
│   ├── alert_dispatch.py  # dispatch de alertas (email, telegram, webhook)
│   ├── models.py          # 10 modelos (ver abajo)
│   ├── views.py
│   └── urls.py
└── manage.py
```

## Modelos

| Modelo | Funcion |
|--------|---------|
| `SystemEvent` | Eventos de sistema registrados por todos los servicios |
| `NotificationGroup` | Grupos de notificacion |
| `GroupMember` | Miembros de un grupo |
| `GroupAlertSubscription` | Suscripciones de un grupo a alertas |
| `EmailConfig` | Configuracion SMTP |
| `NotificationLog` | Registro de notificaciones enviadas |
| `ServiceConfig` | Registro de servicios (estado, flags) |
| `ServiceHealthLog` | Historial de salud de servicios |
| `AlertChannel` | Canales de alerta |
| `AlertHistory` | Historial de alertas enviadas |

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/api/events/` | GET | Listar eventos |
| `/api/events/receive/` | POST | Registrar un SystemEvent (usado por otros servicios) |
| `/api/events/<id>/` | GET | Detalle de evento |
| `/api/events/recent/` | GET | Eventos recientes |
| `/api/events/<stream>/stream/` | GET | Eventos de un stream |
| `/api/groups/` | GET/POST | Listar/crear grupos |
| `/api/groups/<id>/` | GET | Detalle de grupo |
| `/api/groups/<id>/members/` | GET/POST | Miembros |
| `/api/subscriptions/` | GET/POST | Suscripciones |
| `/api/subscriptions/<id>/` | DELETE | Eliminar suscripcion |
| `/api/notifications/` | GET | Listar notificaciones |
| `/api/notifications/<id>/read/` | POST | Marcar leida |
| `/api/notifications/read-all/` | POST | Marcar todas leidas |
| `/api/email-config/` | GET/POST | Configuracion SMTP |
| `/api/email-config/test/` | POST | Probar envio |
| `/api/services/` | GET/POST | Servicios |
| `/api/services/<id>/` | GET | Detalle |
| `/api/services/<id>/health/` | GET | Historial de salud |
| `/api/services/<id>/<action>/` | POST | Accion (start/stop/restart) |
| `/api/dashboard/` | GET | Resumen del dashboard |
| `/api/stats/` | GET | Estadisticas |
| `/api/alerts/send/` | POST | Enviar alerta |
| `/api/alerts/history/` | GET | Historial de alertas |
| `/api/alerts/config/` | GET/POST | Config de alertas |
| `/api/health/` | GET | Health check |

## Configuracion

| Variable | Uso |
|----------|-----|
| `REDIS_URL` | Broker de Redis (`redis://127.0.0.1:6379/0`) |
| `REDIS_STREAM_MAX_LEN` | Max length de streams |
| `ALERT_EMAIL_*` | SMTP para alertas email |
| `ALERT_TELEGRAM_*` | Bot token / chat id |
| `ALERT_WEBHOOK_*` | Webhook de alertas |

## Integracion

- `vant_common.bus.EventBus` (libreria compartida) es el cliente usado por todos los servicios para `publish_event()` y `subscribe()` a streams Redis.
- Ejemplo en SOAR: `vant-soar` publica predicciones al stream **`threats`** y `vant-soc` (consumidor `consume_soar_events`) las consume para crear reportes.
- El dashboard `vant-web` lee eventos/notificaciones via `bus_*` de `http_client.py`.
