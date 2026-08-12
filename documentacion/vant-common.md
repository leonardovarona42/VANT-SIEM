# vant-common

Libreria **compartida** entre todos los microservicios de VANT-SERVICES.

- Ubicacion: `shared/vant_common/`
- Instalacion: `pip install -e shared/` (o copia en el venv del servidor)

## Descripcion

Contiene los componentes comunes que todos los servicios Django reutilizan: autenticacion entre servicios, cliente del bus (Redis Streams), cliente HTTP interno y middleware de timing/seguridad.

## Archivos

| Archivo | Contenido |
|---------|-----------|
| `auth.py` | Helpers de autenticacion entre servicios (validar JWT / `SERVICE_SECRET`) |
| `bus.py` | `EventBus` - publicacion y suscripcion a **Redis Streams** |
| `http_client.py` | Cliente HTTP base para llamadas internas |
| `middleware.py` | Middleware Django (timing de requests `slow_request`, seguridad) |

## EventBus (`bus.py`)

Cliente de comunicacion en tiempo real sobre **Redis Streams**.

- `REDIS_URL` por defecto `redis://127.0.0.1:6379/3` (el servidor usa `redis://127.0.0.1:6379/0` via `.env`).
- `publish_event(stream_key, event_type, payload, source_service)` - publica un evento en un stream.
- `subscribe(stream_key, callback, group, consumer)` - consume con **consumer groups** (`xreadgroup`); los timeouts de bloqueo sin mensajes son **silenciosos** (no son errores).
- `_redis` - instancia `redis.Redis`.

> Nota de despliegue: en el servidor el paquete puede quedar instalado como **copia** en `site-packages` (no editable). Si se modifica `shared/vant_common/bus.py`, hay que copiar el cambio tambien a `/opt/vant-siem/venv/lib/python3.13/site-packages/vant_common/` para que los servicios en ejecucion lo tomen, y reiniciarlos.

## Middleware (`middleware.py`)

- `RequestTimingMiddleware`: loguea requests lentos como `slow_request method=GET path=... elapsed=Xs` (utilizado en todos los servicios).

## Auth (`auth.py`)

- Validacion de `SERVICE_SECRET` para autorizar llamadas entre servicios internos.
- Helpers para comprobar tokens JWT de usuarios y agentes.
