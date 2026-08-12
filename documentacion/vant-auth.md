# vant-auth

Servicio de **autenticacion y gestion de usuarios** de VANT-SERVICES.

- Puerto: **8100**
- Base de datos: `vant_auth`
- Prefijo URL: `/auth/api/`

## Descripcion

Emiten y validan **tokens JWT** para usuarios del dashboard y para **agentes endpoint** (VANT-Agent). Centraliza: login/logout/refresh, gestion de usuarios del SIEM, tokens de agentes y auditoria de acceso.

## Estructura

```
vant-auth/
├── config/            # settings, urls (prefijo /auth/)
├── auth_app/
│   ├── models.py      # AuthUser, AuthAgentToken, AuthAuditLog
│   ├── views.py       # LoginView, UserListView, agent views, ...
│   ├── serializers.py
│   └── urls.py        # rutas /api/...
└── manage.py
```

## Modelos

| Modelo | Tabla | Funcion |
|--------|-------|---------|
| `AuthUser` | auth_users | Usuario del SIEM (username, email, role, password, activo) |
| `AuthAgentToken` | auth_agent_tokens | Token por agente (para autenticar ingestas) |
| `AuthAuditLog` | auth_audit_log | Auditoria de accesos y operaciones |

## Endpoints

| Ruta | Metodo | Funcion |
|------|--------|---------|
| `/auth/api/login/` | POST | Login con usuario/contraseña, devuelve JWT (access/refresh) |
| `/auth/api/refresh/` | POST | Refresca el JWT de acceso |
| `/auth/api/logout/` | POST | Invalida la sesion |
| `/auth/api/validate/` | POST | Valida un token JWT |
| `/auth/api/agent/register/` | POST | Registra un agente endpoint |
| `/auth/api/agent/token/create/` | POST | Crea token para agente |
| `/auth/api/agent/validate/` | POST | Valida token de agente |
| `/auth/api/agent/revoke/` | POST | Revoca token de agente |
| `/auth/api/users/` | GET | Lista de usuarios |
| `/auth/api/users/me/` | GET | Usuario actual |
| `/auth/api/users/create/` | POST | Crear usuario |
| `/auth/api/users/<id>/` | PATCH | Actualizar usuario |
| `/auth/api/users/<id>/delete/` | DELETE | Eliminar usuario |
| `/auth/api/users/<id>/reset-password/` | POST | Resetear contrasena |
| `/auth/api/users/change-password/` | POST | Cambiar contrasena propia |
| `/auth/api/health/` | GET | Health check |

## Configuracion

| Variable | Uso |
|----------|-----|
| `JWT_SECRET` | Secreto para firmar tokens |
| `JWT_ACCESS_TTL` | TTL del access token |
| `JWT_REFRESH_TTL` | TTL del refresh token |
| `SERVICE_SECRET` | Secreto de confianza entre servicios |

## Integracion

- `vant-web` guarda el `jwt_token` en la sesion del usuario tras login y lo usa para autorizar (`_require_auth`).
- Los agentes usan tokens de `AuthAgentToken` para autenticar las ingestas contra `vant-logs` / `vant-inventory`.
- `vant_common.auth` provee helpers para validar tokens entre servicios.
