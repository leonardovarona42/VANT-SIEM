# VANT-SIEM — Issues de Madurez Operacional

> Auditoría realizada el 2026-08-18. Cada issue tiene prioridad, esfuerzo estimado y estado.

---

## Estado general

| Categoría | Issues | Cerrados |
|-----------|--------|----------|
| Seguridad | 8 | 0 |
| Testing | 2 | 0 |
| Deployment | 3 | 0 |
| Monitoreo | 3 | 0 |
| Datos/Retention | 3 | 0 |
| Código | 3 | 0 |
| **Total** | **22** | **0** |

---

## SEGURIDAD (Prioridad crítica)

### SEC-01: API SOC abierta sin autenticación
- **Severidad**: Crítica
- **Descripción**: `GET /soc/api/` devuelve 22 endpoints con datos sensibles (incidentes, reportes con emails, IPs internas, servicios) sin login. `POST /soc/api/db/backups/` permite escritura sin autenticación.
- **Endpoint**: `/soc/api/*`
- **Evidencia**: `curl -sk https://host/soc/api/reportes/` → 200, 1528 registros con nombres y emails.
- **Fix**: Añadir `IsAuthenticated` o token a todos los ViewSets de SOC. Priorizar endpoints con datos personales.
- **Estado**: Pendiente
- **Esfuerzo**: 0.5 días

### SEC-02: Django DEBUG=True en producción
- **Severidad**: Alta
- **Descripción**: Las páginas 404 muestran la página de depuración de Django (stack trace, settings, URLs). Solo visible con DEBUG activo.
- **Endpoint**: Cualquier URL inexistente (ej. `/api/alerts/`).
- **Evidencia**: `curl -sk https://host/api/alerts/` → página "Page not found" con detalles de Django.
- **Fix**: Verificar `DJANGO_DEBUG` en `.env` del server (puede estar en un settings.py local o sobreescribiendo). Asegurar que `.env` tiene `DJANGO_DEBUG=false`.
- **Estado**: Pendiente
- **Esfuerzo**: 0.25 días

### SEC-03: Session fixation en login web
- **Severidad**: Media
- **Descripción**: `login_view()` en `web_app/views.py:68-101` guarda la sesión manualmente sin `cycle_key()` ni `flush()`. Un atacante puede fijar una sessionid antes del login y hijackear la sesión.
- **Archivo**: `vant-web/web_app/views.py:68-101`
- **Fix**: Llamar `request.session.cycle_key()` después de `request.session.save()`, o usar `django.contrib.auth.login()` en vez de guardar la sesión manualmente.
- **Estado**: Pendiente
- **Esfuerzo**: 0.1 días

### SEC-04: Lockout permanente de cuentas (DoS)
- **Severidad**: Media
- **Descripción**: 5 contraseñas fallidas → `is_active=False` **permanente**, sin ventana temporal ni reset automático. Un atacante puede bloquear cualquier cuenta (incl. admin) sin necesidad de escribir datos.
- **Archivo**: `vant-auth/auth_app/views.py:150-172`
- **Fix**: Implementar lockout con ventana temporal (ej. 15 min) o incrementar contador por IP, no por cuenta. La cuenta `admin` del sistema ya está bloqueada por esto.
- **Estado**: Pendiente
- **Esfuerzo**: 0.5 días

### SEC-05: Registro de agentes sin autenticar
- **Severidad**: Alta
- **Descripción**: `AgentRegisterView` en `auth_app/views.py:264-290` no requiere service secret ni token admin. Cualquiera puede solicitar un token de agente válido, y esos tokens son confiados por el middleware de todos los servicios.
- **Archivo**: `vant-auth/auth_app/views.py:264-290`
- **Fix**: Añadir `require_service_secret` o `require_auth` al view. Alternativamente, generar tokens de agente solo vía CLI con credenciales de admin.
- **Estado**: Pendiente
- **Esfuerzo**: 0.25 días

### SEC-06: Headers de seguridad ausentes
- **Severidad**: Media
- **Descripción**: No hay `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Strict-Transport-Security`, `Referrer-Policy`. Expuesto a clickjacking, sniffing, y buffering de MIME.
- **Fix**: Añadir en nginx (bloque `server`):
  ```
  add_header X-Frame-Options "DENY" always;
  add_header X-Content-Type-Options "nosniff" always;
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;
  ```
- **Estado**: Pendiente
- **Esfuerzo**: 0.1 días

### SEC-07: Cookie csrftoken sin Secure/HttpOnly
- **Severidad**: Baja
- **Descripción**: `CSRF_COOKIE_SECURE` y `CSRF_COOKIE_HTTPONLY` no están definidos en settings. La cookie csrftoken se envía sin flags `Secure` ni `HttpOnly`.
- **Archivo**: `vant-web/config/settings.py`
- **Fix**: Añadir `CSRF_COOKIE_SECURE = not DEBUG` y `CSRF_COOKIE_HTTPONLY = True`.
- **Estado**: Pendiente
- **Esfuerzo**: 0.05 días

### SEC-08: Login web sin rate-limiting real
- **Severidad**: Baja
- **Descripción**: El endpoint de login (`/siem/dashboard/login/`) no tiene rate-limit a nivel Django. nginx usa `zone=api_user rate=20r/s burst=10` que es insuficiente contra fuerza bruta.
- **Archivo**: `scripts/nginx-vantsiem.conf`
- **Fix**: Reducir a `rate=5r/s burst=3` solo para el login, o implementar throttling en la view con django-ratelimit.
- **Estado**: Pendiente
- **Esfuerzo**: 0.25 días

---

## TESTING (Prioridad alta)

### TEST-01: Sin tests unitarios
- **Severidad**: Alta
- **Descripción**: No existe un solo archivo `test_*.py` en ningún servicio. Cualquier cambio puede romper funcionalidad crítica sin detección.
- **Fix**: Crear tests mínimos para:
  - Login/auth flow (auth)
  - CRUD de incidentes SOC (soc)
  - Endpoints de API con/without auth (todos)
  - Filtros de búsqueda y paginación
- **Estado**: Pendiente
- **Esfuerzo**: 2-3 días

### TEST-02: Sin tests de integración
- **Severidad**: Media
- **Descripción**: No hay tests que validen la comunicación entre servicios (web → soc, web → auth, etc.).
- **Fix**: Tests con `testcontainers` o fixtures mockeadas para verificar el flujo completo: login → cargar dashboard → crear incidente → ver reporte.
- **Estado**: Pendiente
- **Esfuerzo**: 1-2 días

---

## DEPLOYMENT (Prioridad alta)

### DEP-01: No hay Docker/containerización
- **Severidad**: Alta
- **Descripción**: El sistema corre como servicios systemd con un venv Python compartido. No es reproducible: si el server muere, hay que reconstruir manualmente.
- **Fix**: Crear `Dockerfile` por servicio + `docker-compose.yml` para el stack completo. Cada servicio containerizado con su propio venv.
- **Estado**: Pendiente
- **Esfuerzo**: 2-3 días

### DEP-02: No hay CI/CD
- **Severidad**: Alta
- **Descripción**: Deployment manual con paramiko y scripts bash. No hay pipeline de validación antes de deploy.
- **Fix**: GitHub Actions mínimo: lint → test → build Docker → push a registry. Deploy manual o con tag.
- **Estado**: Pendiente
- **Esfuerzo**: 1 día

### DEP-03: Repo incompleto vs server
- **Severidad**: Media
- **Descripción**: Template `intelligence_geo_report.html` y endpoint `analytics/geo/report/` existían en server pero no en el repo. Commit `0052397` dice "sin seccion reportes" pero la función estaba deployada.
- **Fix**: Proceso de deploy: siempre commitear antes de deployar. Agregar step de verificación: `git status` limpio antes de push.
- **Estado**: Parcialmente resuelto (template sincronizado 2026-08-18)
- **Esfuerzo**: 0 (proceso, no código)

---

## MONITOREO (Prioridad media)

### MON-01: Sin métricas de aplicación
- **Severidad**: Media
- **Descripción**: No hay Prometheus/Grafana ni exportadores de métricas. Los health checks solo verifican si el proceso está vivo, no la calidad del servicio.
- **Fix**: Instalar `django-prometheus` en cada servicio, configurar Prometheus para scraping, dashboard básico de latencia/error rate.
- **Estado**: Pendiente
- **Esfuerzo**: 1-2 días

### MON-02: Sin alertas de disco/ram/cpu
- **Severidad**: Alta
- **Descripción**: El disco llegó al 100% sin alerta. No hay monitoreo de recursos del sistema.
- **Fix**: Instalar `node_exporter` + Prometheus alert rules para disco >80%, RAM >90%, CPU >95%.
- **Estado**: Pendiente
- **Esfuerzo**: 0.5 días

### MON-03: Sin logs centralizados
- **Severidad**: Media
- **Descripción**: Cada servicio escribe a su propio archivo de log. No hay correlación entre servicios ni búsqueda centralizada.
- **Fix**: Configurar cada servicio para enviar logs a stdout → docker log driver, o instalar Filebeat/Fluentd que envíe a una instancia central (Elasticsearch ya está corriendo).
- **Estado**: Pendiente
- **Esfuerzo**: 1 día

---

## DATOS / RETENTION (Prioridad media)

### DAT-01: Sin política de retención de datos
- **Severidad**: Media
- **Descripción**: Las tablas de logs (`logs_events_raw`, `vant_soc`, etc.) crecen indefinidamente. Sin retención, la BD crecerá hasta llenar el disco.
- **Fix**: Implementar cron de limpieza: `DELETE FROM logs_events_raw WHERE event_time < NOW() - INTERVAL '90 days'`. Mantener tablas de configuración (incidentes, reportes) sin retención.
- **Estado**: Pendiente
- **Esfuerzo**: 0.5 días

### DAT-02: Backups sin verificación automática
- **Severidad**: Media
- **Descripción**: El cron de backup corre diariamente pero no verifica que los dumps sean restaurables. Un backup corrupto es peor que no tener backup.
- **Fix**: Añadir al script de backup: crear DB temporal, restaurar dump, verificar tablas, eliminar DB temporal. Logear resultado.
- **Estado**: Pendiente
- **Esfuerzo**: 0.5 días

### DAT-03: Discos sin partición dedicada para datos
- **Severidad**: Baja
- **Descripción**: PostgreSQL, Elasticsearch, y logs están en particiones que comparten espacio con el sistema. Si la BD crece, el OS se queda sin espacio.
- **Fix**: En servidor actual: mover PostgreSQL a `/srv` (ya tiene symlink del venv). En futuros servidores: partición dedicada `/data` para PostgreSQL + Elasticsearch.
- **Estado**: Pendiente
- **Esfuerzo**: 0.5 días (migración PG a /srv)

---

## CÓDIGO (Prioridad baja)

### CODE-01: Duplicación de código entre servicios
- **Severidad**: Baja
- **Descripción**: `http_client.py`, middleware de auth, y patrones de logging están duplicados en cada servicio. `shared/vant_common/` existe pero no se usa consistente.
- **Fix**: Mover toda lógica compartida a `shared/vant_common/` e instalarlo como paquete (`pip install -e ../shared`). Cada servicio importa en vez de copiar.
- **Estado**: Pendiente
- **Esfuerzo**: 1 día

### CODE-02: Sin documentación de API
- **Severidad**: Baja
- **Descripción**: No hay Swagger/OpenAPI ni documentación de endpoints. Los endpoints se descubren por inspección de `urls.py`.
- **Fix**: Instalar `drf-spectacular` en cada servicio con ViewSets. Generar docs automáticas.
- **Estado**: Pendiente
- **Esfuerzo**: 1 día

### CODE-03: Gestión inconsistente de errores
- **Severidad**: Baja
- **Descripción**: Algunos views devuelven `JsonResponse({"error": str(e)}, status=500)`, otros levantan excepciones, otros devuelven HTML genérico. No hay patrón consistente.
- **Fix**: Crear un middleware de excepciones que capture errores no manejados y devuelva JSON consistente: `{"error": {"code": 500, "message": "...", "service": "soc"}}`.
- **Estado**: Pendiente
- **Esfuerzo**: 0.5 días

---

## Roadmap sugerido

### Semana 1 — Seguridad crítica
- [ ] SEC-01: Cerrar API SOC
- [ ] SEC-02: Apagar DEBUG
- [ ] SEC-03: Fix session fixation
- [ ] SEC-05: Autenticar registro de agentes
- [ ] SEC-06: Headers nginx
- [ ] SEC-07: CSRF cookie flags

### Semana 2 — Operaciones
- [ ] SEC-04: Fix lockout (con ventana temporal)
- [ ] SEC-08: Rate-limit login
- [ ] MON-02: Alertas de disco
- [ ] DAT-01: Retención de datos
- [ ] DAT-02: Verificación de backups
- [ ] DEP-03: Proceso de deploy

### Semana 3 — Testing + CI
- [ ] TEST-01: Tests unitarios mínimos
- [ ] DEP-02: CI pipeline básico
- [ ] DEP-01: Docker compose

### Semana 4 — Monitoreo + Código
- [ ] MON-01: Métricas Prometheus
- [ ] MON-03: Logs centralizados
- [ ] CODE-01: Shared package
- [ ] CODE-02: API docs
- [ ] CODE-03: Error handling consistente
- [ ] DAT-03: Migrar PG a /srv
