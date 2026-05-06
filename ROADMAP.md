# VANT-SIEM Roadmap

> Última actualización: 2026-05-06 | Version: 2.1

## Estado Actual (v2.1)

### Completado

- [x] Repositorio VANT-Agent separado (`github.com/leonardovarona42/VANT-Agent`)
- [x] Directorio `opensearch_agents/` eliminado del proyecto principal
- [x] Directorio `collector/` eliminado
- [x] Directorio `inventory/` eliminado (funcionalidades movidas a servicios)
- [x] Directorio `opensearch_service/` eliminado (aislado en Logs Service)
- [x] Directorio `opensearch_ui/` eliminado (funcionalidades consolidadas)
- [x] Directorio `scripts/` eliminado
- [x] Archivos Docker movidos a `docker_deployment/`
- [x] Scripts standalone creados (`startup.sh`, `stop.sh`, `status.sh`)
- [x] Service Bus definido (`CORE/service_bus.py`)
- [x] Tipos de eventos definidos (`CORE/events.py`)
- [x] Celery configurado (`CORE/celery.py`)
- [x] Tasks async en EVENT_M y VANT_SIEM
- [x] `docker-compose.yml` con 5 bases de datos PostgreSQL
- [x] Modulos legacy eliminados (IRIS, Ollama, ai_models)
- [x] `Subred` modelo eliminado, fusionado en `Servicio`
- [x] Servicio como modelo unificado de red (host, switch, router, firewall, VLAN, subred, segmento, red, cluster, plataforma, servicio_externo)
- [x] Campos de red en Servicio: network, subnet_mask, gateway, red_tipo, DHCP
- [x] Topologia visual con vis-network (esquema fisico y logico)
- [x] Fullscreen en esquemas de topologia
- [x] Vista de arbol de redes con expand/collapse
- [x] Vista de detalle de subred: IPs asignadas, hosts activos, % uso, stats
- [x] Paginacion en todas las vistas de listas
- [x] Busqueda en tiempo real en listas
- [x] Formulario dinamico de servicio con secciones por tipo

### En progreso

- [ ] Implementar `CORE/db_router.py` para enrutar modelos a BDs correctas
- [ ] Completar management commands para servicios aislados
- [ ] URLs API por servicio (`/api/logs/`, `/api/incidents/`, `/api/network/`)
- [ ] Health check endpoints por servicio
- [ ] API contracts entre servicios

---

## Fase 2: Separacion de Bases de Datos (Semana 2-3)

### 2.1 Database Router
- [ ] Implementar `CORE/db_router.py`
- [ ] Configurar 5 conexiones en `settings.py`:
  - `default` → `vant_siem` (users, auth, config)
  - `logs` → `vant_logs` (LogEvent, LogSource)
  - `incidents` → `vant_incidents` (EVENT_M models)
  - `assets` → `vant_assets` (inventory, DLP, agents)
  - `network` → `vant_network` (Servicio, ServicioIP, PuertoDispositivo)

### 2.2 Migraciones por BD
- [ ] `makemigrations` para cada base de datos
- [ ] Scripts de migracion de datos existentes
- [ ] Testing de queries cross-database

### 2.3 Docker Compose
- [x] 5 contenedores PostgreSQL con volumenes separados
- [x] Servicios aislados con health checks
- [x] Redis para Service Bus y Celery
- [x] Variables de entorno en `.env.example`

---

## Fase 3: Service Bus y Comunicacion (Semana 3-4)

### 3.1 Service Bus (Redis Pub/Sub)
- [x] Implementacion base `CORE/service_bus.py`
- [x] Tipos de eventos definidos `CORE/events.py`
- [ ] Completar canales:
  - `vant:log.alert` → Logs → Incidents
  - `vant:asset.dlp` → Assets → Incidents
  - `vant:incident.created` → Incidents → Notifications
  - `vant:network.change` → Network → Assets
- [ ] Implementar retry y dead-letter queue
- [ ] Logging de eventos pub/sub

### 3.2 Service Registry
- [ ] Health check endpoint por servicio (`/health/`)
- [ ] Service discovery basico
- [ ] Timeout y circuit breaker entre servicios

### 3.3 API Contracts
- [ ] Documentar APIs de cada servicio
- [ ] Versionado de APIs (`/api/v1/logs/`, etc.)
- [ ] Auth tokens entre servicios

---

## Fase 4: Servicios Independientes (Semana 4-6)

### 4.1 Logs Service (Puerto 9201)
- [ ] Aislar completamente en proceso separado
- [ ] Bulk ingest API (`/api/logs/bulk/`)
- [ ] Query API con filtros avanzados
- [ ] Retention policies (auto-delete logs > N dias)

### 4.2 Incidents Service (Puerto 8001)
- [ ] Aislar EVENT_M en proceso separado
- [ ] API REST para incidentes
- [ ] Auto-creacion desde Service Bus
- [ ] Reportes y compliance

### 4.3 Assets Service (Puerto 8002)
- [ ] Aislar inventory + DLP en proceso separado
- [ ] Agent management API
- [ ] Inventory sync
- [ ] DLP policies e incidentes

### 4.4 Network Service (Puerto 8004)
- [x] Modelo Servicio unificado implementado
- [x] Gestion de subredes, VLANs, segmentos
- [x] Topologia visual (fisico y logico)
- [ ] API REST para servicios de red
- [ ] Integracion con Assets Service
- [ ] IPAM completo (scan de red, discovery)

### 4.5 AI Service (Puerto 8003) - Placeholder
- [ ] Estructura base del servicio
- [ ] Endpoint para analisis futuro
- [ ] Integracion con LLM (futuro)

---

## Fase 5: Integracion con VANT-Agent (Semana 5-6)

### 5.1 Agent API Endpoints
- [ ] `/api/assets/enroll/` - Registro de agente
- [ ] `/api/assets/heartbeat/` - Heartbeat
- [ ] `/api/logs/bulk/` - Envio de logs al Logs Service
- [ ] `/api/assets/inventory/` - Envio de inventario al Assets Service
- [ ] `/api/assets/dlp/incident/` - Envio de incidentes DLP

### 5.2 Agent Commands
- [ ] Issue commands desde Web Portal
- [ ] Agent pull de comandos pendientes
- [ ] Ack de comandos ejecutados

### 5.3 Agent Auth
- [ ] Bootstrap secret
- [ ] Token-based auth
- [ ] Allowlist de agentes

---

## Fase 6: Deploy y Operaciones (Semana 6-7)

### 6.1 Docker
- [x] Dockerfiles por servicio (estructura base)
- [x] `docker-compose.yml` completo
- [ ] Health checks funcionales
- [ ] Logging centralizado

### 6.2 Standalone (Linux)
- [x] `startup.sh` - Iniciar todos los servicios
- [x] `stop.sh` - Detener todos los servicios
- [x] `status.sh` - Ver estado de cada servicio
- [ ] Systemd service files

### 6.3 Monitoreo
- [ ] Dashboard de estado de servicios
- [ ] Metricas por servicio
- [ ] Alertas de servicio caido

---

## Fase 7: Testing y CI/CD (Semana 7-8)

### 7.1 Tests
- [ ] Unit tests por servicio
- [ ] Integration tests (Service Bus)
- [ ] Load tests (Logs Service)

### 7.2 CI/CD
- [ ] GitHub Actions para linting y tests
- [ ] Build Docker images en PR merge
- [ ] Deploy automatico a staging

---

## Decisiones Pendientes

1. **Storage de logs a largo plazo** - ¿ClickHouse? ¿Elasticsearch? ¿Seguir con PostgreSQL?
2. **AI Service** - ¿Que LLM usar? ¿Local o cloud?
3. **Message broker** - ¿Solo Redis? ¿RabbitMQ para mayor robustez?
4. **Frontend** - ¿Seguir con Django templates? ¿Migrar a SPA?
5. **Monitoring** - ¿Prometheus + Grafana? ¿OpenTelemetry?
