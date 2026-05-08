# VANT-SIEM Roadmap

> Última actualización: 2026-05-07 | Version: 3.0

## Estado Actual (v3.0)

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
- [x] Database Router implementado (`CORE/db_router.py`) con 3 routers
- [x] 4 bases de datos PostgreSQL aisladas: `vant_siem`, `vant_logs`, `vant_inventory`, `vant_dlp`
- [x] Docker Compose con 5 contenedores PostgreSQL, Redis, service bus
- [x] DLP Microservice completo: modelos, API REST, UI de gestion
- [x] DLP: Politicas (`DlpPolicy`) con paths, extensiones, tamano max
- [x] DLP: Reglas (`DlpRule`) keyword/regex/metadata con severidad
- [x] DLP: Incidentes (`DlpIncident`) con fingerprint unico y dedup
- [x] DLP: Escaneos (`DlpScanSummary`) con resumen de ejecuciones
- [x] DLP: API para agente (`/dlp/api/agent/dlp/config/`, `/dlp/api/agent/dlp/threats/`)
- [x] DLP: UI completa (dashboard, incidentes, politicas, reglas, escaneos)
- [x] INVENTORY: Modelos `Agent`, `AgentSoftware`, `AgentCommand` con BD aislada
- [x] INVENTORY: API de heartbeat, inventory submit, config pull, comandos
- [x] INVENTORY: UI de agentes con dashboard, lista, detalle, config push
- [x] Logs Service auto-spawn via management command en standalone mode
- [x] Assets Service auto-spawn via management command en standalone mode
- [x] JSON array parsing en `file_log.py` con dedup por `id`/`event_id`
- [x] TimescaleDB integrado para `logs_events_raw` con hypertables
- [x] VANT-Agent JSON parsing con soporte UTF-8 BOM
- [x] VANT-Agent con collectors: windows_eventlog, file_log, aegis_dlp, inventory
- [x] Agente ejecutable Windows con PyInstaller + PyQt6 tray mode

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
- [ ] Aislar completamente en proceso separado (Docker)
- [ ] Bulk ingest API (`/api/logs/bulk/`)
- [ ] Query API con filtros avanzados
- [ ] Retention policies (auto-delete logs > N dias)

### 4.2 Incidents Service (Puerto 8001)
- [ ] Aislar EVENT_M en proceso separado
- [ ] API REST para incidentes
- [ ] Auto-creacion desde Service Bus
- [ ] Reportes y compliance

### 4.3 Assets Service (Puerto 8002)
- [ ] Aislar inventory + DLP en proceso separado (Docker)
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
- [x] `/logs/api/bulk/` - Envio de logs al Logs Service
- [x] `/inventory/api/inventory/submit/` - Envio de inventario
- [x] `/inventory/api/heartbeat/` - Heartbeat + pull de comandos
- [x] `/dlp/api/agent/dlp/config/` - Config DLP para agente
- [x] `/dlp/api/agent/dlp/threats/` - Envio de incidentes DLP
- [ ] `/api/assets/enroll/` - Registro/bootstrap de agente

### 5.2 Agent Commands
- [x] Issue commands desde Web Portal
- [x] Agent pull de comandos pendientes
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
