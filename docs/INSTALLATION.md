# Instalacion VANT-SIEM + OpenSearch

## Requisitos

- Python 3.13+
- PostgreSQL 14+
- Windows o Linux

## 1) SIEM Django

```bash
python -m venv venv
# Linux: source venv/bin/activate
# Windows: .\\venv\\Scripts\\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

Configurar la base principal en `CORE/settings.py`.

## 2) Base de datos dedicada OpenSearch

Crear la base separada para logs y aplicar el schema:

```bash
psql -U postgres -d vant_opensearch -f opensearch_service/service/schema.sql
```

Variables recomendadas:

- `OS_DB_HOST`
- `OS_DB_PORT`
- `OS_DB_NAME`
- `OS_DB_USER`
- `OS_DB_PASSWORD`

## 3) Servicio OpenSearch en Windows

Instalar la tarea del microservicio:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_service\service\install_windows_service.ps1
```

Validar health:

```powershell
Invoke-RestMethod http://127.0.0.1:9201/health
```

## 4) Agente OpenSearch

### Windows

Ejecutar:

```powershell
.\opensearch_agents\windows\opensearch_agent_setup.exe
```

Durante `Probar conexion`, el wizard ya hace:

- consulta de `bootstrap`
- enrolamiento firmado
- validacion del token del agente
- prueba del endpoint de ingesta

El instalador incluye:

- perfil de auditoria de Active Directory para Windows Server
- `asset_audit` para inventario y timeline del endpoint
- `aegis_dlp` para deteccion de informacion clasificada y sensible
- `sendheartbeat.exe`, `opena_mover.exe` y `opena_checker.exe`
- desinstalador y registro en Windows
- ACL endurecida sobre el directorio de instalacion

Canales recomendados para Active Directory:

- `Security`
- `System`
- `Application`
- `Directory Service`
- `DNS Server`
- `DFS Replication`
- `Active Directory Web Services`

### Linux

Guias por distro:

- `opensearch_agents/linux/debian/README.md`
- `opensearch_agents/linux/ubuntu/README.md`
- `opensearch_agents/linux/zentyal/README.md`

Construccion del bundle offline:

```bash
./opensearch_agents/linux/build_linux.sh
```

Utilidades incluidas:

- `sendheartbeat`
- `opena_mover`
- `opena_checker`
- `opena_enroll`

Enrolamiento manual:

```bash
sudo opena_enroll
sudo opena_enroll --enrollment-code CODIGO-DEL-TICKET
sudo opena_enroll --bootstrap-key MI-SECRETO
```

Variables de backend relacionadas:

- `VANT_AGENT_ALLOWED`
- `VANT_AGENT_SHARED_SECRET`
- `VANT_AGENT_REQUIRE_ENROLLMENT_TICKET=1`

## 5) OpenSearch UI

Accesos:

- Dashboard: `http://localhost:8000/opensearch/`
- Discovery: `http://localhost:8000/opensearch/discover/`

## Verificacion rapida

1. El servicio responde en `/health`.
2. El agente fue enrolado y tiene `output.auth.token`.
3. El agente esta en ejecucion.
4. `os_events_raw` incrementa registros.
5. Discovery muestra datos y filtros funcionales.
