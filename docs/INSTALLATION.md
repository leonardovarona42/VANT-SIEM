# Instalacion VANT-SIEM + OpenSearch

## Objetivo

Esta guia concentra:

- instalacion base del SIEM
- despliegue de servicios Django y OpenSearch
- despliegue y enrolamiento del agente
- flujo de referencia para Debian WSL

## Requisitos

- Python 3.13+
- PostgreSQL 14+
- Windows o Linux

## 1) Componentes del despliegue

El stack operativo queda dividido asi:

1. `VANT-SIEM Django` en `:8000`
2. `OpenSearch Service` en `:9201`
3. `OpenSearch Agent` en el endpoint o en Debian WSL

## 2) Base de datos

### Base principal del SIEM

Por defecto el proyecto espera:

- DB: `vant_siem`
- user: `vantsiem`
- password: `vantsiem123`

### Base dedicada de OpenSearch

Crear la base separada para logs:

```bash
psql -U postgres -d postgres -c "CREATE DATABASE vant_opensearch;"
```

El schema se puede aplicar manualmente:

```bash
psql -U postgres -d vant_opensearch -f opensearch_service/service/schema.sql
```

O automaticamente cuando ejecutes:

```bash
python manage.py migrate
```

Variables recomendadas:

- `OS_DB_HOST`
- `OS_DB_PORT`
- `OS_DB_NAME`
- `OS_DB_USER`
- `OS_DB_PASSWORD`

## 3) VANT-SIEM Django

### Instalacion basica

```bash
python -m venv venv
# Linux: source venv/bin/activate
# Windows: .\\venv\\Scripts\\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
python manage.py check
```

### Arranque manual

```bash
python manage.py runserver 127.0.0.1:8000
```

Configurar la base principal en `CORE/settings.py` cuando cambie el entorno.

## 4) Servicio OpenSearch

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
- `Uninstall-VANT-OpenSearch-Agent.exe` para desinstalacion directa

Comportamiento de instalacion:

- con privilegios de administrador instala en `C:\Program Files\VANT\OpenSearchAgent`
- sin elevacion hace fallback a `%LOCALAPPDATA%\VANT\OpenSearchAgent`
- si existe una instalacion previa, la desinstala primero y luego instala la nueva
- durante la desinstalacion/actualizacion detiene tarea programada y procesos del agente/tray

Instalacion manual por PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\Install-OpenSearchAgent.ps1 -RunNow
```

Instalacion manual en modo usuario:

```powershell
powershell -ExecutionPolicy Bypass -File .\opensearch_agents\windows\Install-OpenSearchAgent.ps1 -UserMode -RunNow
```

Reenrolamiento en Windows:

1. abrir `opensearch_agent_setup.exe`
2. cargar o corregir `host`, `port`, `bootstrap key` y, si aplica, `enrollment code`
3. usar `Probar conexion`
4. el setup reescribe el `config.yaml` con el nuevo token

Herramientas post-instalacion en Windows:

- `sendheartbeat.exe`
- `opena_mover.exe`
- `opena_checker.exe`

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

Comandos de enrolamiento manual:

```bash
sudo opena_enroll
sudo opena_enroll --enrollment-code CODIGO-DEL-TICKET
sudo opena_enroll --bootstrap-key MI-SECRETO
sudo opena_enroll --config /etc/vant-siem/config.yaml
sudo opena_enroll --no-backup
sudo opena_enroll --quiet
```

Comandos de validacion post-enrolamiento:

```bash
sudo opena_checker
sudo sendheartbeat --config /etc/vant-siem/config.yaml
```

Variables de backend relacionadas:

- `VANT_AGENT_ALLOWED`
- `VANT_AGENT_SHARED_SECRET`
- `VANT_AGENT_REQUIRE_ENROLLMENT_TICKET=1`

## 5) Servicios Linux/WSL recomendados

En Linux o Debian WSL, el despliegue estable recomendado es:

1. `vant-wsl-ip.service` si necesitas IP fija de testing
2. `vant-opensearch.service`
3. `vant-siem.service`
4. `vant-siem-agent.service`

Ver los ejemplos completos de unidades `systemd` en:

- `opensearch_agents/linux/debian/README.md`
- `opensearch_service/README.md`

### Debian WSL como entorno de testing

Resumen rapido del despliegue real en Debian WSL:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip build-essential libpq-dev postgresql postgresql-contrib curl
sudo -u postgres psql -c "CREATE ROLE vantsiem WITH LOGIN PASSWORD 'vantsiem123';"
sudo -u postgres createdb -O vantsiem vant_siem
sudo -u postgres createdb vant_opensearch
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'postgres';"
sudo rm -rf /opt/vant-siem
sudo mkdir -p /opt/vant-siem
sudo tar --exclude=.git --exclude=venv --exclude=.venv-wsl --exclude=__pycache__ \
  -cf - -C /mnt/c/Users/SysAdmin/Documents/develop/VANT-SIEM . | \
  sudo tar -xf - -C /opt/vant-siem
cd /opt/vant-siem
python3 -m venv .venv
source .venv/bin/activate
pip install Django==5.2.3
pip install django-sslserver==0.22.0
pip install requests==2.31.0
pip install pandas==2.3.0
pip install scikit-learn==1.8.0
pip install Flask==3.0.0
python manage.py migrate --noinput
python manage.py check
```

Para publicar el stack de testing dentro de Debian WSL sobre `192.168.12.43`,
revisa la guia detallada en:

- `opensearch_agents/linux/debian/README.md`

## 6) OpenSearch UI

Accesos:

- Dashboard: `http://localhost:8000/opensearch/`
- Discovery: `http://localhost:8000/opensearch/discover/`

## 7) Verificacion rapida

1. El servicio responde en `/health`.
2. El agente fue enrolado y tiene `output.auth.token`.
3. El agente esta en ejecucion.
4. `os_events_raw` incrementa registros.
5. Discovery muestra datos y filtros funcionales.

## 8) Referencias

- `opensearch_service/README.md`
- `opensearch_agents/AGENT_MANUAL.md`
- `opensearch_agents/linux/debian/README.md`
- `docs/ARCHITECTURE.md`
