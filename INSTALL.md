# VANT-SIEM — Guía de Instalación y Configuración

---

## Índice

1. [Requisitos del Sistema](#1-requisitos-del-sistema)
2. [Instalación de Dependencias del Sistema](#2-instalación-de-dependencias-del-sistema)
3. [Base de Datos — PostgreSQL + TimescaleDB](#3-base-de-datos--postgresql--timescaledb)
4. [Configuración de Bases de Datos](#4-configuración-de-bases-de-datos)
5. [Redis](#5-redis)
6. [Aplicación Django](#6-aplicación-django)
7. [Gunicorn + systemd](#7-gunicorn--systemd)
   - 7.5 [Flujo Alterno: Gunicorn + Microservicios](#75-flujo-alterno-gunicorn--microservicios-wrapper)
8. [Nginx + SSL](#8-nginx--ssl)
9. [Instalación del Agente](#9-instalación-del-agente)
10. [Errores Comunes y Soluciones](#10-errores-comunes-y-soluciones)
11. [Mantenimiento](#11-mantenimiento)

---

## 1. Requisitos del Sistema

### Hardware mínimo
| Recurso | Mínimo | Recomendado |
|---|---|---|
| RAM | 4 GB | 8 GB+ |
| CPU | 2 núcleos | 4+ núcleos |
| Disco | 20 GB | 50 GB+ (depende de retención de logs) |

### Software
- **SO:** Ubuntu 22.04+ / Debian 12+
- **PostgreSQL:** 15+ con TimescaleDB 2.x
- **Redis:** 6.x+
- **Python:** 3.11+
- **Nginx:** 1.24+

---

## 2. Instalación de Dependencias del Sistema

```bash
# Actualizar paquetes
sudo apt update && sudo apt upgrade -y

# Dependencias básicas
sudo apt install -y curl wget gnupg postgresql-common python3 python3-pip \
  python3-venv git nginx redis-server build-essential libssl-dev \
  libffi-dev libpq-dev

# Verificar versiones
python3 --version    # >= 3.11
psql --version       # >= 15
redis-server --version
nginx -v
```

---

## 3. Base de Datos — PostgreSQL + TimescaleDB

### 3.1 Instalar PostgreSQL

```bash
# Agregar repositorio oficial de PostgreSQL
sudo /usr/share/postgresql-common/pgdg/apt.postgresql.org.sh

# Instalar PostgreSQL 16
sudo apt install -y postgresql-16 postgresql-client-16

# Verificar
sudo systemctl status postgresql
```

### 3.2 Instalar TimescaleDB

```bash
# Agregar repositorio de TimescaleDB
curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/timescaledb.gpg
echo "deb https://packagecloud.io/timescale/timescaledb/debian/ $(lsb_release -c -s) main" | sudo tee /etc/apt/sources.list.d/timescaledb.list

sudo apt update
sudo apt install -y timescaledb-2-postgresql-16 timescaledb-tools

# Configurar PostgreSQL para TimescaleDB
sudo timescaledb-tune --quiet --yes

# Reiniciar PostgreSQL
sudo systemctl restart postgresql
```

### 3.3 Configurar pg_hba.conf

```bash
# Permitir conexiones locales con password
sudo sed -i 's/local\s*all\s*all\s*peer/local   all             all                                     md5/' /etc/postgresql/16/main/pg_hba.conf

sudo systemctl restart postgresql
```

---

## 4. Configuración de Bases de Datos

VANT-SIEM usa **6 bases de datos independientes** para separar dominios:

| Base de Datos | Puerto | Propósito |
|---|---|---|
| `vant_siem` | 5432 | Web portal principal |
| `vant_logs` | 5433 | Logs de eventos |
| `vant_incidents` | 5434 | Incidentes de seguridad |
| `vant_assets` | 5435 | Inventario de activos |
| `vant_network` | 5436 | Topología de red |
| `vant_dlp` | 5437 | Prevención de fuga de datos |

### 4.1 Crear Bases de Datos y Usuarios

```bash
sudo -u postgres psql << 'SQL'
-- Crear usuario
CREATE USER vantsiem WITH PASSWORD 'tu_password_segura';

-- Crear bases de datos
CREATE DATABASE vant_siem OWNER vantsiem;
CREATE DATABASE vant_logs OWNER vantsiem;
CREATE DATABASE vant_incidents OWNER vantsiem;
CREATE DATABASE vant_assets OWNER vantsiem;
CREATE DATABASE vant_network OWNER vantsiem;
CREATE DATABASE vant_dlp OWNER vantsiem;
SQL
```

### 4.2 Configurar TimescaleDB (Hypertables)

Conectar a cada base de datos y habilitar TimescaleDB:

```bash
# Para cada base de datos, ejecutar:
for db in vant_siem vant_logs vant_incidents vant_assets vant_network vant_dlp; do
  sudo -u postgres psql -d "$db" -c "CREATE EXTENSION IF NOT EXISTS timescaledb;"
  echo "TimescaleDB habilitado en $db"
done
```

> **Nota:** Si alguna base de datos no requiere hypertables, igual se habilita la extensión para compatibilidad.

### 4.3 Configurar PostgreSQL para múltiples puertos

VANT-SIEM usa puertos separados por base de datos. Editar `postgresql.conf`:

```bash
sudo tee -a /etc/postgresql/16/main/postgresql.conf > /dev/null << 'EOF'

# Puertos adicionales para VANT-SIEM
port = 5432
EOF
```

> **Alternativa:** Usar el mismo puerto 5432 para todas las conexiones si estás en desarrollo. En producción se recomienda usar puertos separados a nivel de aplicación o un connection pooler como PgBouncer.

### 4.4 Verificar conexiones

```bash
# Probar cada base de datos
for port in 5432 5433 5434 5435 5436 5437; do
  PGPASSWORD='tu_password' psql -h localhost -p $port -U vantsiem -d vant_siem -c "SELECT 1 AS test" 2>&1 | head -3
done
```

---

## 5. Redis

Redis se usa como message bus (ServiceBus) y backend de Celery.

```bash
# Verificar que Redis esté corriendo
sudo systemctl status redis-server

# Configurar Redis para conexiones locales
sudo sed -i 's/^bind 127.0.0.1 ::1/bind 127.0.0.1/' /etc/redis/redis.conf
sudo systemctl restart redis-server

# Verificar
redis-cli ping
# Debería responder: PONG
```

---

## 6. Aplicación Django

### 6.1 Clonar / Copiar el proyecto

```bash
# Desde Windows (en WSL)
cd /home
git clone https://github.com/tu-repo/VANT-SIEM.git vant-siem

# O copiar desde Windows
# cp -r /mnt/c/Users/TuUsuario/Documents/develop/VANT-SIEM /home/vant-siem

cd /home/vant-siem
```

### 6.2 Crear entorno virtual

```bash
python3 -m venv venv
source venv/bin/activate
```

### 6.3 Instalar dependencias

```bash
pip install --upgrade pip
pip install -r requirements.txt

# Si hay errores con psycopg2, instalar psycopg2-binary:
# pip install psycopg2-binary
```

### 6.4 Configurar variables de entorno

```bash
cp .env.example .env
nano .env   # Editar con tus valores
```

Configuración mínima requerida en `.env`:

```env
# ==== Service Identity ====
VANT_SERVICE_NAME=vant-siem
MICROSERVICE_MODE=standalone

# ==== Database - Web Portal ====
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vant_siem
DB_USER=vantsiem
DB_PASSWORD=tu_password_segura

# ==== Database - Logs ====
LOGS_DB_HOST=localhost
LOGS_DB_PORT=5432
LOGS_DB_NAME=vant_logs
LOGS_DB_USER=vantsiem
LOGS_DB_PASSWORD=tu_password_segura

# ==== Database - Incidents ====
INCIDENTS_DB_HOST=localhost
INCIDENTS_DB_PORT=5432
INCIDENTS_DB_NAME=vant_incidents
INCIDENTS_DB_USER=vantsiem
INCIDENTS_DB_PASSWORD=tu_password_segura

# ==== Database - Assets ====
ASSETS_DB_HOST=localhost
ASSETS_DB_PORT=5432
ASSETS_DB_NAME=vant_assets
ASSETS_DB_USER=vantsiem
ASSETS_DB_PASSWORD=tu_password_segura

# ==== Database - Network ====
NETWORK_DB_HOST=localhost
NETWORK_DB_PORT=5432
NETWORK_DB_NAME=vant_network
NETWORK_DB_USER=vantsiem
NETWORK_DB_PASSWORD=tu_password_segura

# ==== Database - DLP ====
DLP_DB_HOST=localhost
DLP_DB_PORT=5432
DLP_DB_NAME=vant_dlp
DLP_DB_USER=vantsiem
DLP_DB_PASSWORD=tu_password_segura

# ==== Redis ====
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1
SERVICE_BUS_URL=redis://localhost:6379/10

# ==== Service URLs ====
LOGS_SERVICE_URL=http://localhost:9201
INCIDENTS_SERVICE_URL=http://localhost:8001
ASSETS_SERVICE_URL=http://localhost:8002
NETWORK_SERVICE_URL=http://localhost:8004
AI_SERVICE_URL=http://localhost:8003

# ==== Django ====
SECRET_KEY=genera-una-clave-segura-aqui
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,tu-dominio.com

# ==== Timezone ====
TIME_ZONE=America/Havana
```

### 6.5 Generar SECRET_KEY

```bash
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
# Copiar el resultado y pegarlo en .env como SECRET_KEY
```

### 6.6 Migraciones

```bash
python manage.py migrate --database=default
python manage.py migrate --database=vant_dlp
python manage.py migrate --database=vant_inventory
python manage.py migrate --database=vant_logs

# Crear superusuario
python manage.py createsuperuser
```

### 6.7 Verificar

```bash
python manage.py check
python manage.py runserver 0.0.0.0:8000 --noreload
# Probar en navegador: http://IP-DEL-SERVIDOR:8000/siem/dashboard/login/
```

---

## 7. Gunicorn + systemd

### 7.1 Gunicorn (ya incluido en requirements.txt)

```bash
pip install gunicorn
```

### 7.2 Configuración de Gunicorn

Archivo `gunicorn.conf.py`:

```python
wsgi_app = 'CORE.wsgi:application'
bind = '0.0.0.0:8000'
worker_class = 'sync'
workers = 4
timeout = 120
graceful_timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 200
accesslog = '/home/vant-siem/logs/gunicorn-access.log'
errorlog = '/home/vant-siem/logs/gunicorn-error.log'
loglevel = 'info'
capture_output = True
```

### 7.3 Probar Gunicorn manualmente

```bash
mkdir -p logs
gunicorn --config gunicorn.conf.py
# En otra terminal: curl http://localhost:8000/siem/dashboard/login/
```

### 7.4 Servicio systemd (usuario)

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/vantsiem.service << 'EOF'
[Unit]
Description=VANT-SIEM Django Application (Gunicorn)
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/vant-siem
Environment=PATH=/home/vant-siem/venv/bin:/usr/bin:/bin
Environment=TIMESCALEDB_ENABLED=True
ExecStart=/home/vant-siem/venv/bin/gunicorn --config /home/vant-siem/gunicorn.conf.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/vantsiem.log
StandardError=append:/var/log/vantsiem.log

[Install]
WantedBy=default.target
EOF

# Recargar systemd y habilitar
systemctl --user daemon-reload
systemctl --user enable vantsiem.service
systemctl --user start vantsiem.service

# Verificar
systemctl --user status vantsiem.service
```

> **Nota:** Si se tiene acceso root, se puede crear el servicio a nivel del sistema en `/etc/systemd/system/vantsiem.service` con `User=testing`.

### 7.5 Flujo Alterno: Gunicorn + Microservicios (Wrapper)

Si necesitas que al iniciar el Web Portal también se levanten los microservicios (AEGIS DLP, Inventory, Logs) —tal como lo hacía el `manage.py runserver` original— usa este flujo en lugar del anterior.

#### 7.5.1 Requisitos

```bash
pip install gunicorn
```

#### 7.5.2 Archivos necesarios

**`gunicorn.conf.py`** — configuración de gunicorn (ver [sección 7.2](#72-configuración-de-gunicorn)).

**`start.sh`** — wrapper que inicia microservicios + gunicorn:

```bash
cat > /home/vant-siem/start.sh << 'SHEOF'
#!/bin/bash
set -e

VANT_DIR="/home/vant-siem"
VENV="$VANT_DIR/venv"
PYTHON="$VENV/bin/python"
MANAGE="$PYTHON $VANT_DIR/manage.py"
LOG_DIR="$VANT_DIR/logs/services"
PID_DIR="/tmp/vantsiem-pids"

mkdir -p "$LOG_DIR" "$PID_DIR"
rm -f "$PID_DIR"/*.pid

SERVICES=(
  "AEGIS DLP:run_aegis_service:8002"
  "Inventory:run_inventory_service:8003"
  "Logs:run_logs_service:9201"
)

echo "=== Starting VANT-SIEM Microservices ==="
CHILD_PIDS=()

start_service() {
  local name="$1"; local cmd="$2"; local port="$3"
  local log="$LOG_DIR/${cmd}.log"
  echo -n "  $name (port $port)... "
  $MANAGE "$cmd" --port "$port" --noreload >> "$log" 2>&1 &
  local pid=$!; CHILD_PIDS+=($pid)
  echo "$pid" > "$PID_DIR/${cmd}.pid"
  echo "PID $pid"
}

start_service "AEGIS DLP Service" "run_aegis_service" "8002"
start_service "Inventory Service" "run_inventory_service" "8003"
start_service "Logs Service" "run_logs_service" "9201"

sleep 3
echo ""; echo "=== Starting Gunicorn (Web Portal :8000) ==="

$VENV/bin/gunicorn --config "$VANT_DIR/gunicorn.conf.py" &
GUNICORN_PID=$!; CHILD_PIDS+=($GUNICORN_PID)

cleanup() {
  echo ""; echo "=== Shutting down all services ==="
  for pid in "${CHILD_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      echo -n "  Stopping PID $pid... "
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; echo "OK"
    fi
  done
  rm -f "$PID_DIR"/*.pid
  echo "=== All services stopped ==="
}
trap cleanup EXIT INT TERM
wait "$GUNICORN_PID"
SHEOF
chmod +x /home/vant-siem/start.sh
```

**`~/.config/systemd/user/vantsiem.service`** — servicio systemd que usa el wrapper:

```bash
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/vantsiem.service << 'EOF'
[Unit]
Description=VANT-SIEM Django (Gunicorn + Microservicios)
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/vant-siem
Environment=PATH=/home/vant-siem/venv/bin:/usr/bin:/bin
Environment=TIMESCALEDB_ENABLED=True
ExecStart=/home/vant-siem/start.sh
Restart=always
RestartSec=5
StandardOutput=append:/var/log/vantsiem.log
StandardError=append:/var/log/vantsiem.log

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable vantsiem.service
systemctl --user restart vantsiem.service
```

#### 7.5.3 Verificar

```bash
# Estado del servicio
systemctl --user status vantsiem.service

# Puertos esperados
ss -tlnp | grep -E '8000|8002|8003|9201'

# Probar portal
curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/siem/dashboard/login/
# Debe responder: 200
```

| Puerto | Servicio |
|---|---|
| 8000 | Web Portal (Gunicorn) |
| 8002 | AEGIS DLP Service |
| 8003 | Inventory Service |
| 9201 | Logs Service |

#### 7.5.4 Logs

Cada servicio escribe su log en `/home/vant-siem/logs/services/`:

```bash
# Logs individuales
tail -f /home/vant-siem/logs/services/run_aegis_service.log
tail -f /home/vant-siem/logs/services/run_inventory_service.log
tail -f /home/vant-siem/logs/services/run_logs_service.log

# Logs de gunicorn
tail -f /home/vant-siem/logs/gunicorn-error.log
```

---

## 8. Nginx + SSL

### 8.1 Configurar Nginx

```bash
sudo mkdir -p /etc/nginx/ssl
```

Archivo `/etc/nginx/sites-available/vantsiem`:

```nginx
upstream django_vant {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name tu-dominio.com IP_DEL_SERVIDOR;

    client_max_body_size 2000M;

    location /static/ {
        alias /home/vant-siem/staticfiles/;
    }

    location /media/ {
        alias /home/vant-siem/media/;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    http2 on;
    server_name tu-dominio.com IP_DEL_SERVIDOR;

    ssl_certificate /etc/nginx/ssl/tu-dominio.pem;
    ssl_certificate_key /etc/nginx/ssl/tu-dominio.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    client_max_body_size 2000M;

    location /static/ {
        alias /home/vant-siem/staticfiles/;
    }

    location /media/ {
        alias /home/vant-siem/media/;
    }

    location / {
        proxy_pass http://django_vant;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
```

### 8.2 Generar SSL autofirmado (para pruebas)

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/vsiem.key \
  -out /etc/nginx/ssl/vsiem.pem \
  -subj "/C=CU/ST=Ciudad/L=Habana/O=VANT/CN=IP_DEL_SERVIDOR"
```

### 8.3 Activar sitio

```bash
sudo ln -sf /etc/nginx/sites-available/vantsiem /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

---

## 9. Instalación del Agente

### 9.1 Desde paquete .deb (Linux)

```bash
# Copiar el paquete al servidor cliente
scp vant-siem-agent-debian_1.0.0_all.deb user@cliente:/tmp/

# En el cliente:
sudo dpkg -i /tmp/vant-siem-agent-debian_1.0.0_all.deb

# Si hay dependencias faltantes:
sudo apt --fix-broken install -y
```

### 9.2 Configurar el agente

```bash
# Editar configuración del agente
sudo nano /etc/vant-siem/config.yaml
```

Configuración mínima:

```yaml
server:
  url: https://IP_DEL_SERVIDOR
  verify_ssl: false  # false si usas SSL autofirmado

agent:
  id: "nombre-del-agente"
  hostname: "nombre-del-host"
  interval: 300  # segundos entre heartbeats

inventory:
  enabled: true
  interval: 3600

dlp:
  enabled: true
  scan_interval: 300
  paths:
    - /home
    - /tmp
    - /var/www

logging:
  level: info
  file: /var/log/vant-siem-agent.log
```

### 9.3 Iniciar el agente

```bash
sudo systemctl enable vant-siem-agent
sudo systemctl start vant-siem-agent
sudo systemctl status vant-siem-agent
```

### 9.4 Verificar comunicación

```bash
# Revisar logs del agente
tail -f /var/log/vant-siem-agent.log

# Revisar heartbeats en el servidor
curl -k https://IP_DEL_SERVIDOR/inventory/api/heartbeat/ \
  -X POST -H "Content-Type: application/json" \
  -d '{"agent_id":"nombre-del-agente"}'
```

### 9.5 Instalación manual (sin paquete)

```bash
# En el cliente:
sudo mkdir -p /opt/vant-siem-agent
cd /opt/vant-siem-agent

# Copiar los archivos del agente (desde VANT-Agent-build/)
# y configurar como servicio manualmente
```

---

## 10. Errores Comunes y Soluciones

### 10.1 Error: `'NoneType' object has no attribute 'startswith'`

**Causa:** El ServiceBus recibe `None` como URL de Redis.
**Solución:** Asegurar que `CORE/arkangel/bus.py` tenga el fix:

```python
def __init__(self, url=None):
    self.redis = redis.from_url(url or 'redis://localhost:6379/10', decode_responses=True)
```

### 10.2 Error: `connect() failed (111: Connection refused) while connecting to upstream`

**Causa:** nginx no puede conectar con el backend Django/Gunicorn.
**Solución:**
```bash
# Verificar que gunicorn está corriendo
systemctl --user status vantsiem.service

# Verificar puerto
ss -tlnp | grep 8000

# Revisar logs de gunicorn
tail -f /home/vant-siem/logs/gunicorn-error.log
```

### 10.3 Error: `Permission denied: '/var/log/vantsiem-error.log'`

**Causa:** Gunicorn intenta escribir logs en `/var/log/` sin permisos.
**Solución:** Usar rutas dentro del home del usuario en `gunicorn.conf.py`:
```python
accesslog = '/home/vant-siem/logs/gunicorn-access.log'
errorlog = '/home/vant-siem/logs/gunicorn-error.log'
```

### 10.4 Error: `FATAL: role "vantsiem" does not exist`

**Causa:** No se creó el usuario de PostgreSQL.
**Solución:**
```bash
sudo -u postgres createuser vantsiem -P
```

### 10.5 Error: `could not connect to server: Connection refused` (PostgreSQL)

**Causa:** PostgreSQL no está corriendo o no escucha en el puerto esperado.
**Solución:**
```bash
sudo systemctl restart postgresql
sudo systemctl status postgresql
ss -tlnp | grep 5432
```

### 10.6 Error: `RuntimeWarning: DateTimeField received a naive datetime`

**Causa:** Los agentes envían fechas sin zona horaria.
**Solución:** Ya corregido en `AEGIS/views.py` con `timezone.make_aware()`.

### 10.7 Error: Servicio se reinicia constantemente (exit code 1)

**Causa:** Error no capturado en el código (ej: ServiceBus, conexión BD).
**Solución:**
```bash
# Revisar logs de salida
tail -100 /var/log/vantsiem.log
# Buscar la traza del error y aplicar el fix correspondiente
```

### 10.8 Error: `aegis.service_bus.unavailable`

**Causa:** Redis no está corriendo o no es accesible.
**Solución:**
```bash
sudo systemctl status redis-server
redis-cli ping  # Debe responder PONG
```

### 10.9 Error: 502 Bad Gateway desde nginx

**Causa:** El upstream (gunicorn) no responde.
**Solución:**
```bash
# Verificar gunicorn
systemctl --user status vantsiem.service

# Verificar logs de nginx
tail -f /var/log/nginx/error.log

# Aumentar timeout si es necesario
# proxy_read_timeout 120s;
```

### 10.10 Error: Base de datos llena / WAL crece sin control

**Causa:** TimescaleDB acumula chunks viejos.
**Solución:**
```sql
-- Ver tamaño
SELECT hypertable_name, table_size FROM timescaledb_information.hypertable;

-- Configurar política de retención (ej: 90 días)
SELECT add_retention_policy('nombre_hypertable', INTERVAL '90 days');
```

### 10.11 Error: `pg_restore: error: could not execute query: ERROR: relation already exists`

**Causa:** Intentar restaurar un backup sobre datos existentes.
**Solución:** Usar `--clean --if-exists` en pg_restore.

---

## 11. Mantenimiento

### 11.1 Respaldo de bases de datos

```bash
#!/bin/bash
BACKUP_DIR="/backup/vantsiem"
DATE=$(date +%Y%m%d_%H%M%S)
DB_USER="vantsiem"
DB_PASS="tu_password"

mkdir -p $BACKUP_DIR

for db in vant_siem vant_logs vant_incidents vant_assets vant_network vant_dlp; do
  PGPASSWORD=$DB_PASS pg_dump -h localhost -U $DB_USER -d $db \
    -F c -f "$BACKUP_DIR/${db}_$DATE.dump"
  echo "Backup de $db completado"
done

# Rotar backups de más de 30 días
find $BACKUP_DIR -name "*.dump" -mtime +30 -delete
```

### 11.2 Restaurar una base de datos

```bash
PGPASSWORD=tu_password pg_restore -h localhost -U vantsiem -d vant_siem \
  --clean --if-exists vant_siem_20250101_120000.dump
```

### 11.3 Actualizar el proyecto

```bash
# Desde el directorio del proyecto
cd /home/vant-siem

# Si usas git
git pull

# Si copias desde Windows
# rsync -av --delete \
#   --exclude='.git/' --exclude='__pycache__/' --exclude='venv/' \
#   --exclude='media/' --exclude='staticfiles/' --exclude='*.pyc' \
#   /mnt/c/Users/TuUsuario/Documents/develop/VANT-SIEM/ .

# Activar venv y actualizar dependencias
source venv/bin/activate
pip install -r requirements.txt

# Migraciones si hay cambios
python manage.py migrate --database=default
python manage.py migrate --database=vant_dlp
python manage.py migrate --database=vant_inventory
python manage.py migrate --database=vant_logs

# Recolectar estáticos
python manage.py collectstatic --noinput

# Reiniciar servicio
systemctl --user restart vantsiem.service
```

### 11.4 Monitoreo rápido

```bash
# Verificar que todo está funcionando
echo "=== Gunicorn ==="
systemctl --user status vantsiem.service | head -3

echo "=== Nginx ==="
sudo systemctl status nginx | head -3

echo "=== PostgreSQL ==="
sudo systemctl status postgresql | head -3

echo "=== Redis ==="
sudo systemctl status redis-server | head -3

echo "=== Puertos ==="
ss -tlnp | grep -E '8000|443|80|5432|6379'
```

---

## Credenciales por Defecto (desarrollo)

| Servicio | Usuario | Contraseña |
|---|---|---|
| Django Admin | (el que crees con `createsuperuser`) | — |
| PostgreSQL | vantsiem | (la configures en `.env`) |
| Redis | — | sin autenticación (solo local) |

---

## Estructura de Directorios

```
/home/vant-siem/
├── AEGIS/              # Módulo DLP
├── CORE/               # Configuración central
│   └── arkangel/       # Message Bus (ServiceBus)
├── EVENT_M/            # Gestión de eventos
├── INVENTORY/          # Inventario de activos
├── OPENSEARCH_LOGS/    # Logs en OpenSearch
├── VANT_SIEM/          # Portal web
├── logs/               # Logs de gunicorn
├── media/              # Archivos subidos
├── staticfiles/        # Archivos estáticos
├── venv/               # Entorno virtual Python
├── gunicorn.conf.py    # Configuración de gunicorn
├── manage.py           # Management de Django
├── requirements.txt    # Dependencias Python
└── .env                # Variables de entorno
```
