# 📖 VANT-SIEM OpenSearch Agent - Manual Profesional

<div align="center">

![VANT-SIEM](https://img.shields.io/badge/VANT--SIEM-Agent-v1.01-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green)
![Python](https://img.shields.io/badge/Python-3.8%2B-yellow)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

</div>

---

## 📋 Tabla de Contenidos

1. [Introducción](#introducción)
2. [Arquitectura del Sistema](#arquitectura-del-sistema)
3. [Instalación](#instalación)
   - [Windows](#windows)
   - [Linux](#linux)
4. [Configuración](#configuración)
   - [Configuración Básica](#configuración-básica)
   - [Configuración de Recolectores](#configuración-de-recolectores)
   - [Configuración de Autenticación](#configuración-de-autenticación)
5. [Herramientas de Gestión](#herramientas-de-gestión)
   - [opensearchcheck](#opensearchcheck)
   - [opensearchmover](#opensearchmover)
6. [Compilación](#compilación)
   - [Windows (PyInstaller)](#windows-pyinstaller)
   - [Linux](#linux-1)
7. [Solución de Problemas](#solución-de-problemas)
8. [Referencia Rápida](#referencia-rápida)

---

## 🏗️ Introducción

El **Agente VANT-SIEM** es un componente fundamental de la plataforma VANT-SIEM que permite la recolección de eventos de seguridad de múltiples fuentes y su envío a un servidor OpenSearch centralizado.

### Características Principales

| Característica | Descripción |
|----------------|-------------|
| 🔄 **Multi-fuente** | Recolecta de Snort, Suricata, Windows Event Log, PostgreSQL, archivos |
| ⚡ **Tiempo Real** | Envío de eventos en tiempo casi real |
| 🔒 **Seguro** | Soporte para TLS/SSL y autenticación |
| 🧩 **Modular** | Arquitectura basada en recolectores independientes |
| 📊 **Escalable** | Capacidad de procesamiento de alto volumen |

---

## 🏗️ Arquitectura del Sistema

```
┌──────────────────────────────────────────────────────────────────────────┐
│                           VANT-SIEM Platform                             │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────┐         ┌─────────────────┐                       │
│  │  VANT-SIEM UI  │         │  OpenSearch      │                       │
│  │  (Dashboard)   │◄────────┤  (Logs Storage) │                       │
│  └─────────────────┘         └─────────────────┘                       │
│           ▲                          ▲                                  │
│           │                          │                                  │
│           │                          │                                  │
│  ┌────────┴─────────┐        ┌────────┴─────────┐                        │
│  │ OpenSearch      │        │ OpenSearch       │                        │
│  │ Service         │◄───────│ Agent            │                        │
│  │ (Ingest API)    │        │ (Collector)     │                        │
│  └─────────────────┘        └────────┬─────────┘                        │
│                                      │                                   │
│                                      ▼                                   │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Data Sources                                  │   │
│  │  ┌────────┐ ┌──────────┐ ┌───────┐ ┌────────┐ ┌──────────────┐  │   │
│  │  │ Snort  │ │ Suricata │ │Windows│ │PostgreSQL│ │  File Logs  │  │   │
│  │  │  IDS   │ │   IDS    │ │Eventlog│ │   DB    │ │  (Samba,etc)│  │   │
│  │  └────────┘ └──────────┘ └───────┘ └────────┘ └──────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────┘
```

### Flujo de Datos

1. **Recolección**: El agente lee eventos de las fuentes configuradas
2. **Procesamiento**: Normaliza y enriquece los eventos con metadatos
3. **Envío**: Envía los eventos al servicio de OpenSearch
4. **Almacenamiento**: OpenSearch almacena y indexa los eventos
5. **Visualización**: La UI de VANT-SIEM muestra los datos

---

## 💾 Instalación

### Windows

#### Opción 1: Ejecutable Pre-compilado

1. Descargue el archivo `VANT-SIEM-Agent.exe` de la carpeta `dist`
2. Copie a la ubicación deseada
3. Copie `config.example.yaml` como `config.yaml`
4. Edite `config.yaml` con su configuración

#### Opción 2: Desde Código Fuente

```powershell
# Requisitos previos
# - Python 3.8 o superior
# - pip

# 1. Clonar o copiar el proyecto
cd opensearch_agents

# 2. Crear entorno virtual (opcional pero recomendado)
python -m venv venv
.\venv\Scripts\activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Copiar configuración
copy config.example.yaml config.yaml

# 5. Editar configuración
notepad config.yaml

# 6. Ejecutar agente
python agent.py --config config.yaml

# O compilar a EXE
python build_agent.py --agent
```

### Linux

#### Debian/Ubuntu

```bash
# 1. Instalar dependencias del sistema
sudo apt update
sudo apt install python3 python3-pip python3-venv

# 2. Copiar archivos del agente
cd opensearch_agents

# 3. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# 4. Instalar dependencias
pip install -r requirements.txt

# 5. Copiar y configurar
cp config.example.yaml config.yaml
nano config.yaml

# 6. Ejecutar
python3 agent.py --config config.yaml

# 7. (Opcional) Crear servicio systemd
sudo cp ../linux/debian/install_agent.sh /usr/local/bin/vant-siem-agent
sudo chmod +x /usr/local/bin/vant-siem-agent
```

#### Zentyal/Other Linux

```bash
# Similar a Debian, ajustar según distribución
# Ver scripts en ../linux/
```

---

## ⚙️ Configuración

### Configuración Básica

El archivo `config.yaml` contiene todas las opciones de configuración:

```yaml
# ==========================================
# Configuración del Agente
# ==========================================
agent:
  id: "agent-001"              # Identificador único del agente
  host_name: "windows-server-01" # Nombre del host
  interval_seconds: 10          # Intervalo de recolección (segundos)

# ==========================================
# Configuración de Salida (OpenSearch)
# ==========================================
output:
  # Endpoint del servicio de OpenSearch
  endpoint: "http://127.0.0.1:9201/api/v1/events/bulk"
  source_endpoint: "http://127.0.0.1:9201/api/v1/sources/upsert"
  
  timeout_seconds: 10           # Timeout de conexión
  
  # Configuración de autenticación
  auth:
    mode: "none"                # none|basic|token
    username: "admin"
    password: "password123"
    token: ""
  
  # Configuración TLS/SSL
  tls:
    enabled: false
    verify: false
    ca_cert: ""

# ==========================================
# Configuración de Recolectores
# ==========================================
collectors:
  # ... (ver siguiente sección)
```

### Configuración de Recolectores

#### Snort IDS

```yaml
collectors:
  snort:
    enabled: true
    path: "C:/snort/log/alert"
    start_position: "end"      # beginning|end
    max_lines_per_cycle: 400
```

#### Suricata IDS

```yaml
collectors:
  suricata:
    enabled: true
    path: "C:/suricata/logs/eve.json"
    start_position: "end"
    max_lines_per_cycle: 600
```

#### Windows Event Log

```yaml
collectors:
  windows_eventlog:
    enabled: true
    channel: "Security"        # Security|Application|System
```

#### PostgreSQL Logs

```yaml
collectors:
  postgres:
    enabled: true
    path: "C:/Program Files/PostgreSQL/16/data/log/postgresql.log"
    start_position: "end"
    max_lines_per_cycle: 400
```

#### File Logs (Personalizado)

```yaml
collectors:
  file_logs:
    enabled: true
    items:
      - enabled: true
        source_name: "samba-audit"
        path: "/var/log/samba/audit.log"
        event_category: "samba.audit"
        severity: "info"
        tags: ["samba", "ad", "audit"]
        start_position: "end"
        max_lines_per_cycle: 400
```

### Configación

#### Sinuración de Autentic Autenticación (Desarrollo)

```yaml
output:
  auth:
    mode: "none"
```

#### Autenticación Básica

```yaml
output:
  auth:
    mode: "basic"
    username: "admin"
    password: "password123"
```

#### Token de Acceso

```yaml
output:
  auth:
    mode: "token"
    token: "your-api-token-here"
```

#### Con TLS/SSL

```yaml
output:
  endpoint: "https://opensearch.example.com:9201/api/v1/events/bulk"
  tls:
    enabled: true
    verify: true              # true para certificados válidos
    ca_cert: "path/to/ca.crt" # Ruta al certificado CA
```

---

## Control y Enrolamiento del Agente (v1.01)

El agente v1.01 usa enrolamiento automático por firma HMAC y reporta inventario del host.

### Endpoints usados por el agente

- `GET /api/agent/bootstrap/`
- `POST /api/agent/enroll/`
- `POST /api/agent/heartbeat/`
- `POST /api/agent/inventory/`
- `POST /api/agent/commands/pull/`
- `POST /api/agent/commands/ack/`

### Reglas clave

- El endpoint `bootstrap` requiere encabezado `X-Agent-Id`.
- Si el servidor está en HTTP, desactiva HTTPS en el instalador.
- Si el servidor está en HTTPS, activa HTTPS en el instalador.

### Inventario reportado

- Seriales de BIOS, CPU y motherboard
- Versiones de SO y build
- Usuarios conectados
- Apps instaladas
- Historial de IPs

Los datos se almacenan en el módulo `inventory` del servidor.

---

## 🔧 Herramientas de Gestión

### opensearchcheck

Verifica la configuración del agente y prueba la conectividad.

#### Uso

```bash
# Verificar configuración por defecto
python opensearchcheck.py

# Verificar configuración personalizada
python opensearchcheck.py --config mi_config.yaml

# Omitir prueba de conectividad
python opensearchcheck.py --skip-connectivity
```

#### Funcionalidades

- ✅ Validación de sintaxis YAML
- ✅ Verificación de configuración del agente
- ✅ Verificación de endpoints
- ✅ Verificación de recolectores
- ✅ Prueba de conectividad TCP
- ✅ Prueba de conexión HTTP/HTTPS
- ✅ Obtención de información del cluster

#### Ejemplo de Salida

```
╔══════════════════════════════════════════════════════════════════════╗
║              VANT-SIEM OpenSearch Agent Checker                       ║
║                    Configuration Validation                          ║
╚══════════════════════════════════════════════════════════════════════╝

  ✓ Configuration file loaded: config.yaml

══════════════════════════════════════════════════════════════════════
  2. Agent Configuration
══════════════════════════════════════════════════════════════════════

  ✓ agent.id: agent-001
  ℹ agent.host_name: windows-server-01

══════════════════════════════════════════════════════════════════════
  5. Connectivity Test
══════════════════════════════════════════════════════════════════════

  ℹ Testing connection to 127.0.0.1:9201
  ✓ TCP connection successful to 127.0.0.1:9201
  ✓ HTTP request successful (status: 200)
  ✓ OpenSearch cluster: vant-siem-cluster
  ✓ OpenSearch version: 2.11.0
```

---

### opensearchmover

Cambia el servidor OpenSearch al que apunta el agente.

#### Uso Interactivo

```bash
python opensearchmover.py --interactive
```

Salida:
```
============================================================
  Server Migration - Interactive Mode
============================================================

  Current Configuration:
    Event Endpoint:     http://old-server:9200/api/v1/events/bulk
    Source Endpoint:    http://old-server:9200/api/v1/sources/upsert
    Auth Mode:          none
    TLS Enabled:        False

  Enter the new OpenSearch server details:
    OpenSearch Server Host: new-server.example.com
    OpenSearch Server Port (default: 9200): 9201
    Use HTTPS? (y/N): y

  Configuration will be updated. A backup will be created.
  Proceed? (y/N): y

  ✓ Backup created: config.yaml.bak
  ✓ Configuration saved: config.yaml
  ℹ Testing new endpoint connectivity...
  ✓ New endpoint is reachable!

  Server migration completed successfully!
```

#### Uso por Comandos

```bash
# Cambiar a nuevo servidor
python opensearchmover.py --host 192.168.1.100

# Con puerto específico
python opensearchmover.py --host opensearch.example.com --port 9201

# Con HTTPS
python opensearchmover.py --host secure-server.com --https

# Ver ejemplos de configuración
python opensearchmover.py --examples
```

---

## 🔨 Compilación

### Windows (PyInstaller)

#### Requisitos

```powershell
# Instalar PyInstaller
pip install pyinstaller
```

#### Compilar

```powershell
# Compilar todo
python build_agent.py

# Compilar solo el agente
python build_agent.py --agent

# Compilar herramienta de verificación
python build_agent.py --check

# Compilar herramienta de migración
python build_agent.py --mover

# Limpiar builds anteriores
python build_agent.py --clean
```

#### Salida

Los archivos compilados se encuentran en:
- `dist/VANT-SIEM-Agent/VANT-SIEM-Agent.exe`
- `dist/VANT-SIEM-Check/VANT-SIEM-Check.exe`
- `dist/VANT-SIEM-Mover/VANT-SIEM-Mover.exe`

### Linux

Para Linux, se utilizan scripts de shell en lugar de compilación:

```bash
# Ver scripts disponibles
ls -la ../linux/

# Instalar en Debian/Ubuntu
cd ../linux/debian
sudo ./install_agent.sh

# Habilitar logs
sudo ./enable_logs.sh
```

---

## 🔍 Solución de Problemas

### El agente no se conecta al servidor

1. **Verificar que OpenSearch esté ejecutándose**
   ```bash
   # Windows
   netstat -an | findstr "9201"
   
   # Linux
   netstat -tlnp | grep 9201
   ```

2. **Verificar configuración**
   ```bash
   python opensearchcheck.py
   ```

3. **Verificar firewall**
   - Windows: Allow port 9201 through Windows Firewall
   - Linux: `sudo ufw allow 9201/tcp`

### No se reciben eventos

1. **Verificar que los recolectores estén habilitados**
   ```yaml
   collectors:
     snort:
       enabled: true  # Debe ser true
   ```

2. **Verificar rutas de archivos**
   ```yaml
   path: "C:/snort/log/alert"  # Ruta correcta
   ```

3. **Verificar permisos**
   - El agente debe tener acceso de lectura a los archivos

### Error de autenticación

1. **Verificar credenciales**
   ```yaml
   auth:
     mode: "basic"
     username: "admin"
     password: "password123"  # Contraseña correcta
   ```

2. **Para TLS, verificar certificado**
   ```yaml
   tls:
     enabled: true
     verify: true
     ca_cert: "C:/certs/ca.crt"
   ```

---

## 📋 Referencia Rápida

### Comandos常用

| Acción | Comando |
|--------|---------|
| Iniciar agente | `python agent.py --config config.yaml` |
| Verificar config | `python opensearchcheck.py` |
| Cambiar servidor | `python opensearchmover.py --host nuevo-servidor` |
| Ver ejemplos | `python opensearchmover.py --examples` |

### Puertos Comunes

| Servicio | Puerto | Protocolo |
|----------|--------|----------|
| OpenSearch | 9200 | HTTP |
| OpenSearch (TLS) | 9201 | HTTPS |
| OpenSearch (Alt) | 9201 | HTTP |

### Variables de Entorno

| Variable | Descripción |
|----------|-------------|
| `VANT_AGENT_CONFIG` | Ruta al archivo de configuración |
| `VANT_AGENT_LOG_LEVEL` | Nivel de logging (DEBUG, INFO, WARNING, ERROR) |

---

## 📞 Soporte

Parareportar problemas o solicitar ayuda:

- 📧 Email: leonardovarona42@gmail.com
- 📱 Tel: +53 58003511

---

<div align="center">

**VANT-SIEM Agent** - *Vigilance And Neutralization of Threats*

*Plataforma de ciberseguridad de próxima generación*

© 2025 VANT-SIEM - Developed by LLVT

</div>
