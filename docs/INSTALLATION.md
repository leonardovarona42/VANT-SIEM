# VANT-SIEM CORE - Guía de Instalación

## Sistema de Gestión de Información y Eventos de Seguridad (SIEM)

VANT-SIEM CORE es una plataforma integral de SIEM (Security Information and Event Management) desarrollada en Django que proporciona gestión completa de incidentes de seguridad, análisis de logs IDS/IPS, monitoreo de servicios, y herramientas avanzadas de análisis de amenazas.

## 📋 Requisitos del Sistema

### Requisitos Mínimos

- **Python**: 3.10+
- **Django**: 5.0+
- **Base de Datos**: PostgreSQL 12+
- **Memoria RAM**: 4GB mínimo, 8GB recomendado
- **Almacenamiento**: 20GB disponible
- **Sistema Operativo**: Linux (Ubuntu/Debian recomendado), Windows 10+, macOS

### Requisitos Opcionales (Recomendados)

- **Servidores IDS**: Snort 2.9/3.0 o Suricata 6.0+
- **IA Local**: Ollama con modelo llama3.2
- **Servidor SMTP**: Para notificaciones por correo
- **Redis**: Para cache y colas de notificaciones

### Dependencias del Sistema

#### Linux (Ubuntu/Debian)

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias básicas
sudo apt install -y python3 python3-pip python3-venv postgresql postgresql-contrib redis-server

# Instalar herramientas de desarrollo (opcional)
sudo apt install -y git curl wget vim htop

# Instalar Snort (opcional)
sudo apt install -y snort

# Instalar Suricata (opcional)
sudo apt install -y suricata
```

#### Windows

```powershell
# Instalar Python 3.10+
# Descargar desde: https://python.org/downloads/

# Instalar PostgreSQL
# Descargar desde: https://postgresql.org/download/

# Instalar Git
# Descargar desde: https://git-scm.com/downloads

# Instalar Redis (opcional)
# Descargar desde: https://redis.io/download
```

## 🚀 Instalación Paso a Paso

### Paso 1: Clonación del Repositorio

```bash
# Clonar el repositorio
git clone <repository-url>
cd VANT-SIEM-CORE

# Verificar estructura de archivos
ls -la
```

### Paso 2: Configuración del Entorno Virtual

```bash
# Crear entorno virtual
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate     # Windows

# Verificar activación
which python  # Debe mostrar la ruta del entorno virtual
```

### Paso 3: Instalación de Dependencias Python

```bash
# Instalar dependencias del proyecto
pip install -r requirements.txt

# Verificar instalación
python -c "import django; print(f'Django {django.VERSION}')"
```

### Paso 4: Configuración de Base de Datos

#### PostgreSQL Setup

```bash
# Crear base de datos y usuario
sudo -u postgres psql

# Dentro de PostgreSQL:
CREATE DATABASE vant_siem_db;
CREATE USER vant_siem_user WITH PASSWORD 'secure_password_here';
GRANT ALL PRIVILEGES ON DATABASE vant_siem_db TO vant_siem_user;
ALTER USER vant_siem_user CREATEDB;
\q
```

#### Configuración en Django

Editar `CORE/settings.py`:

```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'vant_siem_db',
        'USER': 'vant_siem_user',
        'PASSWORD': 'secure_password_here',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

### Paso 5: Migraciones de Base de Datos

```bash
# Ejecutar migraciones
python manage.py makemigrations
python manage.py migrate

# Verificar migraciones
python manage.py showmigrations
```

### Paso 6: Creación de Superusuario

```bash
# Crear usuario administrador
python manage.py createsuperuser

# Username: admin
# Email: admin@vant-siem.local
# Password: [contraseña segura]
```

### Paso 7: Recopilación de Archivos Estáticos

```bash
# Recopilar archivos estáticos
python manage.py collectstatic --noinput

# Verificar archivos estáticos
ls staticfiles/
```

## 🔧 Configuración Avanzada

### Configuración de IDS/IPS (Opcional)

#### Snort Configuration

```bash
# Instalar Snort
sudo apt install snort  # Ubuntu/Debian

# Configurar reglas básicas
sudo snort -c /etc/snort/snort.conf -i eth0 -A console

# Verificar funcionamiento
sudo systemctl status snort
```

#### Suricata Configuration

```bash
# Instalar Suricata
sudo apt install suricata  # Ubuntu/Debian

# Configurar interfaces
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Verificar funcionamiento
sudo systemctl status suricata
```

### Configuración de Ollama (IA - Recomendado)

```bash
# Instalar Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Descargar modelo recomendado
ollama pull llama3.2

# Verificar instalación
ollama list

# Iniciar servicio
ollama serve

# Probar modelo
ollama run llama3.2 "Hola, ¿estás funcionando?"
```

### Configuración de Correo Electrónico

Editar `CORE/settings.py`:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'tu-email@gmail.com'
EMAIL_HOST_PASSWORD = 'tu-app-password'
DEFAULT_FROM_EMAIL = 'VANT-SIEM <noreply@vant-siem.local>'
```

### Configuración de Redis (Opcional)

```bash
# Instalar Redis
sudo apt install redis-server

# Configurar para iniciar automáticamente
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Verificar funcionamiento
redis-cli ping  # Debe responder PONG
```

## 🖥️ Inicio del Sistema

### Modo Desarrollo

```bash
# Activar entorno virtual
source venv/bin/activate

# Iniciar servidor de desarrollo
python manage.py runserver 0.0.0.0:8000

# Acceder desde navegador
# http://localhost:8000/siem/
```

### Modo Producción (Recomendado)

#### Usando Gunicorn + Nginx

```bash
# Instalar Gunicorn
pip install gunicorn

# Instalar Nginx
sudo apt install nginx

# Crear archivo de configuración Gunicorn
sudo nano /etc/systemd/system/vant-siem.service
```

Contenido del archivo de servicio:

```ini
[Unit]
Description=VANT-SIEM Django Application
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/VANT-SIEM-CORE
Environment="PATH=/path/to/VANT-SIEM-CORE/venv/bin"
ExecStart=/path/to/VANT-SIEM-CORE/venv/bin/gunicorn --workers 3 --bind unix:/run/vant-siem.sock CORE.wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# Recargar systemd y iniciar servicio
sudo systemctl daemon-reload
sudo systemctl start vant-siem
sudo systemctl enable vant-siem

# Verificar estado
sudo systemctl status vant-siem
```

#### Configuración Nginx

```bash
sudo nano /etc/nginx/sites-available/vant-siem
```

Contenido del archivo de sitio:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location = /favicon.ico { access_log off; log_not_found off; }

    location /static/ {
        alias /path/to/VANT-SIEM-CORE/staticfiles/;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/run/vant-siem.sock;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Habilitar sitio
sudo ln -s /etc/nginx/sites-available/vant-siem /etc/nginx/sites-enabled
sudo nginx -t
sudo systemctl restart nginx
```

## 🔐 Configuración de Seguridad

### SSL/TLS Certificate (Producción)

```bash
# Instalar Certbot para Let's Encrypt
sudo apt install certbot python3-certbot-nginx

# Obtener certificado SSL
sudo certbot --nginx -d your-domain.com

# Verificar renovación automática
sudo certbot renew --dry-run
```

### Configuración de Firewall

```bash
# Configurar UFW
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

# Verificar estado
sudo ufw status
```

### Configuración de Seguridad Django

Editar `CORE/settings.py`:

```python
# Seguridad
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Cookies seguras
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# Headers de seguridad adicionales
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
```

## 🧪 Verificación de Instalación

### Pruebas Básicas

```bash
# Verificar Django
python manage.py check

# Verificar base de datos
python manage.py dbshell -c "SELECT version();"

# Verificar archivos estáticos
python manage.py collectstatic --dry-run

# Ejecutar pruebas
python manage.py test --keepdb
```

### Pruebas de Funcionalidad

1. **Acceder al sistema**: `http://localhost:8000/siem/login/`
2. **Login con superusuario**: Verificar acceso al dashboard
3. **Configurar IDS**: Crear configuración de prueba
4. **Probar IA**: Verificar conexión con Ollama
5. **Enviar notificación**: Probar sistema de alertas

### Monitoreo Inicial

```bash
# Ver logs de aplicación
tail -f logs/django.log

# Ver logs de IDS (si configurado)
tail -f logs/ids_ingest.log

# Monitorear procesos
htop
```

## 📊 Monitoreo y Mantenimiento

### Comandos de Gestión

```bash
# Rotación de logs
python manage.py rotate_suricata_logs

# Limpieza de datos antiguos
python manage.py cleanup_old_logs --days 30

# Verificar integridad de base de datos
python manage.py check --deploy

# Backup de base de datos
pg_dump vant_siem_db > backup_$(date +%Y%m%d_%H%M%S).sql
```

### Monitoreo Continuo

```bash
# Instalar herramientas de monitoreo
sudo apt install monitoring-plugins

# Configurar alertas por email
# Configurar logs rotativo
# Configurar backup automático
```

## 🔧 Solución de Problemas

### Problemas Comunes

#### Error de Base de Datos

```bash
# Verificar conexión
python manage.py dbshell

# Recrear migraciones si es necesario
python manage.py makemigrations --empty your_app
python manage.py migrate --fake-initial
```

#### Error de Permisos

```bash
# Corregir permisos de archivos
sudo chown -R www-data:www-data /path/to/VANT-SIEM-CORE
sudo chmod -R 755 /path/to/VANT-SIEM-CORE
```

#### Error de Ollama

```bash
# Verificar servicio
ollama list
ollama serve

# Reiniciar servicio
sudo systemctl restart ollama
```

### Logs de Diagnóstico

```bash
# Ver logs de aplicación
tail -f logs/django.log

# Ver logs de servidor web
sudo tail -f /var/log/nginx/error.log

# Ver logs de base de datos
sudo tail -f /var/log/postgresql/postgresql-*.log
```

## 📞 Soporte

Para problemas durante la instalación:

1. **Revisar logs**: Verificar archivos de log mencionados arriba
2. **Verificar dependencias**: Asegurar que todas las dependencias estén instaladas
3. **Consultar documentación**: Ver [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
4. **Crear issue**: Reportar problemas en el repositorio del proyecto

## ✅ Checklist de Instalación

- [ ] Repositorio clonado
- [ ] Entorno virtual creado y activado
- [ ] Dependencias Python instaladas
- [ ] Base de datos PostgreSQL configurada
- [ ] Migraciones ejecutadas
- [ ] Superusuario creado
- [ ] Archivos estáticos recopilados
- [ ] Servidor web configurado (desarrollo/producción)
- [ ] IDS/IPS configurado (opcional)
- [ ] Ollama instalado y funcionando (recomendado)
- [ ] Correo electrónico configurado
- [ ] Certificado SSL instalado (producción)
- [ ] Firewall configurado
- [ ] Pruebas básicas ejecutadas
- [ ] Monitoreo configurado

---

**¡Instalación completada!** El sistema VANT-SIEM CORE está listo para usar.
