import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SHARED_DIR = BASE_DIR.parent / "shared"
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "django-insecure-vant-bus-dev-key-change-in-production")
DEBUG = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "corsheaders",
    "rest_framework",
    "bus_app",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "vant_common.middleware.ServiceAuthMiddleware",
    "vant_common.middleware.RequestTimingMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "vant_bus"),
        "USER": os.getenv("POSTGRES_USER", "vantsiem"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "vantsiem"),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": [],
    "UNAUTHENTICATED_USER": None,
}

CORS_ALLOW_ALL_ORIGINS = True

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/4")
REDIS_STREAM_MAX_LEN = int(os.getenv("REDIS_STREAM_MAX_LEN", "100000"))

ALERT_EMAIL_HOST = os.getenv("ALERT_EMAIL_HOST", "smtp.gmail.com")
ALERT_EMAIL_PORT = int(os.getenv("ALERT_EMAIL_PORT", "587"))
ALERT_EMAIL_USER = os.getenv("ALERT_EMAIL_USER", "")
ALERT_EMAIL_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD", "")
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "vant-alerts@example.com")
ALERT_EMAIL_USE_TLS = os.getenv("ALERT_EMAIL_USE_TLS", "True").lower() in ("true", "1", "yes")

ALERT_TELEGRAM_BOT_TOKEN = os.getenv("ALERT_TELEGRAM_BOT_TOKEN", "")
ALERT_TELEGRAM_CHAT_ID = os.getenv("ALERT_TELEGRAM_CHAT_ID", "")

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")
ALERT_WEBHOOK_SECRET = os.getenv("ALERT_WEBHOOK_SECRET", "")

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True
