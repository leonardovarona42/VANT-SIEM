import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SHARED_DIR = BASE_DIR.parent / "shared" / "vant_common"
if SHARED_DIR.exists() and str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "vant-web-insecure-change-me-in-production-9f8e7d6c5b4a",
)

DEBUG = os.getenv("DJANGO_DEBUG", "False").lower() in ("true", "1", "yes")

ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "*").split(",")

INSTALLED_APPS = [
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "web_app",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

try:
    from vant_common.middleware import RequestTimingMiddleware
    MIDDLEWARE.append("vant_common.middleware.RequestTimingMiddleware")
except ImportError:
    pass

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "web_app" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
                "web_app.context_processors.service_status",
                "web_app.context_processors.user_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "vant_web"),
        "USER": os.getenv("POSTGRES_USER", "vantsiem"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "vantsiem"),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
    }
}

LANGUAGE_CODE = "es"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = os.getenv("STATIC_ROOT", "/home/vant-siem/staticfiles/")
STATICFILES_DIRS = [
    BASE_DIR / "web_app" / "static",
]

MEDIA_URL = "/media/"
MEDIA_ROOT = os.getenv("MEDIA_ROOT", "/home/vant-siem/media/")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/siem/dashboard/login/"

SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_AGE = 28800
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True

SERVICE_SECRET = os.getenv("SERVICE_SECRET", "")

SERVICE_URLS = {
    "AUTH_SERVICE_URL": os.getenv("AUTH_SERVICE_URL", "http://127.0.0.1:8100"),
    "INVENTORY_SERVICE_URL": os.getenv("INVENTORY_SERVICE_URL", "http://127.0.0.1:8300"),
    "LOGS_SERVICE_URL": os.getenv("LOGS_SERVICE_URL", "http://127.0.0.1:8400"),
    "SOC_SERVICE_URL": os.getenv("SOC_SERVICE_URL", "http://127.0.0.1:8500"),
    "BUS_SERVICE_URL": os.getenv("BUS_SERVICE_URL", "http://127.0.0.1:8600"),
    "INTELLIGENCE_SERVICE_URL": os.getenv("INTELLIGENCE_SERVICE_URL", "http://127.0.0.1:8700"),
    "SOAR_SERVICE_URL": os.getenv("SOAR_SERVICE_URL", "http://127.0.0.1:8800"),
}

for key, val in SERVICE_URLS.items():
    globals()[key] = val
