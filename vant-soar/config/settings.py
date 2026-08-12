import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SHARED_DIR = BASE_DIR.parent / 'shared'
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'vant-soar-dev-key-change-in-production')

DEBUG = os.getenv('DJANGO_DEBUG', 'False').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', '*').split(',')

INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'rest_framework',
    'corsheaders',
    'soar_app',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'vant_common.middleware.ServiceAuthMiddleware',
    'vant_common.middleware.RequestTimingMiddleware',
]

ROOT_URLCONF = 'config.urls'

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("POSTGRES_DB", "vant_soar"),
        "USER": os.getenv("POSTGRES_USER", "vantsiem"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "vantsiem"),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": 600,
    },
    "vant_logs": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "vant_logs",
        "USER": os.getenv("POSTGRES_USER", "vantsiem"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "vantsiem"),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": 600,
    },
    "vant_soc": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "vant_soc",
        "USER": os.getenv("POSTGRES_USER", "vantsiem"),
        "PASSWORD": os.getenv("POSTGRES_PASSWORD", "vantsiem"),
        "HOST": os.getenv("POSTGRES_HOST", "127.0.0.1"),
        "PORT": os.getenv("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": 600,
    },
}

DATABASE_ROUTERS = ['soar_app.db_router.LogsRouter']

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [],
    'DEFAULT_PERMISSION_CLASSES': [],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
}

CORS_ALLOW_ALL_ORIGINS = DEBUG

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} {levelname} {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': os.getenv('LOG_LEVEL', 'INFO'),
    },
    'loggers': {
        'soar_app': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'vant_common': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Paths for serialized ML models
SOAR_MODELS_DIR = BASE_DIR / 'models'
SOAR_MODELS_DIR.mkdir(exist_ok=True)
