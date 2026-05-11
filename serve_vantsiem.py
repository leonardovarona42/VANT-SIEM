import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).resolve().parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')

import django
django.setup()

from django.conf import settings
from waitress import serve
from CORE.wsgi import application

host, port = os.getenv('GUNICORN_BIND', '127.0.0.1:8000').split(':')
port = int(port)

print(f"VANT-SIEM starting on {host}:{port}")
print(f"DEBUG: {settings.DEBUG}")
print(f"DB: {settings.DATABASES['default']['NAME']} @ {settings.DATABASES['default']['HOST']}")

serve(application, host=host, port=port, threads=8, channel_timeout=120)
