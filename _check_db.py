from django.conf import settings
import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'VANT_SIEM.settings')
import django
django.setup()
db = settings.DATABASES['default']
print(f"DB Name: {db['NAME']}")
print(f"DB User: {db['USER']}")
print(f"DB Host: {db['HOST']}")
print(f"DB Port: {db['PORT']}")
