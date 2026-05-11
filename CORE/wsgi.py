"""
WSGI config for CORE project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'CORE.settings')

application = get_wsgi_application()

from whitenoise import WhiteNoise
application = WhiteNoise(application, root=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'staticfiles'))
application.add_files(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'VANT_SIEM', 'assets'), prefix='static/')
