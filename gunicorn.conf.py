import os
wsgi_app = 'CORE.wsgi:application'
bind = os.getenv('GUNICORN_BIND', '127.0.0.1:8000')
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
