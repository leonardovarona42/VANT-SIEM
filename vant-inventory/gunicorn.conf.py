import os

wsgi_app = "config.wsgi:application"

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8300")
workers = 4
worker_class = "gevent"
worker_connections = 500
timeout = 60
keepalive = 5
max_requests = 2000
max_requests_jitter = 200
accesslog = "/var/log/vant/inventory-access.log"
errorlog = "/var/log/vant/inventory-error.log"
loglevel = "info"
