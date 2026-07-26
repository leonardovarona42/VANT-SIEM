import os

wsgi_app = "config.wsgi:application"

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8400")
workers = 4
worker_class = "gevent"
worker_connections = 500
timeout = 30
keepalive = 5
max_requests = 5000
max_requests_jitter = 500
accesslog = "/var/log/vant/logs-access.log"
errorlog = "/var/log/vant/logs-error.log"
loglevel = "info"
