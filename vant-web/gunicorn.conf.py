import os

wsgi_app = "config.wsgi:application"

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8200")
workers = 4
worker_class = "gevent"
worker_connections = 500
timeout = 60
keepalive = 5
max_requests = 2000
accesslog = "/var/log/vant/web-access.log"
errorlog = "/var/log/vant/web-error.log"
loglevel = "info"
