import os

wsgi_app = "config.wsgi:application"

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8600")
workers = 2
worker_class = "sync"
timeout = 30
keepalive = 5
max_requests = 2000
accesslog = "/var/log/vant/bus-access.log"
errorlog = "/var/log/vant/bus-error.log"
loglevel = "info"
