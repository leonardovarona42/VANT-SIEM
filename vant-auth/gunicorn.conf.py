import os

wsgi_app = "config.wsgi:application"

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8100")
workers = 2
worker_class = "sync"
timeout = 30
keepalive = 5
max_requests = 1000
accesslog = "/var/log/vant/auth-access.log"
errorlog = "/var/log/vant/auth-error.log"
loglevel = "info"
