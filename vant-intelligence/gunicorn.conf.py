import os

wsgi_app = "config.wsgi:application"

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8700")
workers = 2
worker_class = "sync"
timeout = 30
keepalive = 5
max_requests = 5000
max_requests_jitter = 500
accesslog = "/var/log/vant/intelligence-access.log"
errorlog = "/var/log/vant/intelligence-error.log"
loglevel = "info"
