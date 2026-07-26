import os

wsgi_app = "config.wsgi:application"

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8500")
workers = 2
worker_class = "gevent"
worker_connections = 200
timeout = 120
keepalive = 5
max_requests = 2000
accesslog = "/var/log/vant/soc-access.log"
errorlog = "/var/log/vant/soc-error.log"
loglevel = "info"
