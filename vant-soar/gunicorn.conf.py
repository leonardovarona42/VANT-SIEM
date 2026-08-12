import multiprocessing
import os

bind = os.getenv("GUNICORN_BIND", "127.0.0.1:8800")
workers = int(os.getenv("GUNICORN_WORKERS", "2"))
threads = int(os.getenv("GUNICORN_THREADS", "4"))
timeout = 120
graceful_timeout = 30
max_requests = 1000
max_requests_jitter = 100
preload = True

accesslog = os.getenv("GUNICORN_ACCESS_LOG", "-")
errorlog = os.getenv("GUNICORN_ERROR_LOG", "-")
loglevel = os.getenv("LOG_LEVEL", "info")
