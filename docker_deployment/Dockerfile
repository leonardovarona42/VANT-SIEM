FROM python:3.12-slim AS base

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Web Portal (Django UI)
FROM base AS django
EXPOSE 8000 8001 8002 8003
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

# Logs Service (HTTP ingestion)
FROM base AS service
EXPOSE 9201
CMD ["python", "manage.py", "run_opensearch_service", "--host", "0.0.0.0", "--port", "9201"]

# AI Service (with GPU support optional)
FROM base AS ai-service
EXPOSE 8003
CMD ["python", "manage.py", "runserver", "0.0.0.0:8003"]

# Celery Worker
FROM base AS celery
CMD ["celery", "-A", "CORE", "worker", "--loglevel=info", "--concurrency=4"]
