import os


class Settings:
    SERVICE_HOST = os.getenv("OS_SERVICE_HOST", "192.168.1.12")
    SERVICE_PORT = int(os.getenv("OS_SERVICE_PORT", "9201"))

    DB_HOST = os.getenv("OS_DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("OS_DB_PORT", "5432"))
    DB_NAME = os.getenv("OS_DB_NAME", "vant_opensearch")
    DB_USER = os.getenv("OS_DB_USER", "postgres")
    DB_PASSWORD = os.getenv("OS_DB_PASSWORD", "postgres")

    AUTH_MODE = os.getenv("OS_AUTH_MODE", "none").lower()  # none|basic|token
    AUTH_USERNAME = os.getenv("OS_AUTH_USERNAME", "")
    AUTH_PASSWORD = os.getenv("OS_AUTH_PASSWORD", "")
    AUTH_TOKEN = os.getenv("OS_AUTH_TOKEN", "")
