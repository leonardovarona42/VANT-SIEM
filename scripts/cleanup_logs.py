import os
import psycopg2
from datetime import datetime, timedelta

# Configuration from environment or defaults
DB_NAME = os.getenv("POSTGRES_DB", "vant_logs")
DB_USER = os.getenv("POSTGRES_USER", "vantsiem")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "vantsiem")
DB_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

RETENTION_DAYS = 90

def cleanup():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT
        )
        conn.autocommit = True
        cur = conn.cursor()

        # Log events cleanup
        # Assuming the table is logs_events_raw as per audit
        query = f"DELETE FROM logs_events_raw WHERE event_time < NOW() - INTERVAL '{RETENTION_DAYS} days'"
        cur.execute(query)
        deleted = cur.rowcount

        print(f"Successfully deleted {deleted} old events from logs_events_raw.")

        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error during cleanup: {e}")

if __name__ == "__main__":
    cleanup()
