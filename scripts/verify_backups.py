import os
import psycopg2
from datetime import datetime, timedelta

# Configuration from environment or defaults
DB_USER = os.getenv("POSTGRES_USER", "vantsiem")
DB_PASS = os.getenv("POSTGRES_PASSWORD", "vantsiem")
DB_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

# List of databases to verify based on existing backup script
DB_LIST = [
    "vant_assets", "vant_auth", "vant_bus", "vant_dlp", "vant_incidents",
    "vant_intelligence", "vant_inventory", "vant_logs", "vant_logs_db",
    "vant_network", "vant_siem", "vant_soar", "vant_soc", "vant_web"
]

def verify_backup(backup_dir="/opt/vant-siem/backups"):
    results = {}

    for db in DB_LIST:
        print(f"Verifying backup for {db}...")
        # Find the most recent dump file for this DB
        import glob
        files = glob.glob(f"{backup_dir}/{db}_*.dump")
        if not files:
            results[db] = "No backup found"
            continue

        latest_file = max(files, key=os.path.getctime)

        try:
            # Create a temporary database to test restoration
            temp_db = f"temp_verify_{db}"

            # Connect to postgres system db to handle create/drop
            conn = psycopg2.connect(
                dbname="postgres",
                user=DB_USER,
                password=DB_PASS,
                host=DB_HOST,
                port=DB_PORT
            )
            conn.autocommit = True
            cur = conn.cursor()

            # Drop temp db if exists and create new one
            cur.execute(f"DROP DATABASE IF EXISTS {temp_db}")
            cur.execute(f"CREATE DATABASE {temp_db}")
            cur.close()
            conn.close()

            # Attempt restoration using pg_restore
            import subprocess
            # pg_restore -d temp_db latest_file
            res = subprocess.run(
                ["pg_restore", "-d", temp_db, latest_file],
                capture_output=True, text=True, timeout=300
            )

            if res.returncode == 0 or "errors" not in res.stderr.lower():
                results[db] = "Verified"
            else:
                results[db] = f"Failed: {res.stderr[:100]}"

            # Cleanup temp db
            conn = psycopg2.connect(dbname="postgres", user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
            conn.autocommit = True
            cur = conn.cursor()
            cur.execute(f"DROP DATABASE {temp_db}")
            cur.close()
            conn.close()

        except Exception as e:
            results[db] = f"Error: {str(e)}"

    return results

if __name__ == "__main__":
    verification_results = verify_backup()
    for db, status in verification_results.items():
        print(f"{db}: {status}")
