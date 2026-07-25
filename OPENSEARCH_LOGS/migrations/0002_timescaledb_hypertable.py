from django.db import migrations

def create_hypertable(apps, schema_editor):
    """
    Converts logs_events_raw into a TimescaleDB hypertable.
    Only works if TimescaleDB extension is installed.
    Skipped silently if not available.
    """
    with schema_editor.connection.cursor() as cursor:
        try:
            cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'timescaledb';")
            if cursor.fetchone():
                cursor.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM timescaledb_information.hypertables
                            WHERE hypertable_name = 'logs_events_raw'
                        ) THEN
                            ALTER TABLE logs_events_raw DROP CONSTRAINT IF EXISTS logs_events_raw_pkey;
                            PERFORM create_hypertable(
                                'logs_events_raw', 'event_time',
                                if_not_exists => TRUE,
                                chunk_time_interval => interval '7 days'
                            );
                        END IF;
                    END
                    $$;
                """)
            else:
                print("TimescaleDB not installed. Skipping hypertable creation.")
        except Exception as e:
            print(f"Hypertable creation skipped: {e}")


def drop_hypertable(apps, schema_editor):
    with schema_editor.connection.cursor() as cursor:
        try:
            cursor.execute("SELECT extname FROM pg_extension WHERE extname = 'timescaledb';")
            if cursor.fetchone():
                cursor.execute(
                    "SELECT drop_chunks('logs_events_raw', older_than => (now() - interval '7 days'));"
                )
        except Exception as e:
            print(f"Hypertable drop skipped: {e}")


class Migration(migrations.Migration):

    dependencies = [
        ('OPENSEARCH_LOGS', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_hypertable, reverse_code=drop_hypertable),
    ]
