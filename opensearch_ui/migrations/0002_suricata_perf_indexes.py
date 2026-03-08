from django.db import migrations


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("ids_ingest", "0001_initial"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            CREATE INDEX IF NOT EXISTS idx_evealert_evt_ts_desc
            ON ids_ingest_suricataevealert (event_type, timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_evealert_evt_ts_srcip
            ON ids_ingest_suricataevealert (event_type, timestamp DESC, src_ip);

            CREATE INDEX IF NOT EXISTS idx_evealert_evt_ts_destip
            ON ids_ingest_suricataevealert (event_type, timestamp DESC, dest_ip);

            CREATE INDEX IF NOT EXISTS idx_evealert_evt_ts_proto
            ON ids_ingest_suricataevealert (event_type, timestamp DESC, proto);

            CREATE INDEX IF NOT EXISTS idx_evealert_evt_ts_category
            ON ids_ingest_suricataevealert (event_type, timestamp DESC, category)
            WHERE category IS NOT NULL;

            CREATE INDEX IF NOT EXISTS idx_flow_ts_desc_proto
            ON ids_ingest_suricataflow (timestamp DESC, proto);

            CREATE INDEX IF NOT EXISTS idx_flow_ts_desc_srcip
            ON ids_ingest_suricataflow (timestamp DESC, src_ip);

            CREATE INDEX IF NOT EXISTS idx_flow_ts_desc_destip
            ON ids_ingest_suricataflow (timestamp DESC, dest_ip);
            """,
            reverse_sql="""
            DROP INDEX IF EXISTS idx_flow_ts_desc_destip;
            DROP INDEX IF EXISTS idx_flow_ts_desc_srcip;
            DROP INDEX IF EXISTS idx_flow_ts_desc_proto;
            DROP INDEX IF EXISTS idx_evealert_evt_ts_category;
            DROP INDEX IF EXISTS idx_evealert_evt_ts_proto;
            DROP INDEX IF EXISTS idx_evealert_evt_ts_destip;
            DROP INDEX IF EXISTS idx_evealert_evt_ts_srcip;
            DROP INDEX IF EXISTS idx_evealert_evt_ts_desc;
            """,
        ),
    ]
