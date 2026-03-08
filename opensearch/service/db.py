import json
try:
    from psycopg import connect
    from psycopg.rows import dict_row
    _USE_PSYCOPG3 = True
except Exception:
    import psycopg2
    import psycopg2.extras
    _USE_PSYCOPG3 = False

from config import Settings


def get_conn():
    if _USE_PSYCOPG3:
        return connect(
            host=Settings.DB_HOST,
            port=Settings.DB_PORT,
            dbname=Settings.DB_NAME,
            user=Settings.DB_USER,
            password=Settings.DB_PASSWORD,
            autocommit=True,
        )
    conn = psycopg2.connect(
        host=Settings.DB_HOST,
        port=Settings.DB_PORT,
        dbname=Settings.DB_NAME,
        user=Settings.DB_USER,
        password=Settings.DB_PASSWORD,
    )
    conn.autocommit = True
    return conn


def save_events(events):
    if not events:
        return 0

    with get_conn() as conn:
        with conn.cursor() as cur:
            for ev in events:
                cur.execute(
                    """
                    INSERT INTO os_events_raw (
                        source_type, source_name, host_name, event_time, severity,
                        event_category, message, raw_payload, tags
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
                    """,
                    (
                        ev.get("source_type"),
                        ev.get("source_name"),
                        ev.get("host_name"),
                        ev.get("event_time"),
                        ev.get("severity"),
                        ev.get("event_category"),
                        ev.get("message"),
                        json.dumps(ev.get("raw_payload", {})),
                        json.dumps(ev.get("tags", [])),
                    ),
                )
    return len(events)


def upsert_source(source):
    with get_conn() as conn:
        if _USE_PSYCOPG3:
            cur = conn.cursor(row_factory=dict_row)
        else:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        with cur:
            cur.execute(
                """
                INSERT INTO os_sources (source_id, source_type, host_name, enabled, last_seen_at, meta)
                VALUES (%s, %s, %s, %s, NOW(), %s::jsonb)
                ON CONFLICT (source_id)
                DO UPDATE SET
                    source_type = EXCLUDED.source_type,
                    host_name = EXCLUDED.host_name,
                    enabled = EXCLUDED.enabled,
                    last_seen_at = NOW(),
                    meta = EXCLUDED.meta
                RETURNING source_id
                """,
                (
                    source.get("source_id"),
                    source.get("source_type"),
                    source.get("host_name"),
                    bool(source.get("enabled", True)),
                    json.dumps(source.get("meta", {})),
                ),
            )
            return cur.fetchone()
