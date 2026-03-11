CREATE TABLE IF NOT EXISTS os_sources (
    id BIGSERIAL PRIMARY KEY,
    source_id VARCHAR(128) UNIQUE NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    host_name VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen_at TIMESTAMPTZ,
    meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS os_events_raw (
    id BIGSERIAL PRIMARY KEY,
    source_type VARCHAR(64) NOT NULL,
    source_name VARCHAR(128) NOT NULL,
    host_name VARCHAR(255),
    host_ip VARCHAR(64),
    event_time TIMESTAMPTZ NOT NULL,
    severity VARCHAR(32),
    event_category VARCHAR(128),
    message TEXT,
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_os_events_time ON os_events_raw (event_time DESC);
CREATE INDEX IF NOT EXISTS idx_os_events_source ON os_events_raw (source_type, source_name, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_os_events_category ON os_events_raw (event_category, event_time DESC);
