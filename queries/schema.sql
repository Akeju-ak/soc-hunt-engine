INSTALL json;
LOAD json;

CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS norm;

CREATE TABLE IF NOT EXISTS raw.quarantine (
    source_file VARCHAR,
    line_number INTEGER,
    raw_record VARCHAR,
    reason_code VARCHAR,
    raw_locator VARCHAR,
    ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS norm.events (
    event_id VARCHAR PRIMARY KEY,
    event_time TIMESTAMP,
    source_type VARCHAR,
    identity VARCHAR,
    asset_id VARCHAR,
    event_action VARCHAR,
    raw_locator VARCHAR
);

CREATE TABLE IF NOT EXISTS norm.reconciliation (
    metric VARCHAR PRIMARY KEY,
    count_value INTEGER
);
