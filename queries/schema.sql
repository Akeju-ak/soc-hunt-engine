
INSTALL json;
LOAD json;


CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS norm;


CREATE TABLE IF NOT EXISTS raw.quarantine (
    source_file VARCHAR,
    raw_record VARCHAR,
    reason_code VARCHAR,
    ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS norm.events (
    event_id VARCHAR PRIMARY KEY,
    event_time TIMESTAMP,
    source_type VARCHAR,        -- 'auth', 'web', 'dns', 'firewall', 'edr'
    identity VARCHAR,           -- User or service account name
    asset_id VARCHAR,           -- System / Host machine identifier
    event_action VARCHAR,       -- Action (e.g., login_success, dns_query, process_start)
    raw_locator VARCHAR         -- Reference back to raw log for audit traceability
);
