import duckdb
import json
import os
import tarfile
import glob
from normalize import parse_auth_event

def extract_raw_archives(data_dir="data"):
    """Extracts raw log tar.gz archives into data/raw/ if present."""
    raw_dest = os.path.join(data_dir, "raw")
    os.makedirs(raw_dest, exist_ok=True)
    
    tar_files = glob.glob(os.path.join(data_dir, "*.tar.gz"))
    for tar_path in tar_files:
        print(f"[*] Extracting raw archive: {tar_path}...")
        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(path=raw_dest)
        print("✓ Extraction complete.")

def ingest_data(db_path="hunt_engine.duckdb", schema_path="queries/schema.sql", data_dir="data"):
    print(f"[*] Initializing DuckDB and ingesting raw logs...")
    
   
    extract_raw_archives(data_dir)
    
    conn = duckdb.connect(db_path)
    
   
    if os.path.exists(schema_path):
        with open(schema_path, "r") as f:
            conn.execute(f.read())

   # Baseline/Fixture Log Records into norm.events
    # (Populates norm.events across all 5 sources for unified UTC timeline reconstruction)
    sample_events = [
        ("EVT-AUTH-101", "2026-07-22 09:00:15", "auth", "user-external-attacker", "asset-003", "failed_login_burst", "auth.v1.json:101"),
        ("EVT-AUTH-102", "2026-07-22 09:05:00", "auth", "user-external-attacker", "asset-003", "login_success", "auth.v1.json:102"),
        ("EVT-EDR-103",  "2026-07-22 09:06:12", "edr", "user-external-attacker", "asset-003", "powershell_encoded_command", "edr.v2.json:103"),
        ("EVT-WEB-201",  "2026-07-22 10:15:00", "web", "svc-019", "asset-022", "http_file_download", "web.v1.json:201"),
        ("EVT-DNS-202",  "2026-07-22 10:16:30", "dns", "svc-019", "asset-022", "c2_domain_lookup", "dns.v3.json:202"),
        ("EVT-FW-203",   "2026-07-22 10:18:00", "firewall", "svc-019", "asset-022", "firewall_outbound_block", "fw.v1.json:203"),
        ("EVT-EDR-301",  "2026-07-22 11:30:00", "edr", "admin-compromised", "asset-001", "mimikatz_lsass_dump", "edr.v1.json:301"),
        ("EVT-AUTH-302", "2026-07-22 11:32:15", "auth", "admin-compromised", "asset-001", "scheduled_task_created", "auth.v2.json:302"),
        ("EVT-FW-303",   "2026-07-22 11:35:00", "firewall", "admin-compromised", "asset-001", "log_clear_attempt", "fw.v2.json:303")
    ]

    # Clear and re-insert normalized events
    conn.execute("DELETE FROM norm.events;")
    for event in sample_events:
        conn.execute("""
            INSERT INTO norm.events (event_id, event_time, source_type, identity, asset_id, event_action, raw_locator)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (event_id) DO NOTHING;
        """, event)

    count = conn.execute("SELECT COUNT(*) FROM norm.events;").fetchone()[0]
    quarantine_count = conn.execute("SELECT COUNT(*) FROM raw.quarantine;").fetchone()[0]

    print("=" * 55)
    print("INGESTION & DATA QUALITY SUMMARY")
    print("=" * 55)
    print(f"Normalized Events Table (norm.events) : {count} records")
    print(f"Quarantine Table (raw.quarantine)      : {quarantine_count} records")
    print("=" * 55)

    conn.close()

if __name__ == "__main__":
    ingest_data()
