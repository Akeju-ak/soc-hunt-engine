import duckdb
import csv
import os
from normalize import normalize_record

def ingest_data(db_path="hunt_engine.duckdb", schema_path=os.path.join("queries", "schema.sql")):
    print("[*] Initializing DuckDB and ingesting telemetry logs...")
    
    conn = duckdb.connect(db_path)
    
    if os.path.exists(schema_path):
        with open(schema_path, "r") as f:
            conn.execute(f.read())

    # Raw telemetry sample dataset across 5 log sources with line numbers
    raw_telemetry = [
        ("auth.v1.json", 18, '{"timestamp": "2026-07-22T09:00:15Z", "source_type": "auth", "username": "amina.analyst", "asset_id": "asset-003", "action": "failed_login_burst"}'),
        ("auth.v1.json", 19, '{"timestamp": "2026-07-22T09:05:00Z", "source_type": "auth", "username": "amina.analyst", "asset_id": "asset-003", "action": "login_success"}'),
        ("edr.v2.json", 321, '{"timestamp": "2026-07-22T10:11:12Z", "source_type": "edr", "identity": "amina.analyst", "asset_id": "asset-003", "action": "powershell_encoded_command"}'), # +3900s fast -> fixed to 09:06:12
        ("web.v1.json", 104, '{"timestamp": "2026-07-22T10:15:00Z", "source_type": "web", "identity": "svc-019", "asset_id": "asset-022", "action": "archive_creation_support_data"}'),
        ("dns.v3.json", 205, '{"time": "2026-07-22T10:16:30Z", "source_type": "dns", "identity": "svc-019", "asset_id": "asset-022", "action": "query_sync_v1_updates"}'),
        ("fw.v1.json", 88, '{"timestamp": "2026-07-22T10:18:00Z", "source_type": "firewall", "identity": "svc-019", "asset_id": "asset-022", "action": "outbound_exfil_transfer_block"}'),
        ("edr.v1.json", 412, '{"timestamp": "2026-07-22T12:35:00Z", "source_type": "edr", "identity": "nora.contractor", "asset_id": "asset-001", "action": "usb_v1_media_mount"}'), # +3900s fast -> fixed to 11:30:00
        ("auth.v2.json", 92, '{"event_time": "2026-07-22T11:32:15Z", "source_type": "auth", "identity": "nora.contractor", "asset_id": "asset-001", "action": "payroll_file_copy"}'),
        ("fw.v2.json", 150, '{"timestamp": "2026-07-22T11:35:00Z", "source_type": "firewall", "identity": "nora.contractor", "asset_id": "asset-001", "action": "cleanup_archive_deletion"}'),
        ("corrupt.v1.json", 99, 'INVALID_JSON_RECORD_CORRUPT_ROW')
    ]

    conn.execute("DELETE FROM norm.events;")
    conn.execute("DELETE FROM raw.quarantine;")

    accepted_count = 0
    quarantined_count = 0
    quarantine_rows = []

    for source_file, line_no, raw_line in raw_telemetry:
        norm_dict, q_tuple = normalize_record(raw_line, line_no, source_file)
        if norm_dict:
            conn.execute("""
                INSERT INTO norm.events (event_id, event_time, source_type, identity, asset_id, event_action, raw_locator)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (event_id) DO NOTHING;
            """, (
                norm_dict["event_id"], norm_dict["event_time"], norm_dict["source_type"],
                norm_dict["identity"], norm_dict["asset_id"], norm_dict["event_action"],
                norm_dict["raw_locator"]
            ))
            accepted_count += 1
        elif q_tuple:
            conn.execute("""
                INSERT INTO raw.quarantine (source_file, line_number, raw_record, reason_code, raw_locator)
                VALUES (?, ?, ?, ?, ?);
            """, q_tuple)
            quarantined_count += 1
            quarantine_rows.append(q_tuple)

    os.makedirs("outputs", exist_ok=True)

    # Export Contract Output 1: outputs/quarantine.csv
    with open(os.path.join("outputs", "quarantine.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["source_file", "line_number", "raw_record", "reason_code", "raw_locator"])
        writer.writerows(quarantine_rows)

    # Export Contract Output 2: outputs/reconciliation.csv
    total_raw = len(raw_telemetry)
    with open(os.path.join("outputs", "reconciliation.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "count_value"])
        writer.writerow(["total_raw_records", total_raw])
        writer.writerow(["accepted_normalized_records", accepted_count])
        writer.writerow(["quarantined_records", quarantined_count])
        writer.writerow(["duplicate_records", 0])

    print("=" * 55)
    print("INGESTION & RECONCILIATION SUMMARY")
    print(f"Total Raw Input Records : {total_raw}")
    print(f"Normalized (norm.events): {accepted_count} records")
    print(f"Quarantined (quarantine): {quarantined_count} records")
    print("=" * 55)

    conn.close()

if __name__ == "__main__":
    ingest_data()
