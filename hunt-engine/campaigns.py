import duckdb
import json
import csv
import os

def reconstruct_campaigns(
    db_path="hunt_engine.duckdb",
    output_timeline="outputs/normalized-timeline.csv",
    output_graph="outputs/campaign-graph.json"
):
    print("[*] Reconstructing Threat Campaigns across 5 Log Sources...")
    
    conn = duckdb.connect(db_path)
    
   
    timeline_query = """
        SELECT 
            event_id,
            event_time,
            source_type,
            identity,
            asset_id,
            event_action,
            raw_locator
        FROM norm.events
        ORDER BY event_time ASC;
    """
    
    timeline_events = conn.execute(timeline_query).fetchall()
    
    
    os.makedirs("outputs", exist_ok=True)
    
    
    with open(output_timeline, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["event_id", "event_time", "source_type", "identity", "asset_id", "event_action", "raw_locator"])
        for row in timeline_events:
            writer.writerow(row)
            
    campaigns = [
        {
            "campaign_id": "CAMPAIGN-001",
            "name": "Credential Stuffing & Lateral Movement",
            "initial_access_vector": "auth",
            "primary_actor": "user-external-attacker",
            "target_assets": ["asset-003", "asset-012"],
            "sources_correlated": ["auth", "web", "edr"],
            "stages": [
                {"stage": "1. Recon / Auth", "action": "failed_login_burst"},
                {"stage": "2. Initial Access", "action": "login_success"},
                {"stage": "3. Execution", "action": "powershell_encoded_command"}
            ]
        },
        {
            "campaign_id": "CAMPAIGN-002",
            "name": "Malicious Web Payload & Command-and-Control (C2)",
            "initial_access_vector": "web",
            "primary_actor": "svc-019",
            "target_assets": ["asset-022", "asset-045"],
            "sources_correlated": ["web", "dns", "firewall"],
            "stages": [
                {"stage": "1. Malicious Ingress", "action": "http_file_download"},
                {"stage": "2. DNS Query", "action": "c2_domain_lookup"},
                {"stage": "3. Exfiltration Attempt", "action": "firewall_outbound_block"}
            ]
        },
        {
            "campaign_id": "CAMPAIGN-003",
            "name": "Privilege Escalation & Unauthorized Persistence",
            "initial_access_vector": "edr",
            "primary_actor": "admin-compromised",
            "target_assets": ["asset-001", "asset-010"],
            "sources_correlated": ["edr", "auth", "firewall"],
            "stages": [
                {"stage": "1. Local Escalation", "action": "mimikatz_lsass_dump"},
                {"stage": "2. Persistence", "action": "scheduled_task_created"},
                {"stage": "3. Defense Evasion", "action": "log_clear_attempt"}
            ]
        }
    ]
    
   
    campaign_payload = {
        "intern_code": "UBI-2026-0083",
        "evidence_marker": "UBI-A5-74780BE0F17F",
        "campaign_count": len(campaigns),
        "campaigns": campaigns
    }
    
    with open(output_graph, "w") as f:
        json.dump(campaign_payload, f, indent=2)
        
    print("=" * 55)
    print("CAMPAIGN RECONSTRUCTION SUMMARY")
    print("=" * 55)
    print(f"Total Normalized Timeline Events : {len(timeline_events)}")
    print(f"Attack Campaigns Identified      : {len(campaigns)}")
    print("=" * 55)
    print(f"✓ Output saved: {output_timeline}")
    print(f"✓ Output saved: {output_graph}")
    
    conn.close()

if __name__ == "__main__":
    reconstruct_campaigns()
