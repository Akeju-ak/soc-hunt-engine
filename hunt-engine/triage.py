import json
import csv
import os
from datetime import datetime

def parse_iso(dt_str):
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        return None

def is_valid_asset(asset_id):
    """Checks if asset is a valid corporate machine (asset-001 through asset-050)."""
    if not asset_id or asset_id in ("asset-999", "asset-000", "unknown", "none", "unassigned"):
        return False
    if asset_id.startswith("asset-"):
        try:
            num = int(asset_id.split("-")[1])
            return 1 <= num <= 50
        except (IndexError, ValueError):
            return False
    return False

def is_valid_actor(actor):
    """Checks if actor is an authorized service account (svc-001 through svc-050)."""
    if not actor or not actor.startswith("svc-") or actor in ("svc-999", "svc-000", "unknown", "none"):
        return False
    try:
        num = int(actor.split("-")[1])
        return 1 <= num <= 50
    except (IndexError, ValueError):
        return False

def run_triage(
    discrepancy_path="data/ubi-2026-0083-stage-5-discrepancy.json",
    output_json="outputs/triage_results.json",
    output_csv="outputs/tp-fp-table.csv"
):
    print("[*] Running Complete 7-Point Compliance Triage Engine...")
    
    if not os.path.exists(discrepancy_path):
        print(f"[!] Error: File not found at {discrepancy_path}")
        return

    with open(discrepancy_path, "r") as f:
        data = json.load(f)

    candidates = data.get("reviewCandidates", [])
    change_records = {rec["activityId"]: rec for rec in data.get("changeRecords", [])}

    valid_owners = {"Security Engineering", "Platform", "Data Services", "IT Operations"}

    benign_list = []
    escalation_list = []
    csv_rows = [["activity_id", "disposition", "change_id", "reason"]]

    for cand in candidates:
        act_id = cand["activityId"]
        ticket = change_records.get(act_id)

        # Check 1: Ticket Existence
        if not ticket:
            reason = "MISSING_CHANGE_TICKET"
            escalation_list.append({"activityId": act_id, "reason": reason})
            csv_rows.append([act_id, "ESCALATE", "NONE", reason])
            continue

        change_id = ticket.get("changeId", "UNKNOWN")
        asset_id = str(ticket.get("assetId", ""))
        actor = str(ticket.get("actor", ""))
        owner = str(ticket.get("owner", ""))
        status = str(ticket.get("status", ""))
        approver = str(ticket.get("approvedBy", ""))
        starts_at = parse_iso(ticket.get("startsAt", ""))
        ends_at = parse_iso(ticket.get("endsAt", ""))

        reasons = []

        # Check 2: Status Validation
        if status != "APPROVED":
            reasons.append(f"Invalid status ({status})")

        # Check 3: Approver Authority Validation
        if approver != "change-board":
            reasons.append(f"Unapproved authority ({approver})")

        # Check 4: Asset Range Validation
        if not is_valid_asset(asset_id):
            reasons.append(f"Invalid asset binding ({asset_id})")

        # Check 5: Actor Service Account Range Validation
        if not is_valid_actor(actor):
            reasons.append(f"Unauthorized or invalid actor ({actor})")

        # Check 6: Operational Owner Department Validation
        if owner not in valid_owners:
            reasons.append(f"Unauthorized department owner ({owner})")

        # Check 7: Time Window Duration Validation
        if not starts_at or not ends_at:
            reasons.append("Missing timestamp in window")
        else:
            duration_sec = (ends_at - starts_at).total_seconds()
            if duration_sec <= 0 or duration_sec > 7200:
                reasons.append(f"Non-covering or invalid duration ({duration_sec}s)")

        # Final Classification
        if not reasons:
            benign_list.append({
                "activityId": act_id,
                "changeId": change_id,
                "disposition": "BENIGN"
            })
            csv_rows.append([act_id, "BENIGN", change_id, "Authorized Change Ticket"])
        else:
            combined_reason = " | ".join(reasons)
            escalation_list.append({
                "activityId": act_id,
                "changeId": change_id,
                "reason": combined_reason,
                "disposition": "ESCALATE"
            })
            csv_rows.append([act_id, "ESCALATE", change_id, combined_reason])

    # Ensure output directory exists
    os.makedirs("outputs", exist_ok=True)

    # Save Deliverable Output #10: JSON Triage Results
    triage_payload = {
        "intern_code": "UBI-2026-0083",
        "evidence_marker": "UBI-A5-74780BE0F17F",
        "summary": {
            "total_evaluated": len(candidates),
            "benign_count": len(benign_list),
            "escalated_count": len(escalation_list)
        },
        "benign_candidates": benign_list,
        "escalated_incidents": escalation_list
    }

    with open(output_json, "w") as f:
        json.dump(triage_payload, f, indent=2)

    # Save Deliverable Output: CSV Decision Table
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(csv_rows)

    print("=" * 55)
    print("TRIAGE EXECUTION SUMMARY")
    print("=" * 55)
    print(f"Total Candidates Analyzed : {len(candidates)}")
    print(f"Benign Matches (FP)       : {len(benign_list)} (Target: 80)")
    print(f"Escalated Incidents (TP)  : {len(escalation_list)} (Target: 16)")
    print("=" * 55)
    print(f"✓ Output saved: {output_json}")
    print(f"✓ Output saved: {output_csv}")

if __name__ == "__main__":
    run_triage()
