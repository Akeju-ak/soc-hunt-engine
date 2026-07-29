import json
import csv
import os
from datetime import datetime

def parse_iso(dt_str):
    try:
        return datetime.fromisoformat(str(dt_str).replace("Z", "+00:00"))
    except Exception:
        return None

def is_valid_asset(asset_id):
    if not asset_id or asset_id in ("asset-999", "asset-000", "unknown", "none"):
        return False
    if str(asset_id).startswith("asset-"):
        try:
            num = int(str(asset_id).split("-")[1])
            return 1 <= num <= 50
        except (IndexError, ValueError):
            return False
    return False

def is_valid_actor(actor):
    if not actor or not str(actor).startswith("svc-") or actor in ("svc-999", "svc-000", "unknown"):
        return False
    try:
        num = int(str(actor).split("-")[1])
        return 1 <= num <= 50
    except (IndexError, ValueError):
        return False

def run_triage(
    discrepancy_path=os.path.join("data", "ubi-2026-0083-stage-5-discrepancy.json"),
    output_json=os.path.join("outputs", "triage_results.json"),
    output_csv=os.path.join("outputs", "tp-fp-table.csv")
):
    print("[*] Running 7-Point Compliance Alert Triage Engine...")
    
    if not os.path.exists(discrepancy_path):
        print(f"[!] File not found: {discrepancy_path}")
        return

    with open(discrepancy_path, "r") as f:
        data = json.load(f)

    candidates = data.get("reviewCandidates", [])
    change_records = {rec["activityId"]: rec for rec in data.get("changeRecords", [])}
    valid_owners = {"Security Engineering", "Platform", "Data Services", "IT Operations"}

    benign_list = []
    escalation_list = []
    csv_rows = [["activity_id", "disposition", "change_id", "raw_locator", "reason"]]

    source_file_name = os.path.basename(discrepancy_path)

    for idx, cand in enumerate(candidates, start=1):
        act_id = cand["activityId"]
        raw_locator = f"{source_file_name}:{idx}"
        ticket = change_records.get(act_id)

        if not ticket:
            reason = "MISSING_CHANGE_TICKET"
            escalation_list.append({"activityId": act_id, "disposition": "ESCALATE", "raw_locator": raw_locator, "reason": reason})
            csv_rows.append([act_id, "ESCALATE", "NONE", raw_locator, reason])
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
        if status != "APPROVED":
            reasons.append(f"Invalid status ({status})")
        if approver != "change-board":
            reasons.append(f"Unapproved authority ({approver})")
        if not is_valid_asset(asset_id):
            reasons.append(f"Invalid asset ({asset_id})")
        if not is_valid_actor(actor):
            reasons.append(f"Unauthorized actor ({actor})")
        if owner not in valid_owners:
            reasons.append(f"Unauthorized owner ({owner})")
        if not starts_at or not ends_at:
            reasons.append("Missing timestamp")
        else:
            duration_sec = (ends_at - starts_at).total_seconds()
            if duration_sec <= 0 or duration_sec > 7200:
                reasons.append(f"Invalid duration ({duration_sec}s)")

        if not reasons:
            benign_list.append({
                "activityId": act_id,
                "changeId": change_id,
                "disposition": "BENIGN",
                "raw_locator": raw_locator,
                "reason": "Authorized Change Ticket"
            })
            csv_rows.append([act_id, "BENIGN", change_id, raw_locator, "Authorized Change Ticket"])
        else:
            combined_reason = " | ".join(reasons)
            escalation_list.append({
                "activityId": act_id,
                "changeId": change_id,
                "disposition": "ESCALATE",
                "raw_locator": raw_locator,
                "reason": combined_reason
            })
            csv_rows.append([act_id, "ESCALATE", change_id, raw_locator, combined_reason])

    os.makedirs("outputs", exist_ok=True)

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

    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(csv_rows)

    print("=" * 55)
    print(f"Total Candidates Analyzed : {len(candidates)}")
    print(f"Benign Matches (FP)       : {len(benign_list)} (Target: 80)")
    print(f"Escalated Incidents (TP)  : {len(escalation_list)} (Target: 16)")
    print("=" * 55)

if __name__ == "__main__":
    run_triage()
