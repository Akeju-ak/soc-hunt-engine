import json
from datetime import datetime

def parse_auth_event(raw_record, source_file="auth.json"):
    """
    Standardizes Auth log schema versions (V1, V2, V3) into norm.events.
    Returns (normalized_dict, quarantine_tuple)
    """
    try:
        data = json.loads(raw_record) if isinstance(raw_record, str) else raw_record
        version = str(data.get("schema_version", "1"))
        
        event_id = data.get("event_id", f"AUTH-{hash(str(data))}")
        
        if version == "1":
            event_time = data.get("timestamp")
            identity = data.get("username")
            action = data.get("action")
        elif version == "2":
            event_time = data.get("event_time")
            identity = data.get("identity")
            action = data.get("result")
        elif version == "3":
            event_time = data.get("time")
            rec = data.get("record", {})
            identity = rec.get("username")
            action = rec.get("action")
        else:
            return None, (source_file, str(raw_record), "UNSUPPORTED_SCHEMA_VERSION")

        # Validate mandatory fields
        if not event_time or not identity or not action:
            return None, (source_file, str(raw_record), "MISSING_MANDATORY_FIELDS")

        normalized = {
            "event_id": str(event_id),
            "event_time": event_time,
            "source_type": "auth",
            "identity": str(identity),
            "asset_id": data.get("asset_id", "unknown-host"),
            "event_action": str(action),
            "raw_locator": f"{source_file}:{event_id}"
        }
        return normalized, None

    except Exception as e:
        return None, (source_file, str(raw_record), f"PARSE_FAILURE: {str(e)}")


if __name__ == "__main__":
    # Test fixture normalization
    sample_v1 = '{"schema_version": "1", "timestamp": "2026-07-22T10:00:00Z", "username": "alice", "action": "login_success"}'
    sample_corrupt = '{"schema_version": "1", "timestamp": "invalid"}'

    norm_event, err = parse_auth_event(sample_v1)
    print("✓ Test V1 Normalization Output:", norm_event)

    corrupt_event, err = parse_auth_event(sample_corrupt)
    print("✓ Test Corrupt Record Routing:", err)
