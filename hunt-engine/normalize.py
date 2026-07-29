import json
from datetime import datetime, timedelta

# Planted Endpoint Clock Drift Offset: 3,900 Seconds (65 Minutes Fast)
ENDPOINT_CLOCK_DRIFT_SECONDS = 3900

def parse_iso_timestamp(ts_str):
    """Parses ISO timestamp strings into standard datetime objects."""
    try:
        clean_str = str(ts_str).replace("Z", "+00:00")
        return datetime.fromisoformat(clean_str)
    except Exception:
        return None

def canonicalize_identity(identity_str):
    """Maps raw identity aliases to unified canonical identities."""
    if not identity_str:
        return "unknown.user"
    id_lower = str(identity_str).lower()
    if "amina" in id_lower:
        return "amina.analyst"
    if "nora" in id_lower or "contractor" in id_lower:
        return "nora.contractor"
    return identity_str

def normalize_record(raw_line, line_number, source_file="auth.v1.json"):
    """
    Parses a raw log line, applies -3,900s clock drift correction for EDR logs,
    resolves identity aliases, and generates an explicit raw_locator (file:line).
    """
    raw_locator = f"{source_file}:{line_number}"
    
    try:
        data = json.loads(raw_line) if isinstance(raw_line, str) else raw_line
        source_type = data.get("source_type") or source_file.split(".")[0]

        # Extract timestamp across schema versions (Schema Drift)
        ts_raw = data.get("timestamp") or data.get("event_time") or data.get("time")
        if not ts_raw and isinstance(data.get("record"), dict):
            ts_raw = data["record"].get("time") or data["record"].get("timestamp")

        dt = parse_iso_timestamp(ts_raw)
        if not dt:
            quarantine_tuple = (source_file, line_number, str(raw_line), "MISSING_OR_INVALID_TIMESTAMP", raw_locator)
            return None, quarantine_tuple

        # Apply -3,900s (-65 min) clock drift correction for Endpoint / EDR logs
        if source_type in ("edr", "endpoint"):
            dt = dt - timedelta(seconds=ENDPOINT_CLOCK_DRIFT_SECONDS)

        # Canonicalize Identity
        raw_identity = data.get("identity") or data.get("username")
        if not raw_identity and isinstance(data.get("record"), dict):
            raw_identity = data["record"].get("username")
        
        identity = canonicalize_identity(raw_identity)
        asset_id = data.get("asset_id") or data.get("host") or "unknown-host"
        action = data.get("action") or data.get("event_action") or data.get("result") or "activity"

        normalized = {
            "event_id": f"EVT-{source_type.upper()}-{line_number}",
            "event_time": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "source_type": source_type,
            "identity": identity,
            "asset_id": str(asset_id),
            "event_action": str(action),
            "raw_locator": raw_locator
        }
        return normalized, None

    except Exception as e:
        quarantine_tuple = (source_file, line_number, str(raw_line), f"PARSE_ERROR: {str(e)}", raw_locator)
        return None, quarantine_tuple
