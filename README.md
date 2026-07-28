# SOC Hunt Engine — Multi-Source Threat Detection Pipeline

A production-style Security Operations Center (SOC) pipeline built in **Python** and **DuckDB** that normalizes multi-source security telemetry, triages suspicious activity against change-management records, and reconstructs multi-stage attack campaigns on a unified timeline.


---

## Why this exists

SOCs don't get clean data. The same field shows up under different names across log versions (schema drift), clocks drift out of sync across systems, and duplicate events show up from network retransmissions. This project treats that as the actual problem to solve — before any detection rule gets written — by building a pipeline that ingests, normalizes, validates, and correlates raw telemetry into something a human analyst can actually investigate.

## What it does

The pipeline runs in three stages:

### 1. Ingestion & Normalization (`hunt-engine/ingest.py`, `hunt-engine/normalize.py`)
Loads security events from 5 telemetry sources — **Auth, Web, DNS, Firewall, and EDR** — into a unified DuckDB schema (`norm.events`). The auth normalizer specifically handles 3 different schema versions (differing field names for timestamp, identity, and action), and any record that's unparseable or missing mandatory fields is routed to `raw.quarantine` with a reason code instead of being dropped silently.

### 2. Alert Triage (`hunt-engine/triage.py`)
Cross-references 96 flagged activity candidates against corporate change-management tickets using a strict **7-point compliance check**:

| # | Check | Requirement |
|---|-------|-------------|
| 1 | Ticket existence | `activityId` must have a matching change record |
| 2 | Status | Must be `APPROVED` |
| 3 | Approval authority | Must be `change-board` |
| 4 | Asset scope | Must be `asset-001`–`asset-050` |
| 5 | Actor authorization | Must be `svc-001`–`svc-050` |
| 6 | Department ownership | Security Engineering, Platform, Data Services, or IT Operations |
| 7 | Time window | Event must fall within ticket window, duration ≤ 2 hours |

An activity is only cleared as benign if **all 7 checks** pass. Result: **80 confirmed false positives**, **16 escalated as unauthorized incidents**.

### 3. Campaign Reconstruction (`hunt-engine/campaigns.py`)
Correlates normalized events across all 5 sources on a single UTC timeline to identify full attack storylines rather than isolated alerts. Three campaigns were reconstructed:

- **Credential Stuffing & Lateral Movement** — failed login burst → successful login → obfuscated PowerShell execution
- **Malicious Web Payload & C2** — HTTP file download → C2 domain lookup → firewall egress block
- **Privilege Escalation & Persistence** — LSASS credential dump → scheduled task creation → audit log clear attempt

## Architecture

```
Raw Telemetry (Auth / Web / DNS / Firewall / EDR)
            │
            ▼
   normalize.py  ──►  norm.events (clean)
                  ──►  raw.quarantine (malformed/invalid)
            │
            ▼
   triage.py  ──►  outputs/triage_results.json
              ──►  outputs/tp-fp-table.csv
            │
            ▼
   campaigns.py  ──►  outputs/normalized-timeline.csv
                 ──►  outputs/campaign-graph.json
```

## Project structure

```
.
├── hunt-engine/
│   ├── ingest.py        # Loads events into DuckDB
│   ├── normalize.py     # Schema-drift normalization + quarantine logic
│   ├── triage.py         # 7-point compliance triage engine
│   └── campaigns.py      # Cross-source campaign correlation
├── queries/
│   └── schema.sql        # DuckDB table definitions
├── data/
│   └── ubi-2026-0083-stage-5-discrepancy.json   # Alert candidates + change records
├── outputs/
│   ├── triage_results.json
│   ├── tp-fp-table.csv
│   ├── normalized-timeline.csv
│   └── campaign-graph.json
├── tests/
│   └── test_pipeline.py  # Automated verification of triage + campaign counts
├── evidence-index.csv
├── manifest.sha256       # Integrity hashes for all deliverables
└── README.md
```

## Getting started

**Requirements:** Python 3.10+, pip

```bash
# 1. Clone the repo
git clone https://github.com/Akeju-ak/soc-hunt-engine.git
cd soc-hunt-engine

# 2. Set up a virtual environment
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install --upgrade pip
pip install duckdb pytest

# 4. Run the pipeline
python3 hunt-engine/ingest.py       # Ingest & normalize telemetry
python3 hunt-engine/triage.py       # Run the 7-point triage engine
python3 hunt-engine/campaigns.py    # Reconstruct threat campaigns

# 5. Verify everything with the automated test suite
python3 -m pytest tests/
```

## Verification & integrity

- `tests/test_pipeline.py` asserts the exact triage counts (96 evaluated, 80 benign, 16 escalated) and campaign count (3), so any regression in the logic fails the build immediately.
- `manifest.sha256` contains SHA-256 hashes of every deliverable file for integrity verification.
- All outputs are generated programmatically from `data/ubi-2026-0083-stage-5-discrepancy.json` — nothing in `outputs/` is hand-edited.

## Tech stack

Python · DuckDB · pytest · JSON/CSV structured data · MITRE ATT&CK-aligned campaign mapping

## License

Add a license of your choice (e.g. MIT) if you intend this repo to be public and reusable.
