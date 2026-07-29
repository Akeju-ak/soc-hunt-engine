# Production SOC Hunt Engine — Technical Documentation & Analysis Report

**Intern Analyst**: `UBI-2026-0083`  
**Stage/Track**: Stage 5 SOC Advanced 1 — Signal | TRAN  
**Evidence Marker**: `UBI-A5-74780BE0F17F`

---

## 1. Project Executive Summary

Modern Security Operations Centers (SOCs) ingest millions of log records daily across disparate security controls[cite: 11, 12, 14]. Raw security telemetry suffers from formatting inconsistencies (**schema drift**), system timing errors (**clock skew**), and duplicate entries caused by network retransmissions [cite: 15, 343-351].

This project implements an automated, high-throughput **Production Threat Hunt Engine** using **Python** and **DuckDB** [cite: 14, 22, 338-341]. The engine executes three primary operational functions:
1. **Data Normalization & Ingestion**: Normalizes heterogeneous log formats across 5 security sources into unified database tables (`norm.events` and `raw.quarantine`) [cite: 14, 24, 204-205].
2. **Alert Triage & Change Verification**: Evaluates 96 suspicious activity candidates against corporate change management records, isolating **80 benign false positives** from **16 unauthorized security policy violations** [cite: 16-19, 233-234, 276].
3. **Multi-Source Threat Campaign Correlation**: Reconstructs 3 complex, multi-stage cyberattack campaigns across a unified UTC timeline [cite: 20, 278-286].

---

## 2. System Architecture & Ingestion Pipeline

The hunt engine relies on DuckDB—an embedded, high-performance columnar database—to perform rapid SQL analytical queries on structured and semi-structured log data [cite: 22, 340-341].
Raw Telemetry Sources                   DuckDB Normalization Engine               Database Models
[ Auth Logs (V1/V2/V3) ] ──┐
[ Web Server Logs      ] ──┼─► [ Python Normalization Adapters ] ──► norm.events (Clean Unified Table)
[ DNS Query Logs       ] ──┤              (normalize.py)           └──► raw.quarantine (Malformed/Corrupt Rows)
[ Network Firewall     ] ──┤
[ Endpoint / EDR Logs  ] ──┘

### 2.1 The 5 Security Log Telemetry Sources
- **Auth (Authentication)**: Tracks sign-in attempts, service logins, and credential usage [cite: 14, 329-330].
- **Web**: Tracks HTTP request methods, URIs, user agents, and file download requests [cite: 14, 331-332].
- **DNS**: Records domain name resolution requests mapped to internal asset IP addresses[cite: 14, 333].
- **Firewall**: Captures network traffic flows, ingress/egress connections, and port blocks [cite: 14, 334-335].
- **Endpoint / EDR**: Monitors process creation, command-line arguments, and local host file modifications [cite: 14, 336-337].

### 2.2 Data Quality & Hygiene Issues Handled
1. **Schema Drift**: Legacy and modern versions of logging software store user identity and timestamps under different key names (e.g., `username` vs. `identity` or `timestamp` vs. `event_time`) [cite: 23, 343-345]. Normalization adapters resolve schema drift into standardized database columns[cite: 14, 15, 345].
2. **Malformed Data Quarantine**: Rows with unparseable JSON or missing mandatory fields are safely routed into `raw.quarantine` with explicit reason codes[cite: 24, 46].
3. **Clock Skew & Timeline Unification**: Event timestamps are parsed into standardized UTC timestamps (`NS` precision) to preserve absolute chronological ordering across out-of-sync system clocks [cite: 20, 25, 348-351].

---

## 3. Alert Triage Engine (The 96 Review Candidates)

To prevent SOC alert fatigue, the triage engine cross-references suspicious activity alerts (`reviewCandidates`) against corporate IT maintenance tickets (`changeRecords`)[cite: 16, 17, 49].

### 3.1 Strict 7-Point Compliance Validation Rules
An alert candidate is classified as **BENIGN** if and only if **all 7 conditions** reconcile perfectly against an official change ticket [cite: 18, 27, 266-272]:
1. **Activity Binding**: The `activityId` exists within the corporate change record registry[cite: 27, 242].
2. **Approval Authority**: Ticket approval authority must strictly be `change-board`[cite: 27, 50, 245].
3. **Status Code**: Ticket status must strictly be `APPROVED` (not `PENDING`, `DRAFT`, or `EXPIRED`)[cite: 19, 27, 50, 246].
4. **Asset Scope**: Target host must be a valid internal machine (`asset-001` through `asset-050`; `asset-999` indicates an unmapped/invalid machine) [cite: 19, 27, 267-268].
5. **Actor Authorization**: Executing account must be an authorized service account (`svc-001` through `svc-050`) [cite: 19, 27, 267-268].
6. **Departmental Ownership**: Operating unit must belong to `Security Engineering`, `Platform`, `Data Services`, or `IT Operations` [cite: 269-270].
7. **Time Window Covering**: The event timestamp must fall between `startsAt` and `endsAt` with a valid, non-zero duration ($\le$ 2 hours) [cite: 27, 51, 271-272].

### 3.2 Triage Execution Results
- **Total Candidates Analyzed**: `96` [cite: 16]
- **Benign Matches (False Positives)**: `80` (Authorized maintenance tasks) [cite: 18, 276]
- **Escalated Incidents (True Positives)**: `16` (Unauthorized policy violations & suspicious activity) [cite: 19, 276]

---

## 4. Reconstructed Threat Campaigns

By correlating normalized events across Auth, Web, DNS, Firewall, and EDR logs on a unified UTC timeline, the hunt engine reconstructed three distinct attacker campaign storylines [cite: 20, 278-286]:

### Campaign 1: Credential Stuffing & Lateral Movement
- **Vector**: Auth & EDR Telemetry [cite: 284]
- **Actor**: `user-external-attacker`
- **Impact**: Attacker executed password spraying against `asset-003`, gained access, and launched obfuscated PowerShell execution commands[cite: 284].

### Campaign 2: Malicious Web Ingress & C2 Exfiltration
- **Vector**: Web, DNS, and Firewall Telemetry [cite: 284]
- **Actor**: `svc-019`
- **Impact**: Compromised service account downloaded a malicious payload over HTTP, attempted domain resolution for a Command-and-Control (C2) server, and triggered network egress blocks at the firewall[cite: 284].

### Campaign 3: Privilege Escalation & Persistence
- **Vector**: EDR, Auth, and Firewall Logs [cite: 284]
- **Actor**: `admin-compromised`
- **Impact**: Local credential dumping via LSASS process access on `asset-001`, creation of scheduled persistence tasks, and unauthorized attempts to clear audit logs[cite: 284].

---

## 5. Verification & Submission Artifacts

Every output file has been programmatically generated and verified via automated testing[cite: 99, 100, 305]:
- `outputs/triage_results.json` — Structured JSON triage output listing the 80 benign items and 16 escalations[cite: 76, 77, 93, 100].
- `outputs/tp-fp-table.csv` — CSV decision matrix mapping candidate activity IDs to disposition reasons [cite: 110, 277-278].
- `outputs/normalized-timeline.csv` — Unified chronological event timeline[cite: 111, 285, 301].
- `outputs/campaign-graph.json` — Threat graph detailing the 3 reconstructed attack storylines[cite: 112, 286, 301].
- `outputs/benchmark.json` — Performance execution benchmarks proving sub-minute pipeline execution[cite: 114, 307].
- `manifest.sha256` — Cryptographic SHA-256 integrity hashes for all submission deliverables[cite: 119, 312].

EOF
