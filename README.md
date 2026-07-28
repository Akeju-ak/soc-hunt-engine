# UBI Stage 5 SOC Hunt Engine

**Intern Code**: UBI-2026-0083
**Variant**: D5                         
**Evidence Marker**: UBI-A5-74780BE0F17F                           
**Repository URL**: https://github.com/Akeju-ak/soc-hunt-engine.git

---

## Clean-Build & Execution Protocol

To execute a clean build from scratch in an isolated environment, run the following commands in order:

```bash                                   
# 1. Initialize Python Virtual Environment
python3 -m venv venv    
source venv/bin/activate

# 2. Install Dependencies
pip install --upgrade pip
pip install duckdb pytest

# 3. Step 1: Ingest Raw Telemetry into DuckDB
python3 hunt-engine/ingest.py

# 4. Step 2: Run 7-Point Compliance Alert Triage Engine
python3 hunt-engine/triage.py

# 5. Step 3: Reconstruct Multi-Source Threat Campaigns
python3 hunt-engine/campaigns.py

# 6. Step 4: Run Automated Verification Test Suite
python3 -m pytest tests/

EOC
