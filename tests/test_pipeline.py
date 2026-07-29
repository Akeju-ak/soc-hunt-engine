import os
import sys
import json
import pytest

sys.path.append(os.path.abspath("hunt-engine"))

from triage import run_triage
from campaigns import reconstruct_campaigns

def test_triage_counts():
    """Verifies that the triage engine evaluates 96 candidates into 80 Benign / 16 Escalated."""
    run_triage()
    assert os.path.exists("outputs/triage_results.json")
    assert os.path.exists("outputs/tp-fp-table.csv")
    
    with open("outputs/triage_results.json", "r") as f:
        data = json.load(f)
        
    assert data["summary"]["total_evaluated"] == 96
    assert data["summary"]["benign_count"] == 80
    assert data["summary"]["escalated_count"] == 16

def test_campaign_reconstruction():
    """Verifies campaign reconstruction and locator presence."""
    reconstruct_campaigns()
    assert os.path.exists("outputs/normalized-timeline.csv")
    assert os.path.exists("outputs/campaign-graph.json")
    
    with open("outputs/campaign-graph.json", "r") as f:
        data = json.load(f)
        
    assert data["campaign_count"] == 3
