.PHONY: all clean build run test verify

# Force make to use the virtual environment binaries regardless of active terminal shell
VENV = venv
PYTHON = $(VENV)/bin/python3
PYTEST = $(VENV)/bin/pytest

all: clean build run test verify

clean:
	rm -rf outputs/* hunt_engine.duckdb .pytest_cache
	mkdir -p outputs

build:
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install duckdb pytest

run:
	$(PYTHON) hunt-engine/ingest.py
	$(PYTHON) hunt-engine/triage.py
	$(PYTHON) hunt-engine/campaigns.py

test:
	$(PYTEST) --junitxml=outputs/test-report.xml tests/

verify:
	sha256sum outputs/* assessment-manifest.json evidence-index.csv integrity-attestation.md continuity-record.md README.md DOCUMENTATION.md > manifest.sha256
	cat manifest.sha256
