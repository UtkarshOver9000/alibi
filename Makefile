# make dev | test | lint | fetch | snapshot | train
PY ?= python
export PYTHONPATH := src

dev:  ## run the API and dashboard at http://localhost:8000
	$(PY) -m uvicorn ittravel.api.app:app --reload --port 8000

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check . && $(PY) -m ruff format --check .

fetch:  ## download the feeds that are due (see sources.yaml)
	$(PY) -m ittravel.intel.fetch --raw data/intel

snapshot: fetch  ## rebuild src/ittravel/intel_data from the downloads
	$(PY) -m ittravel.intel.snapshot --raw data/intel

train:  ## retrain the 2026 network-risk model on ThreatFox data
	$(PY) -m ittravel.netrisk.train --threatfox data/intel/threatfox_full.json.zip

.PHONY: dev test lint fetch snapshot train
