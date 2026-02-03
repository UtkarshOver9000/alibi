# Impossible Travel Auth Anomaly Engine (Python-Only)

Detect logins that violate realistic travel time using geo-distance and time deltas. This project builds a full Python pipeline with data schema, synthetic generator, rules-based detection, and optional ML anomaly scoring.

## Problem Statement
Given user login events (timestamp + location), identify pairs of logins that imply impossible travel. The system should compute distance between locations, estimate required travel speed, and flag anomalies that exceed realistic thresholds.

## Repository Structure
- `src/ittravel/` core library
- `data/` generated datasets
- `models/` serialized thresholds or ML model
- `tests/` basic tests

## Quickstart (PowerShell)
```powershell
cd "C:\Users\utkarsh\OneDrive\Desktop\ML MODEL\impossible-travel"
$env:PYTHONPATH="src"
python -m ittravel.synthetic_data --out data/logins.csv --rows 50000
python -m ittravel.detect --data data/logins.csv --out data/anomalies.csv
```

## Schema (Core Columns)
See `src/ittravel/schema.py`.

Columns:
- `user_id`
- `login_ts` (ISO-8601)
- `lat`, `lon`
- `city`, `country`
- `device_id`, `ip`

Derived:
- `time_delta_hours`
- `distance_km`
- `required_speed_kmph`
- `is_impossible_travel`

## Notes
This baseline uses conservative thresholds. For real-world use:
- Tune speed thresholds per travel mode
- Add device/IP reputation signals
- Add account risk profile features

## License
MIT
