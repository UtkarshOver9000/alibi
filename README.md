# Impossible-Travel Auth Anomaly Engine

![CI](https://github.com/UtkarshOver9000/impossible-travel-auth-anomaly-engine/actions/workflows/ci.yml/badge.svg)

A login anomaly detector that flags suspicious authentication attempts in real time by combining an IsolationForest model with geo-velocity physics (Haversine distance over time). If a user logs in from Tokyo and then from London twenty minutes later, the implied travel speed is physically impossible — this engine catches that class of attack, along with device and subnet anomalies, and returns a 0–100 risk score.

Built as a solo project to explore anomaly detection for account security. The data is synthetic (real auth telemetry is private), but the full pipeline — feature extraction, model, API, and dashboard — runs end to end.

Live demo: https://impossible-travel-auth-anomaly-engi.vercel.app

## What it does

Given a login event, the engine returns a risk score and a human-readable reason:

```
POST /v1/auth/evaluate
{
  "user_id": "usr_9000",
  "login_ts": "2026-08-02T15:30:00Z",
  "lat": 35.6762,
  "lon": 139.6503,
  "city": "Tokyo",
  "country": "JP",
  "device_id": "dev-macbook-pro",
  "ip": "203.0.113.15"
}
```

→ a 0–100 risk score, a tier (LOW / MEDIUM / HIGH / CRITICAL), and the signals that drove it (e.g. "implied travel speed 4,200 km/h from previous login").

## How it works

The score is an ensemble of one learned signal and three deterministic ones:

- **IsolationForest (unsupervised)**: trained on the feature vectors of a user's normal login behavior; flags points that sit far from the learned distribution.
- **Geo-velocity check**: Haversine distance between consecutive logins ÷ time elapsed. Speeds above a plausible-travel threshold are strong impossible-travel signals.
- **Device entropy**: a login from a never-before-seen device raises risk.
- **Subnet jump heuristic**: sudden moves across unrelated IP subnets add risk.

These are combined into a single 0–100 score with a rationale string, so the output is explainable rather than a black box.

## Architecture

```
[ Login Attempt ] ──> [ FastAPI /v1/auth/evaluate ]
                             │
                      [ X-API-Key auth ]
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
      [ Per-user history store ]   [ IsolationForest engine ]
                │                         │
                └────────────┬────────────┘
                             ▼
              [ Ensemble risk scoring (0–100) ]
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
      [ Anomaly log ]            [ Web dashboard ]
```

## Run it locally

```bash
pip install -r requirements.txt
python -m uvicorn ittravel.api.app:app --reload --port 8000
```

- Dashboard: http://localhost:8000
- Interactive API docs (Swagger): http://localhost:8000/docs

Authenticated endpoints expect a header: `X-API-Key: <your-key>`.

## Run the tests

```bash
pytest --cov=src --cov-report=term-missing
```

19 tests, 87% line coverage. Lint with `ruff check .`. CI (`.github/workflows/ci.yml`) runs lint + tests + the evaluation benchmark below on Python 3.10–3.12 for every push and PR.

## Model performance

The engine has no real labeled incidents to validate against (see Limitations), so
`src/ittravel/evaluate.py` instead benchmarks it against `detect_impossible_travel()` —
a second, independently-implemented geo-velocity detector (pure pandas, no ML, no
device/subnet signals) — replayed chronologically over synthetic login sequences. This
tests whether the production engine's extra signals still agree with plain physics,
rather than just reproducing it.

Measured on 5,000 synthetic events / 400 users (`python -m ittravel.evaluate --rows 5000 --seed 11`):

| Metric | Score |
|---|---|
| Precision | 96.6% |
| Recall | 100.0% |
| F1 | 98.3% |
| Accuracy | 99.5% |

Recall of 100% means the ensemble never misses a reference-flagged impossible-travel
event in this benchmark; the precision cost comes from device/subnet signals correctly
flagging additional risk the pure-geometry reference doesn't see.

## Project layout

```
src/ittravel/
  api/                FastAPI app + auth
  ml_engine.py        production ensemble scoring engine (IsolationForest + heuristics)
  detect.py           offline geometric reference detector (pandas, no ML)
  evaluate.py         benchmarks ml_engine.py against detect.py
  geo.py              Haversine / velocity logic
  state.py            per-user login history
  schema.py           request/response models
  synthetic_data.py   data generator
  dashboard/          web UI (HTML/CSS/JS)
tests/                api, engine, detector, and evaluation tests
```

## Limitations & honest notes

- **Data is synthetic.** The generator produces realistic-looking login patterns, but the model has not been validated against real-world auth telemetry. Detection quality on real data is untested.
- **No real ground-truth incidents.** The precision/recall numbers above are against a second synthetic detector, not labeled real-world attacks — that's still the most important next step.
- **Thresholds are hand-tuned**, not learned from a validation set.
- **Single-node, in-memory history.** Not built for scale or persistence; it's a demonstration of the detection logic, not a deployment-ready service.

## Roadmap

- [x] Benchmark the engine and report precision / recall / F1 (against a synthetic reference detector — real labeled data is still needed)
- [x] Add CI (lint + tests + evaluation) on every push/PR
- [ ] Validate against real (or realistically labeled) auth incidents
- [ ] Replace hand-tuned thresholds with a validation-set sweep
- [ ] Add a short demo GIF to this README
- [ ] Persist login history (SQLite) instead of in-memory state

## License

MIT
