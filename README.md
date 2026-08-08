# 🛡️ AuraSentinel AI — Impossible Travel & Auth Anomaly SaaS Engine

A production-grade **AI-Powered Authentication Anomaly Detection SaaS** that evaluates login attempts in real time using an **IsolationForest ML Ensemble** and **Haversine Geo-Physics**.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-IsolationForest-orange)
![CI](https://github.com/UtkarshOver9000/impossible-travel-auth-anomaly-engine/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/Tests-19%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-87%25-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## ✨ Features

- **🧠 Ensemble AI Model**: Combines unsupervised `IsolationForest` machine learning with velocity physics, device entropy, and subnet jump heuristics.
- **🚀 Real-Time FastAPI Engine**: High-throughput REST backend to evaluate authentication events with low latency (<10ms).
- **🔑 API Key Security**: Header-based `X-API-Key` authorization with tenant management.
- **🖥️ Interactive SaaS Web Dashboard**: Dark-mode glassmorphism interface featuring live threat simulation, risk score gauges, audit telemetry, and API key provisioning.
- **📊 Detailed Risk Scoring (0–100)**: Categorizes threats into `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` risk tiers with human-readable rationale explanations.

---

## 🏗️ Architecture

```
[ Login Attempt ] ──> [ FastAPI Endpoint (/v1/auth/evaluate) ]
                             │
                      [ X-API-Key Auth ]
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
      [ State History Store ]   [ IsolationForest ML Engine ]
                │                         │
                └────────────┬────────────┘
                             ▼
              [ Ensemble Risk Scoring (0-100) ]
                             │
                ┌────────────┴────────────┐
                ▼                         ▼
      [ Anomaly Log Store ]      [ Web Dashboard UI ]
```

---

## ⚡ Quickstart & Local SaaS Deployment

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch FastAPI SaaS Server & Web Dashboard
```bash
python -m uvicorn ittravel.api.app:app --reload --port 8000
```
- **Web Dashboard**: Open [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger API Docs**: Open [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🔌 API Reference

### 1. Evaluate Login Attempt (`POST /v1/auth/evaluate`)
**Headers**: `X-API-Key: demo-master-key-9000`

**Request**:
```json
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

**Response**:
```json
{
  "user_id": "usr_9000",
  "is_anomaly": true,
  "risk_score": 92.5,
  "risk_tier": "CRITICAL",
  "reasons": [
    "Impossible physical travel velocity (12480.2 km/h > 900 km/h)",
    "Unrecognized device fingerprint (dev-macbook-pro)"
  ],
  "velocity_kmph": 12480.2,
  "distance_km": 10850.1,
  "time_delta_hours": 0.869,
  "previous_location": { "city": "New York", "country": "US", "lat": 40.7128, "lon": -74.0060 },
  "current_location": { "city": "Tokyo", "country": "JP", "lat": 35.6762, "lon": 139.6503 }
}
```

### 2. Generate API Key (`POST /v1/keys/generate`)
```json
{
  "name": "Production Gateway Key"
}
```

---

## 📊 Model Performance

`src/ittravel/evaluate.py` measures the production ensemble (IsolationForest + heuristics)
against `detect_impossible_travel()` — an independently-implemented, vectorized
geo-velocity reference detector — replayed chronologically over synthetic login
sequences. This checks whether the real-time engine's added signals (device
fingerprinting, IP subnet changes, ML scoring) still agree with ground-truth
physics, not just reproduce it.

Measured on 5,000 synthetic events / 400 users (`python -m ittravel.evaluate --rows 5000 --seed 11`):

| Metric | Score |
|---|---|
| Precision | 96.6% |
| Recall | 100.0% |
| F1 Score | 98.3% |
| Accuracy | 99.5% |

Recall of 100% means the ensemble never misses a reference-labeled impossible-travel
event in this benchmark; the ~3.4% precision cost comes from device/subnet signals
correctly flagging additional risk the pure-geometry reference doesn't see (e.g. a new
device from a nearby but still-anomalous subnet).

```bash
python -m ittravel.evaluate --rows 5000 --seed 11
```

---

## 🧪 Run Automated Tests
```bash
pip install -r requirements.txt
pytest --cov=src --cov-report=term-missing
```
19 unit tests (87% line coverage) cover ML engine scoring, state tracking, edge-case
velocities, the offline reference detector, the evaluation harness, and API
authentication/endpoints. Lint with `ruff check .`. CI (`.github/workflows/ci.yml`)
runs lint + tests + the evaluation harness on Python 3.10–3.12 for every push and PR.
