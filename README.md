# 🛡️ AuraSentinel AI — Impossible Travel & Auth Anomaly SaaS Engine

A production-grade **AI-Powered Authentication Anomaly Detection SaaS** that evaluates login attempts in real time using an **IsolationForest ML Ensemble** and **Haversine Geo-Physics**.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-IsolationForest-orange)
![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen)

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

## 🧪 Run Automated Tests
```bash
python -m pytest
```
All 9 unit tests cover ML engine scoring, state tracking, edge-case velocities, and API authentication.
