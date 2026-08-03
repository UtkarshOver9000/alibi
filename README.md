# 🛡️ AuraSentinel AI — Impossible Travel & Auth Anomaly SaaS Engine

                                                     Impossible-Travel Auth Anomaly Engine

A login anomaly detector that flags suspicious authentication attempts in real time by combining an IsolationForest model with geo-velocity physics (Haversine distance over time). If a user logs in from Tokyo and then from London twenty minutes later, the implied travel speed is physically impossible — this engine catches that class of attack, along with device and subnet anomalies, and returns a 0–100 risk score.

Built as a solo project to explore anomaly detection for account security. The data is synthetic (real auth telemetry is private), but the full pipeline — feature extraction, model, API, and dashboard — runs end to end.

Live demo: https://impossible-travel-auth-anomaly-engi.vercel.app

What it does

Given a login event, the engine returns a risk score and a human-readable reason:
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
→ a 0–100 risk score, a tier (LOW / MEDIUM / HIGH / CRITICAL), and the signals that drove it (e.g. "implied travel speed 4,200 km/h from previous login").

How it works

The score is an ensemble of one learned signal and three deterministic ones:

IsolationForest (unsupervised): trained on the feature vectors of a user's normal login behavior; flags points that sit far from the learned distribution.
Geo-velocity check: Haversine distance between consecutive logins ÷ time elapsed. Speeds above a plausible-travel threshold are strong impossible-travel signals.
Device entropy: a login from a never-before-seen device raises risk.
Subnet jump heuristic: sudden moves across unrelated IP subnets add risk.

These are combined into a single 0–100 score with a rationale string, so the output is explainable rather than a black box.

Architecture
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
      Run it locally
      pip install -r requirements.txt
python -m uvicorn ittravel.api.app:app --reload --port 8000
Dashboard: http://localhost:8000
Interactive API docs (Swagger): http://localhost:8000/docs

Authenticated endpoints expect a header: X-API-Key: <your-key>.

Run the tests
bash
pytest
Project layout
src/ittravel/
  api/            FastAPI app + auth
  ml_engine.py    IsolationForest model
  geo.py          Haversine / velocity logic
  detect.py       ensemble scoring
  state.py        per-user login history
  schema.py       request/response models
  synthetic_data.py  data generator
  dashboard/      web UI (HTML/CSS/JS)
tests/            api, engine, and basic tests
Limitations & honest notes
Data is synthetic. The generator produces realistic-looking login patterns, but the model has not been validated against real-world auth telemetry. Detection quality on real data is untested.
No labeled evaluation yet. There are no precision/recall numbers against a ground-truth set of known-malicious logins — that's the most important next step (see below).
Thresholds are hand-tuned, not learned from a validation set.
Single-node, in-memory history. Not built for scale or persistence; it's a demonstration of the detection logic, not a deployment-ready service.
Roadmap
 Add a small labeled evaluation set and report precision / recall / ROC-AUC.
 Replace hand-tuned thresholds with a validation-set sweep.
 Add a short demo GIF to this README.
 Persist login history (SQLite) instead of in-memory state.
License

MIT


  
