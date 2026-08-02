"""
FastAPI SaaS REST API for AI-Powered Authentication Anomaly Detection.
"""

from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, Depends, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from ..schema import LoginEvent, EvaluationResult, APIKeyCreate, APIKeyResponse
from ..ml_engine import engine
from ..state import store
from .auth import verify_api_key

app = FastAPI(
    title="Impossible Travel & Auth Anomaly AI SaaS",
    description="Production-grade AI Authentication Security API powered by IsolationForest & Geo-Physics",
    version="2.0.0",
)

# Dashboard directory path
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("<h1>AI Auth Anomaly SaaS Backend Running</h1><p>Visit <a href='/docs'>/docs</a> for API documentation.</p>")


@app.post("/v1/auth/evaluate", response_model=EvaluationResult, summary="Evaluate Login Attempt")
async def evaluate_login(
    event: LoginEvent,
    _auth: str = Depends(verify_api_key),
):
    """
    Real-time AI evaluation of an authentication attempt.
    Calculates velocity, distance, device entropy, and ML anomaly risk score.
    """
    return engine.evaluate_event(event)


@app.get("/v1/anomalies", summary="Get Logged Anomaly Alerts")
async def get_anomalies(
    limit: int = Query(50, ge=1, le=200),
    _auth: str = Depends(verify_api_key),
):
    """Fetch recent high-risk anomaly alerts."""
    return store.get_anomalies(limit)


@app.post("/v1/keys/generate", response_model=APIKeyResponse, summary="Generate Client API Key")
async def generate_key(req: APIKeyCreate):
    """Generate a new tenant API key for API integration."""
    return store.create_api_key(req.name)


@app.get("/v1/stats", summary="SaaS Security Telemetry")
async def get_telemetry(_auth: str = Depends(verify_api_key)):
    """Retrieve security telemetry metrics for SaaS dashboard."""
    anomalies = store.get_anomalies(200)
    total_anomalies = len(anomalies)
    critical_count = sum(1 for a in anomalies if a.get("risk_tier") == "CRITICAL")
    high_count = sum(1 for a in anomalies if a.get("risk_tier") == "HIGH")
    
    return {
        "active_monitored_users": len(store.users),
        "total_anomalies_detected": total_anomalies,
        "critical_threats": critical_count,
        "high_threats": high_count,
        "engine_status": "ONLINE",
        "model_version": "IsolationForest-Ensemble-v2.0",
    }
