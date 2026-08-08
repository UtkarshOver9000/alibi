"""
Unit tests for FastAPI REST Endpoints & Authentication.
"""

from fastapi.testclient import TestClient

from ittravel.api.app import app

client = TestClient(app)
API_KEY = "demo-master-key-9000"


def test_api_auth_required():
    res = client.post("/v1/auth/evaluate", json={})
    assert res.status_code == 401


def test_api_invalid_key():
    res = client.post("/v1/auth/evaluate", headers={"X-API-Key": "invalid_key"}, json={})
    assert res.status_code == 403


def test_api_evaluate_success():
    payload = {
        "user_id": "api_usr_10",
        "login_ts": "2026-08-02T15:00:00Z",
        "lat": 40.7128,
        "lon": -74.0060,
        "city": "New York",
        "country": "US",
        "device_id": "dev-mac",
        "ip": "198.51.100.22",
    }
    res = client.post("/v1/auth/evaluate", headers={"X-API-Key": API_KEY}, json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["user_id"] == "api_usr_10"
    assert "risk_score" in data


def test_api_generate_key():
    res = client.post("/v1/keys/generate", json={"name": "Test Key"})
    assert res.status_code == 200
    data = res.json()
    assert "api_key" in data
    assert data["api_key"].startswith("sk_live_")


def test_api_stats():
    res = client.get("/v1/stats", headers={"X-API-Key": API_KEY})
    assert res.status_code == 200
    data = res.json()
    assert data["engine_status"] == "ONLINE"


def test_api_anomalies_requires_auth():
    res = client.get("/v1/anomalies")
    assert res.status_code == 401


def test_api_anomalies_returns_list():
    res = client.get("/v1/anomalies", headers={"X-API-Key": API_KEY})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_api_health_check():
    res = client.get("/v1/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_api_dashboard_root_served():
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
