import os

from fastapi.testclient import TestClient

from ittravel.api.app import app

client = TestClient(app)
KEY = {"X-API-Key": os.environ["ALIBI_API_KEY"]}
EVENT = {
    "user_id": "api-user",
    "login_ts": "2026-08-03T09:00:00Z",
    "ip": "84.208.20.10",
    "device_id": "dev-laptop",
    "country": "NO",
    "asn": 29695,
}


def test_health_and_dashboard():
    health = client.get("/v1/health").json()
    assert health["status"] in ("ok", "degraded") and health["snapshot"]
    for feed in health["feeds"]:
        assert {"id", "name", "status", "last_success", "age_hours", "records"} <= feed.keys()
        assert feed["name"]  # the header names a late feed in words, not by its id
    assert "Alibi" in client.get("/").text


def test_evaluate_requires_a_key():
    assert client.post("/v1/auth/evaluate", json=EVENT).status_code == 401
    assert client.post("/v1/auth/evaluate", json=EVENT, headers={"X-API-Key": "nope"}).status_code == 403


def test_evaluate_returns_model_scores():
    res = client.post("/v1/auth/evaluate", json=EVENT, headers=KEY)
    assert res.status_code == 200
    data = res.json()
    assert data["risk_tier"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert 0 <= data["risk_score"] <= 100
    assert 0 <= data["ato_probability"] <= 1 and 0 <= data["attack_ip_probability"] <= 1
    assert data["recommended_action"]


def test_validation_rejects_bad_input():
    bad = {**EVENT, "rtt_ms": -5}
    assert client.post("/v1/auth/evaluate", json=bad, headers=KEY).status_code == 422


def test_issuing_keys_requires_the_master_key():
    res = client.post("/v1/keys/generate", json={"name": "svc"}, headers=KEY)
    assert res.status_code == 200
    issued = res.json()["api_key"]
    assert issued.startswith("alibi_")
    # an issued key can evaluate, but cannot mint more keys
    assert (
        client.post("/v1/auth/evaluate", json={**EVENT, "user_id": "k"}, headers={"X-API-Key": issued}).status_code
        == 200
    )
    assert client.post("/v1/keys/generate", json={"name": "x"}, headers={"X-API-Key": issued}).status_code == 403
    assert client.post("/v1/keys/generate", json={"name": "x"}).status_code == 401


def test_model_card_endpoint():
    card = client.get("/v1/model").json()
    assert set(card["test_metrics"]) == {"ato", "attack_ip"}
    for metrics in card["test_metrics"].values():
        for key in ("roc_auc", "pr_auc", "precision", "recall", "log_loss", "confusion_matrix"):
            assert key in metrics
    assert card["dataset"]["logins"] > 30_000_000


def test_anomaly_log_and_stats():
    client.post("/v1/auth/evaluate", json={**EVENT, "user_id": "t", "lat": 40.71, "lon": -74.0}, headers=KEY)
    client.post(
        "/v1/auth/evaluate",
        json={
            **EVENT,
            "user_id": "t",
            "login_ts": "2026-08-03T09:05:00Z",
            "lat": 35.67,
            "lon": 139.65,
            "country": "JP",
        },
        headers=KEY,
    )
    logs = client.get("/v1/anomalies", headers=KEY).json()
    assert any(a["user_id"] == "t" for a in logs)
    assert client.get("/v1/stats", headers=KEY).json()["users_seen_by_this_instance"] >= 1


def test_keyed_endpoints_are_off_without_a_server_key(monkeypatch):
    monkeypatch.delenv("ALIBI_API_KEY")
    assert client.post("/v1/auth/evaluate", json=EVENT, headers=KEY).status_code == 503


def test_demo_endpoint_is_rate_limited_per_ip(monkeypatch):
    monkeypatch.setenv("ALIBI_TRUSTED_PROXY_HOPS", "1")
    ip = {"X-Forwarded-For": "198.51.100.77"}
    codes = [client.post("/v1/demo/check", json={}, headers=ip).status_code for _ in range(21)]
    assert codes[:20] == [422] * 20 and codes[20] == 429
    other = client.post("/v1/demo/check", json={}, headers={"X-Forwarded-For": "198.51.100.78"})
    assert other.status_code == 422


def test_demo_checks_are_sandboxed(monkeypatch):
    """A keyless demo keeps nothing and cannot change how a real login from the same IP is scored."""
    from ittravel.engine import get_engine

    monkeypatch.setenv("ALIBI_TRUSTED_PROXY_HOPS", "1")

    engine = get_engine()
    kept = (len(engine.store.users), len(engine.ip_history), len(engine.store.anomaly_logs))
    guesses = [
        {**EVENT, "user_id": "x", "ip": "203.0.113.9", "success": False, "login_ts": f"2026-08-03T09:{m:02d}:00Z"}
        for m in range(20)
    ]
    demo = client.post("/v1/demo/check", json={"events": guesses}, headers={"X-Forwarded-For": "198.51.100.90"})
    assert demo.status_code == 200
    assert (len(engine.store.users), len(engine.ip_history), len(engine.store.anomaly_logs)) == kept
    real = {**EVENT, "user_id": "sandbox-check", "ip": "203.0.113.9", "login_ts": "2026-08-03T09:30:00Z"}
    feats = client.post("/v1/auth/evaluate", json=real, headers=KEY).json()["features"]
    assert feats["ip_attempts_1h"] == 0 and feats["ip_failures_1h"] == 0


def test_forwarded_for_is_trusted_only_behind_a_proxy(monkeypatch):
    from starlette.requests import Request

    from ittravel.api.ratelimit import client_ip

    def ip(forwarded: str) -> str:
        scope = {"type": "http", "headers": [(b"x-forwarded-for", forwarded.encode())], "client": ("10.0.0.5", 4321)}
        return client_ip(Request(scope))

    monkeypatch.delenv("ALIBI_TRUSTED_PROXY_HOPS", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    assert ip("198.51.100.1") == "10.0.0.5"  # no proxy: a client can't choose its own bucket
    monkeypatch.setenv("ALIBI_TRUSTED_PROXY_HOPS", "1")
    assert ip("1.2.3.4, 198.51.100.2") == "198.51.100.2"  # what our proxy saw, not what the client wrote
    monkeypatch.setenv("ALIBI_TRUSTED_PROXY_HOPS", "2")
    assert ip("1.2.3.4, 198.51.100.3, 10.0.0.9") == "198.51.100.3"
    assert ip("198.51.100.4") == "10.0.0.5"  # fewer entries than proxies: the header can't be trusted
    monkeypatch.delenv("ALIBI_TRUSTED_PROXY_HOPS")
    monkeypatch.setenv("VERCEL", "1")
    assert ip("198.51.100.5") == "198.51.100.5"


def test_security_headers():
    page = client.get("/")
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    api = client.get("/v1/health")
    assert api.headers["x-content-type-options"] == "nosniff" and "max-age" in api.headers["strict-transport-security"]


def test_cors_allows_only_known_headers():
    ok = client.options(
        "/v1/intel/overview",
        headers={
            "Origin": "https://example.org",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-API-Key",
        },
    )
    assert ok.status_code == 200 and "x-api-key" in ok.headers["access-control-allow-headers"].lower()
    bad = client.options(
        "/v1/intel/overview",
        headers={
            "Origin": "https://example.org",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-Evil",
        },
    )
    assert bad.status_code == 400


def test_security_txt():
    txt = client.get("/.well-known/security.txt").text
    assert txt.startswith("Contact: https://") and "Expires: 2027-" in txt


def test_read_endpoints_are_cacheable_and_health_is_not():
    assert "s-maxage" in client.get("/v1/intel/overview").headers["cache-control"]
    assert client.get("/v1/health").headers["cache-control"] == "no-store"


def test_request_ids_are_echoed_or_made():
    assert (
        client.get("/v1/health", headers={"X-Request-ID": "trace-12345678"}).headers["x-request-id"] == "trace-12345678"
    )
    made = client.get("/v1/health", headers={"X-Request-ID": "bad id!"}).headers["x-request-id"]
    assert len(made) == 32 and made != "bad id!"


def test_inputs_are_validated_and_bodies_capped():
    bad_ip = {**EVENT, "user_id": "v1", "ip": "999.1.1.1"}
    bad_lat = {**EVENT, "user_id": "v2", "lat": 120.0, "lon": 10.0}
    bad_ts = {**EVENT, "user_id": "v3", "login_ts": "yesterday"}
    for body in (bad_ip, bad_lat, bad_ts):
        assert client.post("/v1/auth/evaluate", json=body, headers=KEY).status_code == 422
    huge = client.post("/v1/demo/check", content=b"x" * (300 * 1024), headers={"Content-Type": "application/json"})
    assert huge.status_code == 413
    # streamed in chunks, with no Content-Length to check up front
    chunked = client.post(
        "/v1/demo/check", content=iter([b"x" * 1024] * 300), headers={"Content-Type": "application/json"}
    )
    assert chunked.status_code == 413
    small = client.post("/v1/demo/check", content=iter([b"{}"]), headers={"Content-Type": "application/json"})
    assert small.status_code == 422  # under the cap, so it reaches validation
