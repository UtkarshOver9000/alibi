from fastapi.testclient import TestClient

from ittravel.api.app import app

client = TestClient(app)


def test_health_and_dashboard():
    health = client.get("/v1/health").json()
    assert health["status"] in ("ok", "degraded") and health["snapshot"]
    for feed in health["feeds"]:
        assert {"id", "name", "status", "last_success", "age_hours", "records"} <= feed.keys()
        assert feed["name"]
    assert "Alibi" in client.get("/").text


def test_terminal_company_endpoint():
    res = client.get("/v1/terminal/company", params={"q": "Cloudflare"})
    assert res.status_code == 200
    data = res.json()
    assert data["query"] == "Cloudflare"
    assert "grade" in data
    assert "score" in data
    assert "executive_summary" in data
    assert "networks" in data


def test_terminal_footprint_endpoint():
    res = client.get("/v1/terminal/footprint", params={"ip": "1.1.1.1"})
    assert res.status_code == 200
    data = res.json()
    assert data["ip"] == "1.1.1.1"
    assert "network" in data
    assert data["network"]["asn"] == 13335
    assert "threat_status" in data
    assert "level" in data["threat_status"]


def test_shield_check_endpoint():
    res = client.get("/v1/shield/check", params={"domain": "google.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["domain"] == "google.com"
    assert data["status"] == "ALLOWED"
    assert data["action"] == "RESOLVED"

    # Test high entropy domain detection
    dga_res = client.get("/v1/shield/check", params={"domain": "xq7b9kz1m0w8p2r4j6f.biz"})
    assert dga_res.status_code == 200
    dga_data = dga_res.json()
    assert dga_data["status"] == "BLOCKED"
    assert dga_data["action"] == "SINKHOLED"
    assert dga_data["sinkhole_ip"] == "0.0.0.0"


def test_state_dossier_endpoint():
    res = client.get("/v1/intel/state/California")
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "California"
    assert data["country_code"] == "US"
    assert "telemetry" in data
    assert "malware_c2_nodes" in data["telemetry"]
    assert "threat_tier" in data["telemetry"]
    assert "ooni_censorship" in data

    # Test index-based lookup
    res_idx = client.get(f"/v1/intel/state/{data['index']}")
    assert res_idx.status_code == 200
    assert res_idx.json()["name"] == "California"

    # Test not found
    assert client.get("/v1/intel/state/NonexistentState123456").status_code == 404


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


def test_body_limit_enforced():
    huge_data = b"x" * (300 * 1024)
    huge = client.post("/v1/terminal/company", content=huge_data, headers={"Content-Type": "application/json"})
    assert huge.status_code == 413
