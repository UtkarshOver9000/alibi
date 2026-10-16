"""
Unit tests for Defense, Supply Chain, Canary, Remediation, and Compute Atlas (Pillars 5-10).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from ittravel.api.app import app

client = TestClient(app)


def test_disruptions_endpoint():
    res = client.get("/v1/intel/disruptions")
    assert res.status_code == 200
    data = res.json()
    assert "total_active_alerts" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


def test_supply_chain_endpoint():
    res = client.get("/v1/supply-chain/analyze", params={"package": "requests", "ecosystem": "pypi"})
    assert res.status_code == 200
    data = res.json()
    assert data["package"] == "requests"
    assert data["ecosystem"] == "pypi"
    assert "licenses" in data
    assert "security_status" in data


def test_leak_hunter_domain_endpoint():
    res = client.get("/v1/terminal/leak-hunter", params={"domain": "adobe.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["domain"] == "adobe.com"
    assert "total_breaches" in data
    assert "ransomware_threat_environment" in data


def test_pwned_password_k_anonymity_endpoint():
    res = client.get("/v1/terminal/pwned-password", params={"prefix": "21BD1"})
    assert res.status_code == 200
    data = res.json()
    assert data["prefix"] == "21BD1"
    assert "matches_found" in data


def test_canary_tripwire_lifecycle():
    # 1. Generate canary
    gen_res = client.post("/v1/canary/generate", params={"kind": "aws", "memo": "Honeypot AWS Key"})
    assert gen_res.status_code == 200
    canary_data = gen_res.json()
    token = canary_data["token"]
    assert "decoys" in canary_data
    assert "aws_credentials" in canary_data["decoys"]

    # 2. Trip canary
    trip_res = client.get(f"/v1/canary/trip/{token}", headers={"User-Agent": "AttackerBot/1.0"})
    assert trip_res.status_code == 200
    assert trip_res.headers["content-type"] == "image/gif"

    # 3. Check alarms
    alarms_res = client.get("/v1/canary/alarms")
    assert alarms_res.status_code == 200
    alarms = alarms_res.json()["alarms"]
    assert len(alarms) > 0
    assert any(a["token"] == token for a in alarms)


def test_remediation_engine_cve():
    res = client.get("/v1/remediation/explain", params={"type": "cve", "target": "CVE-2021-26086"})
    assert res.status_code == 200
    data = res.json()
    assert data["target"] == "CVE-2021-26086"
    assert len(data["bullets"]) == 3
    assert "recommended_command" in data


def test_remediation_engine_ip():
    res = client.get("/v1/remediation/explain", params={"type": "ip", "target": "162.243.103.246"})
    assert res.status_code == 200
    data = res.json()
    assert data["target"] == "162.243.103.246"
    assert len(data["bullets"]) == 3
    assert "recommended_command" in data


def test_remediation_engine_dga():
    res = client.get("/v1/remediation/explain", params={"type": "dga", "target": "xq7b9kz1m0w8.biz", "entropy": 3.85})
    assert res.status_code == 200
    data = res.json()
    assert data["target"] == "xq7b9kz1m0w8.biz"
    assert len(data["bullets"]) == 3


def test_compute_atlas_endpoint():
    res = client.get("/v1/intel/compute-atlas")
    assert res.status_code == 200
    data = res.json()
    assert "ai_clusters" in data
    assert "semiconductor_fabs" in data
    assert len(data["ai_clusters"]) > 0
    assert len(data["semiconductor_fabs"]) > 0
