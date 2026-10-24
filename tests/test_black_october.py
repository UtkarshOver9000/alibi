from fastapi.testclient import TestClient

from ittravel.api.app import app

client = TestClient(app)


def test_black_october_overview():
    resp = client.get("/v1/black-october/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_incidents"] == 27
    assert data["metrics"]["year_level_catastrophes"] >= 10
    assert data["metrics"]["lowest_private_key_value"] == 4
    assert len(data["incidents"]) == 27


def test_black_october_incident_autopsy():
    # Test eMudhra forensic autopsy
    resp = client.get("/v1/black-october/incident/emudhra")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == "emudhra"
    assert "CVE-2026-111943" in data["cve"]
    assert "Key = 4" in data["name"]
    assert "technical_mechanism" in data
    assert "how_it_happened" in data

    # Test PHP2Shell forensic autopsy
    resp2 = client.get("/v1/black-october/incident/php2shell")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["id"] == "php2shell"
    assert "CVE-2026-109618" in data2["cve"]
    assert data2["cvss"] >= 9.0


def test_black_october_incident_not_found():
    resp = client.get("/v1/black-october/incident/nonexistent-incident-slug")
    assert resp.status_code == 404


def test_black_october_audit_get():
    resp = client.get("/v1/black-october/audit?target=example.com&target_type=domain")
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "example.com"
    assert "overall_verdict" in data
    assert "findings" in data
    assert len(data["findings"]) >= 1


def test_black_october_audit_post():
    resp = client.post("/v1/black-october/audit", json={"target": "litellm", "target_type": "package"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "litellm"
    assert "findings" in data


def test_black_october_remediation():
    resp = client.get("/v1/black-october/remediate/php2shell")
    assert resp.status_code == 200
    data = resp.json()
    assert "mitigation_shell_command" in data
    assert "apt-get" in data["mitigation_shell_command"]
    assert "waf_rule" in data
