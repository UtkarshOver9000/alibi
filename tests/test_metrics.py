"""
Tests for Prometheus metrics and cloud provider network identification.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from ittravel.api.app import app
from ittravel.intel import network

client = TestClient(app)


def test_prometheus_metrics_endpoint():
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    text = resp.text
    assert "alibi_up 1" in text
    assert "alibi_bad_ips_total" in text
    assert "alibi_canary_tokens_active" in text
    assert "alibi_active_disruptions" in text


def test_cloud_provider_asn_mapping():
    # Cloudflare 1.1.1.1 is AS13335
    net = network.lookup("1.1.1.1")
    assert net.asn == 13335
    assert net.cloud_provider == "Cloudflare"
    assert "Cloudflare" in net.label or "hosting" in net.label


def test_aws_cloud_provider_recognition():
    # Check that CLOUD_ASN_MAP has AWS and Azure
    assert 16509 in network.CLOUD_ASN_MAP
    assert "AWS" in network.CLOUD_ASN_MAP[16509]
    assert 8075 in network.CLOUD_ASN_MAP
    assert "Azure" in network.CLOUD_ASN_MAP[8075]
