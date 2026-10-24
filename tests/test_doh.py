"""
Tests for RFC 8484 DNS-over-HTTPS and DGA sinkholing.
"""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from ittravel.api.app import app
from ittravel.intel.dns_shield import build_dns_response, parse_dns_qname

client = TestClient(app)


def test_doh_json_query_clean():
    resp = client.get("/dns-query?name=google.com&type=A")
    assert resp.status_code == 200
    data = resp.json()
    assert data["Status"] == 0
    assert data["Question"][0]["name"] == "google.com."
    assert "Answer" in data
    assert data["alibi_verdict"] == "RESOLVED"


def test_doh_json_query_dga_sinkhole():
    resp = client.get("/dns-query?name=xq7b9kz1m0w8p2r4j6f.biz&type=A")
    assert resp.status_code == 200
    data = resp.json()
    assert data["alibi_verdict"] == "SINKHOLED"
    assert data["Answer"][0]["data"] == "0.0.0.0"


def test_doh_wire_format_post():
    # Build a standard DNS query wire packet for google.com (QTYPE=A, QCLASS=IN)
    # Header: ID=0x1234, Flags=0x0100 (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x06google\x03com\x00"  # QNAME: google.com
        b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
    )
    resp = client.post("/dns-query", content=query, headers={"Content-Type": "application/dns-message"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/dns-message"
    body = resp.content
    assert len(body) >= 12
    assert body[:2] == b"\x12\x34"  # Matching transaction ID


def test_doh_wire_format_get_base64url():
    query = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
    dns_b64 = base64.urlsafe_b64encode(query).decode().rstrip("=")
    resp = client.get(f"/dns-query?dns={dns_b64}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/dns-message"
    assert resp.content[:2] == b"\xaa\xbb"


def test_doh_helper_functions():
    query = b"\x43\x21\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x01\x00\x01"
    domain, q_end = parse_dns_qname(query, 12)
    assert domain == "example.org"
    resp = build_dns_response(query, sinkhole=True)
    assert len(resp) > len(query)
    assert resp[-4:] == b"\x00\x00\x00\x00"  # 0.0.0.0 sinkhole
