"""
Tests for OASIS TAXII 2.1 threat intelligence server.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from ittravel.api.app import app

client = TestClient(app)


def test_taxii_discovery():
    resp = client.get("/taxii2/")
    assert resp.status_code == 200
    data = resp.json()
    assert "/taxii2/v21/" in data["api_roots"]
    assert "title" in data


def test_taxii_api_root():
    resp = client.get("/taxii2/v21/")
    assert resp.status_code == 200
    data = resp.json()
    assert "application/taxii+json;version=2.1" in data["versions"]
    assert data["max_content_length"] > 0


def test_taxii_collections_list():
    resp = client.get("/taxii2/v21/collections/")
    assert resp.status_code == 200
    cols = resp.json().get("collections", [])
    assert len(cols) >= 3
    ids = [c["id"] for c in cols]
    assert "alibi-c2-malware" in ids
    assert "alibi-drop-networks" in ids
    assert "alibi-exploited-flaws" in ids


def test_taxii_collection_detail():
    resp = client.get("/taxii2/v21/collections/alibi-c2-malware/")
    assert resp.status_code == 200
    col = resp.json()
    assert col["id"] == "alibi-c2-malware"
    assert col["can_read"] is True
    assert col["can_write"] is False

    # 404 for unknown collection
    resp404 = client.get("/taxii2/v21/collections/unknown-col/")
    assert resp404.status_code == 404


def test_taxii_collection_objects():
    resp = client.get("/taxii2/v21/collections/alibi-c2-malware/objects/?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["type"] == "bundle"
    assert "objects" in data
    assert len(data["objects"]) > 0


def test_taxii_collection_manifest():
    resp = client.get("/taxii2/v21/collections/alibi-c2-malware/manifest/?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "objects" in data
    manifest_items = data["objects"]
    assert len(manifest_items) > 0
    assert "id" in manifest_items[0]
    assert "version" in manifest_items[0]
