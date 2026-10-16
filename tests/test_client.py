"""
Unit tests for AlibiClient Python library SDK.
"""

from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import patch

import pytest

from ittravel.client import AlibiClient, AlibiClientError


class FakeResponse:
    def __init__(self, data: bytes, code: int = 200) -> None:
        self.data = data
        self.code = code

    def read(self) -> bytes:
        return self.data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def test_client_init():
    client = AlibiClient("http://localhost:8000/", api_key="secret-key", timeout=5.0)
    assert client.base_url == "http://localhost:8000"
    assert client.api_key == "secret-key"
    assert client.timeout == 5.0


def test_client_company_dossier():
    client = AlibiClient()
    mock_payload = {"company": "Cloudflare", "grade": "A", "score": 95}

    with patch("urllib.request.urlopen", return_value=FakeResponse(json.dumps(mock_payload).encode())):
        res = client.company_dossier("Cloudflare")
        assert res["company"] == "Cloudflare"
        assert res["grade"] == "A"


def test_client_live_footprint():
    client = AlibiClient()
    mock_payload = {"ip": "1.1.1.1", "threat_tier": "CLEAN"}

    with patch("urllib.request.urlopen", return_value=FakeResponse(json.dumps(mock_payload).encode())):
        res = client.live_footprint("1.1.1.1")
        assert res["ip"] == "1.1.1.1"
        assert res["threat_tier"] == "CLEAN"


def test_client_shield_check():
    client = AlibiClient()
    mock_payload = {"domain": "google.com", "verdict": "ALLOW"}

    with patch("urllib.request.urlopen", return_value=FakeResponse(json.dumps(mock_payload).encode())):
        res = client.shield_check("google.com")
        assert res["domain"] == "google.com"
        assert res["verdict"] == "ALLOW"


def test_client_state_dossier():
    client = AlibiClient()
    mock_payload = {"name": "California", "country_code": "US"}

    with patch("urllib.request.urlopen", return_value=FakeResponse(json.dumps(mock_payload).encode())):
        res = client.state_dossier("California")
        assert res["name"] == "California"


def test_client_raw_text_export():
    client = AlibiClient()
    raw_blocklist = "# ALIBI Blocklist\n1.2.3.4\n"

    with patch("urllib.request.urlopen", return_value=FakeResponse(raw_blocklist.encode())):
        res = client.export_blocklist(limit=10)
        assert "1.2.3.4" in res


def test_client_http_error():
    client = AlibiClient()
    err_body = io.BytesIO(b'{"detail": "Not found"}')
    err = urllib.error.HTTPError("http://localhost:8000/err", 404, "Not Found", {}, err_body)

    with patch("urllib.request.urlopen", side_effect=err):
        with pytest.raises(AlibiClientError) as exc_info:
            client.company_dossier("Nonexistent")
        assert exc_info.value.status_code == 404
        assert "Not found" in exc_info.value.message
