"""
Canary Token & Hacker Tripwire Generator (Pillar 8).
Generates decoy assets (fake AWS keys, database URIs, tracked webhooks) and
alerts when intruders access or leak them, capturing their IP, ASN, and user-agent.
"""

from __future__ import annotations

import base64
import secrets
import time
from typing import Any

from .network import lookup

# In-memory storage for active tokens and tripped alerts
_TOKENS: dict[str, dict[str, Any]] = {}
_ALARMS: list[dict[str, Any]] = []

# 1x1 transparent tracking GIF
PIXEL_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def generate_canary(kind: str = "webhook", memo: str = "Corporate internal decoy") -> dict[str, Any]:
    """Generate a new canary tripwire token and decoy assets."""
    token = secrets.token_hex(12)
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    _TOKENS[token] = {
        "token": token,
        "kind": kind,
        "memo": memo,
        "created_at": created_at,
        "tripped": False,
        "tripped_count": 0,
    }

    # Generate decoy payloads based on requested kind
    fake_aws_key = f"AKIA{token[:16].upper()}"
    fake_aws_secret = secrets.token_urlsafe(32)
    db_uri = f"postgresql://app_svc_{token[:6]}:{secrets.token_hex(8)}@db-cluster-internal.net:5432/production"
    trip_path = f"/v1/canary/trip/{token}"

    return {
        "token": token,
        "kind": kind,
        "memo": memo,
        "created_at": created_at,
        "tripwire_url": trip_path,
        "decoys": {
            "aws_credentials": (
                f"[default]\naws_access_key_id = {fake_aws_key}\naws_secret_access_key = {fake_aws_secret}"
            ),
            "database_connection_string": db_uri,
            "web_beacon_url": trip_path,
        },
    }


def record_trip(token: str, ip: str, user_agent: str) -> dict[str, Any]:
    """Record an intrusion event when a decoy token is accessed."""
    tok_data = _TOKENS.get(token)
    memo = tok_data.get("memo", "Unknown decoy") if tok_data else "Unregistered / Staged Decoy"

    if tok_data:
        tok_data["tripped"] = True
        tok_data["tripped_count"] = tok_data.get("tripped_count", 0) + 1

    net = lookup(ip)
    alarm = {
        "token": token,
        "memo": memo,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "intruder_ip": ip,
        "user_agent": user_agent,
        "network": {
            "asn": net.asn,
            "carrier": net.network,
            "country": net.country,
            "is_hosting_vpn": net.hosting,
        },
    }
    _ALARMS.insert(0, alarm)
    if len(_ALARMS) > 200:
        _ALARMS.pop()
    return alarm


def get_alarms() -> list[dict[str, Any]]:
    """Return recent canary tripwire alarms."""
    return _ALARMS


def get_tokens() -> list[dict[str, Any]]:
    """Return all created canary tokens."""
    return list(_TOKENS.values())
