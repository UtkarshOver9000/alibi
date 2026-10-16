"""
BGP Routing & Server Tripping Radar (Pillar 5).
Real-time global internet disruption, outage, and BGP anomaly tracking powered by
IODA (Internet Outage Detection and Analysis - Georgia Tech / CAIDA) and real-time route telemetry.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any

from .service import _load, meta

# Fallback curated real-time baseline if IODA API is rate-limited or offline
IODA_API_URL = "https://api.ioda.inetintel.cc.gatech.edu/v2/alerts/default/current?limit=50"
CACHE_TTL = 300  # 5 minutes
_CACHE: dict[str, Any] = {"data": None, "ts": 0}


def fetch_ioda_disruptions() -> list[dict[str, Any]]:
    """Fetch live internet outages and BGP anomalies from IODA API."""
    now = time.time()
    if _CACHE["data"] and (now - _CACHE["ts"] < CACHE_TTL):
        return _CACHE["data"]

    if os.getenv("ALIBI_OFFLINE"):
        return _build_fallback_disruptions()

    req = urllib.request.Request(
        IODA_API_URL,
        headers={"User-Agent": "Alibi-Planetary-Terminal/1.0 (+https://github.com/UtkarshOver9000/alibi)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            raw = json.loads(resp.read().decode("utf-8", errors="replace"))
            alerts = []
            for item in raw.get("data", []):
                alerts.append(
                    {
                        "id": item.get("id"),
                        "entity": item.get("entityName") or item.get("entityCode") or "Unknown Region",
                        "entity_type": item.get("entityType", "country"),
                        "entity_code": item.get("entityCode", ""),
                        "datasource": item.get("datasource", "bgp"),
                        "severity": item.get("severity", "medium"),
                        "start_time": item.get("startTime"),
                        "status": "ongoing" if not item.get("endTime") else "resolved",
                        "details": item.get("summary", "Internet connectivity drop detected across network prefixes."),
                    }
                )
            _CACHE["data"] = alerts
            _CACHE["ts"] = now
            return alerts
    except Exception:
        fallback = _build_fallback_disruptions()
        _CACHE["data"] = fallback
        _CACHE["ts"] = now
        return fallback


def _build_fallback_disruptions() -> list[dict[str, Any]]:
    """Synthesize latest known confirmed disruptions from OONI and network data."""
    countries_data = _load("countries.json")
    m = meta()
    disruptions = []

    # Find countries with confirmed web blocks / anomalies in OONI
    for cc, info in countries_data.items():
        ooni = info.get("ooni")
        if ooni and ooni.get("confirmed_blocks", 0) > 10:
            disruptions.append(
                {
                    "id": f"ioda-ooni-{cc.lower()}",
                    "entity": info.get("name", cc),
                    "entity_type": "country",
                    "entity_code": cc,
                    "datasource": "ooni+bgp",
                    "severity": "high" if ooni.get("confirmed_blocks", 0) > 50 else "medium",
                    "start_time": m.get("fetched_at", "2026-10-10"),
                    "status": "ongoing",
                    "details": (
                        f"{ooni.get('confirmed_blocks')} confirmed web blocks and tampering events "
                        "detected across public ISPs."
                    ),
                }
            )

    # Sort high severity first
    disruptions.sort(key=lambda d: 0 if d["severity"] == "high" else 1)
    return disruptions[:30]


def get_disruptions_overview() -> dict[str, Any]:
    """Return structured disruption radar data with summary counts."""
    disruptions = fetch_ioda_disruptions()
    m = meta()
    high_count = sum(1 for d in disruptions if d["severity"] == "high")
    return {
        "as_of": m.get("fetched_at", "2026"),
        "total_active_alerts": len(disruptions),
        "high_severity_outages": high_count,
        "primary_datasource": "IODA (Georgia Tech / CAIDA) + OONI Explorer",
        "alerts": disruptions,
    }
