"""
BGP Routing & Internet Disruption Radar (Pillar 5).

Fetches real-time global internet outages from:
- IODA (Internet Outage Detection & Analysis — Georgia Tech / CAIDA)
- Derives country-level disruption signals from OONI confirmed_blocks in local snapshot

Returns the shape the JS dashboard expects:
  global_health, critical_count, active_disruptions[], as_of
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any

from .service import _load, meta

_UA = "Alibi-Disruption-Radar/1.0 (+https://github.com/UtkarshOver9000/alibi)"

# IODA v2 alerts API – Georgia Tech / CAIDA (public, no key)
IODA_ALERTS_URL = "https://api.ioda.inetintel.cc.gatech.edu/v2/alerts/default/current?limit=50&min_severity=normal"
CACHE_TTL = 300  # 5 minutes
_CACHE: dict[str, Any] = {"data": None, "ts": 0.0}

_SEV_MAP = {"critical": "CRITICAL", "warning": "HIGH", "normal": "MEDIUM", "info": "LOW"}
_COUNTRY_NAMES: dict[str, str] = {}


def _country_name(cc: str) -> str:
    global _COUNTRY_NAMES
    if not _COUNTRY_NAMES:
        try:
            countries = _load("countries.json")
            _COUNTRY_NAMES = {k: v.get("name", k) for k, v in countries.items()}
        except Exception:
            pass
    return _COUNTRY_NAMES.get(cc.upper(), cc)


def _fetch_ioda() -> list[dict[str, Any]]:
    """Call IODA API for live alerts. Caches 5 min."""
    now = time.time()
    if _CACHE["data"] is not None and (now - _CACHE["ts"] < CACHE_TTL):
        return _CACHE["data"]  # type: ignore[return-value]

    if os.getenv("ALIBI_OFFLINE"):
        result = _from_ooni_snapshot()
        _CACHE.update(data=result, ts=now)
        return result

    req = urllib.request.Request(IODA_ALERTS_URL, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            raw = json.loads(r.read().decode("utf-8", errors="replace"))
            alerts: list[dict[str, Any]] = []
            for item in raw.get("data", []):
                entity = item.get("entity", {}) if isinstance(item.get("entity"), dict) else {}
                entity_code = entity.get("code") or item.get("entityCode", "")
                entity_name = entity.get("name") or item.get("entityName") or _country_name(entity_code) or entity_code
                sev_raw = str(item.get("level") or item.get("severity") or "normal").lower()
                sev = _SEV_MAP.get(sev_raw, "MEDIUM")
                started_ts = item.get("time") or item.get("startTime")
                started_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(started_ts))) if started_ts else None
                alerts.append(
                    {
                        "id": item.get("id", f"ioda-{entity_code}"),
                        "country": entity_code.upper() if len(entity_code) == 2 else "",
                        "country_name": entity_name,
                        "type": item.get("datasource", "bgp").upper(),
                        "severity": sev,
                        "started": started_iso,
                        "drop_pct": item.get("overallScore"),
                        "description": item.get("condition") or f"Internet disruption detected — {entity_name}.",
                        "asns": item.get("asns", []),
                        "source": "IODA (Georgia Tech / CAIDA)",
                    }
                )
            if not alerts:
                alerts = _from_ooni_snapshot()
            _CACHE.update(data=alerts, ts=now)
            return alerts
    except Exception:
        result = _from_ooni_snapshot()
        _CACHE.update(data=result, ts=now)
        return result


def _from_ooni_snapshot() -> list[dict[str, Any]]:
    """
    Derive disruption signals from OONI confirmed_blocks in the local snapshot.
    These are real measurements from OONI probe volunteers (no fabrication).
    """
    try:
        countries = _load("countries.json")
    except Exception:
        return []

    disruptions: list[dict[str, Any]] = []
    for cc, info in countries.items():
        ooni = info.get("ooni") or {}
        blocks = ooni.get("confirmed_blocks", 0)
        if blocks < 5:
            continue
        sev = "CRITICAL" if blocks > 200 else "HIGH" if blocks > 50 else "MEDIUM"
        disruptions.append(
            {
                "id": f"ooni-{cc.lower()}",
                "country": cc.upper(),
                "country_name": info.get("name", cc),
                "type": "OONI_CENSORSHIP",
                "severity": sev,
                "started": meta().get("fetched_at"),
                "drop_pct": None,
                "description": (
                    f"{blocks:,} confirmed OONI censorship/blocking measurements in {info.get('name', cc)}. "
                    "Probe volunteers reported consistent interference with web and network services."
                ),
                "asns": [],
                "source": "OONI Explorer (ooni.org)",
            }
        )

    disruptions.sort(key=lambda d: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(d["severity"], 4))
    return disruptions[:40]


def get_disruptions_overview() -> dict[str, Any]:
    """Return disruption radar for the JS dashboard."""
    alerts = _fetch_ioda()
    m = meta()
    critical = sum(1 for a in alerts if a["severity"] == "CRITICAL")
    high = sum(1 for a in alerts if a["severity"] == "HIGH")
    global_health = "CRITICAL" if critical > 5 else "DEGRADED" if (critical + high) > 10 else "NORMAL"

    return {
        "as_of": m.get("fetched_at"),
        "global_health": global_health,
        "critical_count": critical,
        "total_active_alerts": len(alerts),
        "alerts": alerts,
        "active_disruptions": alerts,
        "primary_datasource": "IODA (Georgia Tech / CAIDA) + OONI Explorer",
        "ioda_url": "https://ioda.live",
        "ooni_url": "https://explorer.ooni.org",
    }
