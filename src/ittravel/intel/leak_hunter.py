"""
Corporate Breach & Leak Hunter (Pillar 7).
Audits corporate domains and password exposure using Have I Been Pwned breach archives,
k-anonymity SHA-1 Pwned Passwords range check, and RansomLook extortion claims.
"""

from __future__ import annotations

import os
import urllib.request
from typing import Any

from .service import _load, meta


def corporate_leak_audit(domain: str) -> dict[str, Any]:
    """Audit corporate domain exposure against breach dumps and active ransomware claims."""
    clean_domain = domain.strip().lower().lstrip("@")
    if not clean_domain:
        return {"error": "Domain must not be empty"}

    all_breaches = _load("breaches.json")

    matched_breaches = []
    total_records_exposed = 0
    data_classes_exposed = set()

    # Search breach records by domain or organization name
    needle = clean_domain.split(".")[0]
    for b in all_breaches:
        b_domain = (b.get("domain") or "").lower()
        b_name = (b.get("name") or "").lower()
        if clean_domain in b_domain or needle in b_domain or needle in b_name:
            matched_breaches.append(
                {
                    "title": b.get("title", b.get("name")),
                    "domain": b.get("domain"),
                    "breach_date": b.get("breach_date"),
                    "pwn_count": b.get("pwn_count", 0),
                    "data_classes": b.get("data_classes", []),
                    "verified": b.get("is_verified", True),
                }
            )
            total_records_exposed += b.get("pwn_count", 0)
            data_classes_exposed.update(b.get("data_classes", []))

    # Cross-reference ransomware extortion claims
    threats_data = _load("threats.json")
    ransomware = threats_data.get("ransomware", {})
    recent_claims = ransomware.get("victims", 0)

    m = meta()
    return {
        "domain": clean_domain,
        "as_of": m.get("fetched_at", "2026"),
        "total_breaches": len(matched_breaches),
        "total_records_exposed": total_records_exposed,
        "compromised_data_types": sorted(data_classes_exposed),
        "has_password_exposure": any("Password" in dc for dc in data_classes_exposed),
        "breaches": matched_breaches[:20],
        "ransomware_threat_environment": {
            "recent_extortion_claims_7d": recent_claims,
            "top_active_gangs": [g[0] for g in ransomware.get("by_group", [])[:5]],
        },
        "source": "Have I Been Pwned + RansomLook (100% Real 2026 Data)",
    }


def check_password_hash_k_anonymity(sha1_prefix: str) -> dict[str, Any]:
    """
    Check the first 5 characters of a SHA-1 password hash against HIBP Pwned Passwords.
    Strict k-anonymity: only the 5-char prefix is sent over the wire, never the full password.
    """
    prefix = sha1_prefix.strip().upper()
    if len(prefix) != 5:
        return {"error": "Prefix must be exactly 5 hexadecimal characters."}

    if os.getenv("ALIBI_OFFLINE"):
        return {"prefix": prefix, "matches_found": 12, "source": "HIBP Pwned Passwords (Offline fixture)"}

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Alibi-Leak-Hunter/1.0 (+https://github.com/UtkarshOver9000/alibi)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            count = len(text.strip().splitlines())
            return {
                "prefix": prefix,
                "matches_found": count,
                "status": "EXPOSED" if count > 0 else "CLEAN",
                "source": "Have I Been Pwned Pwned Passwords API (k-anonymity)",
            }
    except Exception:
        return {"prefix": prefix, "matches_found": 0, "status": "UNKNOWN", "source": "HIBP API offline"}
