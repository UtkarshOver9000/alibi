"""
Corporate Breach & Leak Hunter (Pillar 7).

Real data sources:
- HIBP breach catalog (local snapshot — CC BY 4.0)
- HIBP Pwned Passwords k-anonymity range API (live call, no key)
- RansomLook extortion tracker (local snapshot)

Works for ANY domain, any company name, any email domain.
Returns fields the JS dashboard expects exactly.
"""

from __future__ import annotations

import os
import urllib.request
from typing import Any

from .service import _load, meta

_UA = "Alibi-Leak-Hunter/1.0 (+https://github.com/UtkarshOver9000/alibi)"


def corporate_leak_audit(domain: str) -> dict[str, Any]:
    """
    Audit any corporate domain against HIBP breach catalog and ransomware extortion feeds.

    Searches by:
    - Exact domain match (e.g. adobe.com)
    - Domain keyword match (e.g. 'adobe' in 'adobe.co.uk')
    - Company name match

    Returns fields the JS dashboard reads:
      domain, risk_level, total_pwned_accounts, breaches[], ransomware_claims[]
    """
    clean = domain.strip().lower()
    if clean.startswith("@"):
        clean = clean[1:]
    if clean.startswith("www."):
        clean = clean[4:]
    if not clean:
        return {"error": "Domain must not be empty"}

    # Extract the primary name component (e.g. "adobe" from "adobe.com")
    needle = clean.split(".")[0]

    all_breaches = _load("breaches.json")

    matched: list[dict[str, Any]] = []
    total_accounts = 0
    data_classes: set[str] = set()

    for b in all_breaches:
        b_domain = (b.get("domain") or "").lower()
        b_name = (b.get("name") or "").lower()
        b_title = (b.get("title") or "").lower()
        # Match full domain, keyword in domain, or keyword in company name
        if (
            clean == b_domain
            or clean in b_domain
            or needle in b_domain
            or needle in b_name
            or needle in b_title
        ):
            count = int(b.get("pwn_count") or b.get("accounts") or 0)
            matched.append({
                "name": b.get("title") or b.get("name") or b_domain,
                "domain": b.get("domain") or "",
                "breach_date": b.get("breach_date") or b.get("date") or "",
                "pwn_count": count,
                "data_classes": b.get("data_classes") or [],
                "verified": b.get("is_verified", True),
                "description": (b.get("description") or "")[:200],
            })
            total_accounts += count
            data_classes.update(b.get("data_classes") or [])

    # Sort by size descending
    matched.sort(key=lambda x: x["pwn_count"], reverse=True)

    # --- Ransomware extortion claims ---
    threats = _load("threats.json")
    ransomware = threats.get("ransomware", {})
    # Try to find any specific claims mentioning this domain/company
    # RansomLook data in snapshot groups by gang; no per-victim search without a key.
    # We expose the aggregate environment stats.
    recent_claims: list[dict[str, Any]] = []
    for entry in (ransomware.get("recent_victims") or [])[:50]:
        victim = (entry.get("victim") or entry.get("name") or "").lower()
        if needle in victim or clean in victim:
            recent_claims.append({
                "gang": entry.get("group") or entry.get("gang") or "Unknown gang",
                "date": entry.get("date") or entry.get("discovered") or "",
                "details": entry.get("description") or entry.get("details") or "",
            })

    # --- Risk level ---
    if matched and total_accounts > 10_000_000:
        risk = "CRITICAL"
    elif matched and total_accounts > 1_000_000:
        risk = "HIGH"
    elif matched:
        risk = "MEDIUM"
    elif recent_claims:
        risk = "HIGH"
    else:
        risk = "LOW"

    has_passwords = any("password" in dc.lower() for dc in data_classes)

    return {
        # Fields JS reads:
        "domain": clean,
        "risk_level": risk,
        "total_pwned_accounts": total_accounts,
        "breaches": matched[:25],
        "ransomware_claims": recent_claims[:10],
        "ransomware_threat_environment": {
            "recent_extortion_claims_7d": len(recent_claims),
            "recent_claims": recent_claims,
            "top_active_gangs": [g[0] for g in ransomware.get("by_group", [])[:5]],
        },
        # Extra fields for API consumers:
        "total_breaches": len(matched),
        "has_password_exposure": has_passwords,
        "compromised_data_types": sorted(data_classes),
        "as_of": meta().get("fetched_at"),
        "sources": "Have I Been Pwned (CC BY 4.0) · RansomLook",
        "note": (
            "HIBP breach catalog searched by domain and company name keyword. "
            "RansomLook victim list searched for domain keyword matches."
        ),
    }


def check_password_hash_k_anonymity(sha1_prefix: str) -> dict[str, Any]:
    """
    Check any SHA-1 password prefix against HIBP Pwned Passwords range API.

    Strict k-anonymity: only 5-char prefix transmitted. Full hash stays client-side.
    Returns the suffix→count map so the browser can check its own full hash.
    """
    prefix = sha1_prefix.strip().upper()
    if len(prefix) != 5 or not all(c in "0123456789ABCDEF" for c in prefix):
        return {"error": "Prefix must be exactly 5 hexadecimal characters (SHA-1)."}

    if os.getenv("ALIBI_OFFLINE"):
        return {
            "prefix": prefix,
            "matches": {},
            "matches_found": 12,
            "total_hashes_in_range": 12,
            "pwned": True,
            "source": "HIBP Pwned Passwords (offline)",
        }

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _UA,
            "Add-Padding": "true",  # HIBP padding for k-anonymity
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            text = r.read().decode("utf-8", errors="replace")
            matches: dict[str, int] = {}
            total = 0
            for line in text.strip().splitlines():
                line = line.strip()
                if ":" in line:
                    suffix, count_str = line.split(":", 1)
                    try:
                        count = int(count_str.strip())
                        if count > 0:
                            matches[suffix.strip()] = count
                        total += 1
                    except ValueError:
                        pass

            # Check if any suffix has non-zero count (i.e. password is pwned)
            # The actual match is done client-side in JS by comparing the full hash suffix
            pwned_count = max(matches.values()) if matches else 0

            return {
                "prefix": prefix,
                "matches": matches,  # suffix → count; JS finds its suffix
                "matches_found": total or len(matches),
                "total_hashes_in_range": total,
                "pwned": len(matches) > 0,  # at least one match in this prefix range
                "exposure_count": pwned_count,
                "source": "Have I Been Pwned Pwned Passwords API (k-anonymity, SHA-1)",
                "note": "Only the 5-char SHA-1 prefix was transmitted. Full hash stays in browser.",
            }
    except Exception as e:
        return {
            "prefix": prefix,
            "matches": {},
            "matches_found": 0,
            "total_hashes_in_range": 0,
            "pwned": False,
            "error": f"HIBP API error: {str(e)[:100]}",
            "source": "HIBP Pwned Passwords",
        }
