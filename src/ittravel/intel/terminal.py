"""
Open-Source Tech Bloomberg Terminal & Live Footprint Dossier Service.

Aggregates:
- Corporate BGP ASN & Cloud Footprint (from network_names.json)
- Known Exploited Vulnerabilities (from CISA KEV + FIRST EPSS)
- Corporate Data Breaches (from Have I Been Pwned)
- Ransomware Leak-Site Activity (from RansomLook)
- Live Visitor Digital Footprint & Hacker Tripwire Diagnostic
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from .network import lookup
from .service import _load, bad_ip, meta


def fetch_crtsh_subdomains(domain: str, max_results: int = 30) -> list[str]:
    """Fetch live subdomains via Certificate Transparency (crt.sh). Returns [] if offline or unreachable."""
    if os.getenv("ALIBI_OFFLINE"):
        return []
    clean_domain = domain.strip().lower().lstrip(".")
    if "." not in clean_domain or len(clean_domain) < 4:
        return []
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(clean_domain)}&output=json"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Alibi-Planetary-Terminal/1.0 (+https://github.com/UtkarshOver9000/alibi)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            subs = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for sub in name_value.split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(clean_domain) and sub != clean_domain:
                        subs.add(sub)
            return sorted(subs)[:max_results]
    except Exception:
        return []


def company_dossier(query: str, limit: int = 25) -> dict[str, Any]:
    """Compile an open-source Bloomberg-style tech & security dossier on any company or domain."""
    query = query.strip()
    needle = query.lower()

    # 1. Match ASNs and Network Infrastructure
    network_names = _load("network_names.json")
    asn_names = network_names.get("asn_names", {})
    matched_asns = []
    for asn_str, org_name in asn_names.items():
        if needle in org_name.lower() or needle == asn_str:
            matched_asns.append(
                {
                    "asn": int(asn_str),
                    "name": org_name,
                }
            )
            if len(matched_asns) >= limit:
                break

    # 2. Match Corporate Breaches (Have I Been Pwned)
    all_breaches = _load("breaches.json")
    matched_breaches = []
    for b in all_breaches:
        b_name = b.get("name", "").lower()
        b_dom = b.get("domain", "").lower()
        b_title = b.get("title", "").lower()
        if needle in b_name or needle in b_dom or needle in b_title:
            matched_breaches.append(b)

    matched_breaches.sort(key=lambda x: x.get("accounts", 0), reverse=True)
    total_breached_accounts = sum(b.get("accounts", 0) for b in matched_breaches)

    # 3. Match Exploited Flaws (CISA KEV + EPSS)
    all_flaws = _load("flaws.json")
    matched_flaws = []
    for f in all_flaws:
        vendor = f.get("vendor", "").lower()
        product = f.get("product", "").lower()
        cve = f.get("cve", "").lower()
        if needle in vendor or needle in product or needle == cve:
            matched_flaws.append(f)

    # Sort flaws by EPSS probability descending
    matched_flaws.sort(key=lambda x: x.get("epss", 0.0), reverse=True)
    ransomware_flaws = [f for f in matched_flaws if f.get("ransomware_use")]

    # 4. Match Ransomware Extortion Claims (RansomLook)
    threats_data = _load("threats.json")
    ransomware_history = threats_data.get("ransomware", {})
    recent_ransomware_claims = ransomware_history.get("victims", 0)

    # 5. Live Certificate Transparency (crt.sh)
    target_domain = ""
    if "." in needle and not needle.replace(".", "").isdigit():
        target_domain = needle
    elif matched_breaches and matched_breaches[0].get("domain"):
        target_domain = matched_breaches[0]["domain"]

    live_subdomains = fetch_crtsh_subdomains(target_domain) if target_domain else []

    # 6. Calculate Security Health Score (0 - 100)
    score = 100
    # Penalty for active KEV flaws
    score -= min(len(matched_flaws) * 4, 30)
    # Penalty for ransomware-associated flaws
    score -= min(len(ransomware_flaws) * 8, 25)
    # Penalty for past breaches
    score -= min(len(matched_breaches) * 5, 20)
    # Penalty for large breaches (>1M accounts)
    if total_breached_accounts > 10_000_000:
        score -= 15
    elif total_breached_accounts > 1_000_000:
        score -= 10
    score = max(score, 15)

    if score >= 85:
        grade = "A"
        grade_desc = "Strong Security Posture / Minimal Public Surface"
    elif score >= 70:
        grade = "B"
        grade_desc = "Moderate Risk / Managed Vulnerability Surface"
    elif score >= 50:
        grade = "C"
        grade_desc = "Elevated Exposure / Active Exploit Footprint"
    elif score >= 35:
        grade = "D"
        grade_desc = "High Threat Surface / Multiple Historic Breaches"
    else:
        grade = "F"
        grade_desc = "Critical Threat Exposure / Urgent Remediation Required"

    # 7. Executive Plain-English Summary
    top_cve = matched_flaws[0]["cve"] if matched_flaws else "None active"
    bullets = [
        f"Infrastructure: Identified {len(matched_asns)} dedicated ASNs and routing blocks on public networks.",
        (
            f"Vulnerability Exposure: {len(matched_flaws)} CISA KEV flaws cataloged (highest risk: {top_cve}); "
            f"{len(ransomware_flaws)} weaponized in ransomware."
        ),
        (
            f"Leak History: {len(matched_breaches)} corporate breaches logged "
            f"({total_breached_accounts:,} accounts exposed)."
        ),
    ]
    if live_subdomains:
        bullets.append(
            f"Attack Surface: Discovered {len(live_subdomains)} live subdomains via Certificate Transparency."
        )

    return {
        "query": query,
        "as_of": meta().get("fetched_at"),
        "grade": grade,
        "score": score,
        "grade_description": grade_desc,
        "executive_summary": bullets,
        "networks": {
            "total_asns": len(matched_asns),
            "asns": matched_asns,
        },
        "breaches": {
            "total": len(matched_breaches),
            "total_accounts_exposed": total_breached_accounts,
            "recent": matched_breaches[:limit],
        },
        "vulnerabilities": {
            "total_exploited_flaws": len(matched_flaws),
            "ransomware_weaponized": len(ransomware_flaws),
            "high_risk_cves": matched_flaws[:limit],
        },
        "attack_surface": {
            "domain": target_domain or None,
            "subdomains": live_subdomains,
            "total_subdomains_found": len(live_subdomains),
            "source": "Certificate Transparency (crt.sh)",
        },
        "ransomware": {
            "recent_extortion_claims_tracked": recent_ransomware_claims,
        },
    }


def live_footprint(client_ip: str) -> dict[str, Any]:
    """100% real-time personal digital footprint and hacker tripwire diagnostic."""
    client_ip = client_ip.strip()
    net = lookup(client_ip)

    # Check threat list occurrences
    malware_info = bad_ip(client_ip)

    # Determine security status
    is_compromised = bool(malware_info or net.criminal_network)
    is_anonymized = bool(net.tor_exit or net.hosting)

    if is_compromised:
        threat_level = "CRITICAL"
        threat_action = "Hostile threat actor activity detected on this IP."
    elif is_anonymized:
        threat_level = "ELEVATED"
        threat_action = "Routing through VPN, hosting data center, or Tor exit."
    else:
        threat_level = "HEALTHY"
        threat_action = "Standard residential / commercial ISP routing."

    # Subsea cable adjacency
    cables_data = _load("cables.json").get("landing_points", [])
    nearest_landing = None
    if net.country:
        matching_landings = [lp for lp in cables_data if lp.get("country") == net.country]
        if matching_landings:
            nearest_landing = matching_landings[0]

    return {
        "ip": client_ip,
        "network": {
            "asn": net.asn,
            "network_name": net.network,
            "country": net.country,
            "type": net.label,
            "is_hosting_or_vpn": net.hosting,
            "is_tor_exit": net.tor_exit,
            "is_criminal_network": net.criminal_network,
        },
        "threat_status": {
            "level": threat_level,
            "summary": threat_action,
            "malware_records": malware_info,
        },
        "nearest_subsea_landing": nearest_landing,
        "as_of": meta().get("fetched_at"),
    }
