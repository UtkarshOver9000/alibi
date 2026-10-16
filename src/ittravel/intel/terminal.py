"""
Open-Source Tech Bloomberg Terminal & Live Footprint Dossier.

Works for ANY company, domain, or ASN — not just presets.
Real external API calls: BGPView (ASN lookup), crt.sh (CT subdomains),
plus local snapshot data for CISA KEV, HIBP breaches, and EPSS scores.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.parse
import urllib.request
from typing import Any

from .network import lookup
from .service import _load, bad_ip, meta

_UA = "Alibi-Bloomberg/1.0 (+https://github.com/UtkarshOver9000/alibi)"


# ---------------------------------------------------------------------------
# BGPView – free, no key, returns real ASN data for any org name
# ---------------------------------------------------------------------------

def _bgpview_search(query: str) -> list[dict[str, Any]]:
    """Search BGPView for ASNs matching an organisation name."""
    if os.getenv("ALIBI_OFFLINE"):
        return []
    url = f"https://api.bgpview.io/search?query_term={urllib.parse.quote(query)}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=4.0) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            asns = []
            for a in data.get("data", {}).get("asns", [])[:12]:
                asns.append({
                    "asn": a.get("asn"),
                    "network": a.get("name", ""),
                    "country": a.get("country_code", ""),
                    "description": a.get("description", ""),
                })
            return asns
    except Exception:
        return []


def _bgpview_asn_detail(asn: int) -> dict[str, Any]:
    """Fetch prefixes and peer count for a single ASN."""
    if os.getenv("ALIBI_OFFLINE"):
        return {}
    url = f"https://api.bgpview.io/asn/{asn}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=3.5) as r:
            d = json.loads(r.read().decode("utf-8", errors="replace")).get("data", {})
            return {
                "asn": asn,
                "name": d.get("name", ""),
                "description": d.get("description_short", ""),
                "country": d.get("country_code", ""),
                "rir": d.get("rir_allocation", {}).get("rir_name", ""),
                "abuse_contacts": d.get("abuse_contacts", []),
                "peers_ipv4": d.get("peers", {}).get("ipv4", {}).get("count", 0),
                "prefixes_ipv4": d.get("prefixes", {}).get("ipv4_count", 0),
            }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Certificate Transparency – crt.sh (no key needed)
# ---------------------------------------------------------------------------

def fetch_crtsh_subdomains(domain: str, max_results: int = 40) -> list[str]:
    """Enumerate live subdomains via CT logs (crt.sh). Works for any domain."""
    if os.getenv("ALIBI_OFFLINE"):
        return []
    clean = domain.strip().lower().lstrip("*.")
    if "." not in clean or len(clean) < 4:
        return []
    url = f"https://crt.sh/?q=%.{urllib.parse.quote(clean)}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            subs: set[str] = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    s = name.strip().lower().lstrip("*.")
                    if s.endswith(clean) and s != clean:
                        subs.add(s)
            return sorted(subs)[:max_results]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# NVD / MITRE CVE lookup – no key needed for basic CVE data
# ---------------------------------------------------------------------------

def _fetch_nvd_cve(cve_id: str) -> dict[str, Any] | None:
    """Fetch basic CVE description from NVD API 2.0 (no key for low-rate queries)."""
    if os.getenv("ALIBI_OFFLINE"):
        return None
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id.upper())}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=4.0) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            items = data.get("vulnerabilities", [])
            if not items:
                return None
            cve = items[0].get("cve", {})
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss = entries[0].get("cvssData", {}).get("baseScore")
                    break
            return {
                "cve": cve_id.upper(),
                "description": desc[:300],
                "cvss": cvss,
                "published": cve.get("published", ""),
            }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main company_dossier – works for ANY query
# ---------------------------------------------------------------------------

def company_dossier(query: str, limit: int = 25) -> dict[str, Any]:
    """
    Open-source Bloomberg dossier for ANY company, domain, or ASN.

    Aggregates:
    - BGPView: real ASN/network footprint (any org name)
    - CISA KEV + EPSS: known-exploited CVEs (any vendor/product)
    - HIBP: data breaches (any domain or company name)
    - crt.sh: live Certificate Transparency subdomains (any domain)
    """
    query = query.strip()
    needle = query.lower()

    # --- 1. BGPView ASN search (real, any company) ---
    live_asns = _bgpview_search(query)

    # Also check local iptoasn data
    network_names = _load("network_names.json")
    asn_names = network_names.get("asn_names", {})
    local_asns: list[dict[str, Any]] = []
    for asn_str, org_name in asn_names.items():
        if needle in org_name.lower():
            local_asns.append({"asn": int(asn_str), "network": org_name, "country": ""})
            if len(local_asns) >= limit:
                break

    # Merge: live_asns first (more detailed), then local
    seen_asns: set[int] = {a["asn"] for a in live_asns if a.get("asn")}
    merged_asns = live_asns + [a for a in local_asns if a.get("asn") not in seen_asns]
    merged_asns = merged_asns[:limit]

    # --- 2. CISA KEV + EPSS flaws ---
    all_flaws = _load("flaws.json")
    matched_flaws = []
    for f in all_flaws:
        vendor = f.get("vendor", "").lower()
        product = f.get("product", "").lower()
        cve = f.get("cve", "").lower()
        if needle in vendor or needle in product or needle == cve:
            matched_flaws.append(f)
    matched_flaws.sort(key=lambda x: x.get("epss", 0.0), reverse=True)
    ransomware_flaws = [f for f in matched_flaws if f.get("ransomware_use")]
    top_cve_ids = [f["cve"] for f in matched_flaws[:10]]

    # --- 3. HIBP breaches ---
    all_breaches = _load("breaches.json")
    matched_breaches = []
    for b in all_breaches:
        b_name = b.get("name", "").lower()
        b_dom = b.get("domain", "").lower()
        b_title = b.get("title", "").lower()
        if needle in b_name or needle in b_dom or needle in b_title:
            matched_breaches.append(b)
    matched_breaches.sort(key=lambda x: x.get("accounts", 0), reverse=True)
    total_accounts = sum(b.get("accounts", 0) for b in matched_breaches)

    # --- 4. Certificate Transparency subdomains ---
    # Use domain if it looks like one, else guess from breaches
    target_domain = ""
    if "." in needle and not needle.replace(".", "").isdigit():
        target_domain = needle
    elif matched_breaches and matched_breaches[0].get("domain"):
        target_domain = matched_breaches[0]["domain"]

    live_subdomains = fetch_crtsh_subdomains(target_domain) if target_domain else []

    # --- 5. Security Health Score (0–100, letter grade) ---
    score = 100
    score -= min(len(matched_flaws) * 4, 30)
    score -= min(len(ransomware_flaws) * 8, 25)
    score -= min(len(matched_breaches) * 5, 20)
    if total_accounts > 10_000_000:
        score -= 15
    elif total_accounts > 1_000_000:
        score -= 10
    score = max(score, 10)

    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 35 else "F"
    grade_desc = {
        "A": "Strong Security Posture — minimal public attack surface",
        "B": "Moderate Risk — managed vulnerability surface",
        "C": "Elevated Exposure — active exploited CVE footprint",
        "D": "High Threat Surface — multiple historic breaches or active ransomware-targeted CVEs",
        "F": "Critical Exposure — urgent remediation required",
    }[grade]

    # --- 6. Executive summary bullets ---
    top_cve = matched_flaws[0]["cve"] if matched_flaws else None
    bullets = []
    if merged_asns:
        asn_list = ", ".join(f"AS{a['asn']}" for a in merged_asns[:4])
        bullets.append(f"Network footprint: {len(merged_asns)} BGP autonomous systems identified ({asn_list}).")
    if matched_flaws:
        bullets.append(
            f"Vulnerability exposure: {len(matched_flaws)} CISA Known Exploited CVEs attributed to this vendor "
            f"(highest risk: {top_cve}); {len(ransomware_flaws)} actively weaponized by ransomware gangs."
        )
    else:
        bullets.append("Vulnerability exposure: No CISA Known Exploited CVEs found for this vendor in our catalog.")
    if matched_breaches:
        bullets.append(
            f"Breach history: {len(matched_breaches)} publicly confirmed data breaches logged by HIBP "
            f"({total_accounts:,} accounts exposed in total)."
        )
    else:
        bullets.append("Breach history: No corporate domain matches found in the HIBP public breach catalog.")
    if live_subdomains:
        bullets.append(
            f"Attack surface: {len(live_subdomains)} live subdomains enumerated via Certificate Transparency (crt.sh)."
        )
    if not merged_asns and not matched_flaws and not matched_breaches and not live_subdomains:
        bullets.append(
            f"No records found for '{query}' across BGPView, CISA KEV, HIBP, or Certificate Transparency. "
            "Try a more specific company name, primary domain (e.g. infosys.com), or known vendor name."
        )

    # --- 7. Build structured breach summary for JS ---
    breach_summary = {
        "total_breaches": len(matched_breaches),
        "total_records": total_accounts,
        "data_classes": sorted({dc for b in matched_breaches for dc in b.get("data_classes", [])}),
    }

    # --- 8. ASN profile in the shape the JS reads ---
    asn_profile = [
        {
            "asn": a.get("asn"),
            "network": a.get("network", ""),
            "country": a.get("country", ""),
            "description": a.get("description", ""),
        }
        for a in merged_asns[:limit]
    ]

    return {
        # Fields the JS dashboard reads:
        "query": query,
        "company": query,
        "primary_domain": target_domain or None,
        "grade": grade,
        "score": score,
        "grade_description": grade_desc,
        "executive_summary": bullets,
        "summary_bullets": bullets,
        "asn_profile": asn_profile,
        "exploited_cves": top_cve_ids,
        "breach_summary": breach_summary,
        "attack_surface": {
            "domain": target_domain or None,
            "subdomains": live_subdomains,
            "total_found": len(live_subdomains),
            "source": "crt.sh Certificate Transparency",
        },
        # Also keep the verbose fields for API consumers
        "networks": {"total_asns": len(merged_asns), "asns": merged_asns},
        "breaches": {
            "total": len(matched_breaches),
            "total_accounts_exposed": total_accounts,
            "recent": matched_breaches[:limit],
        },
        "vulnerabilities": {
            "total_exploited": len(matched_flaws),
            "ransomware_weaponized": len(ransomware_flaws),
            "top_cves": matched_flaws[:limit],
        },
        "ransomware": {"active_extortion_gangs_7d": [f["cve"] for f in ransomware_flaws[:5]]},
        "as_of": meta().get("fetched_at"),
        "sources": "BGPView (ASN lookup) · CISA KEV · FIRST EPSS · HIBP (CC BY 4.0) · crt.sh Certificate Transparency",
    }


# ---------------------------------------------------------------------------
# live_footprint – returns fields the JS dashboard expects
# ---------------------------------------------------------------------------

def live_footprint(client_ip: str) -> dict[str, Any]:
    """
    Real-time digital footprint for ANY IP address.

    Returns fields matching the JS dashboard's expected shape:
    - threat_tier: CRITICAL / HIGH / ELEVATED / HEALTHY
    - is_tor, is_malware, is_criminal_network
    - network.asn, network.network, network.country, network.type
    - malware_threat: malware family if flagged
    - subsea_cables: list of nearby cable names
    """
    client_ip = client_ip.strip()
    net = lookup(client_ip)
    malware_info = bad_ip(client_ip)

    # Determine tier
    is_malware = bool(malware_info)
    is_criminal = bool(net.criminal_network)
    is_tor = bool(net.tor_exit)
    is_hosting = bool(net.hosting)

    if is_malware or is_criminal:
        tier = "CRITICAL"
        tier_summary = "Active threat actor infrastructure. Block at firewall immediately."
    elif is_tor:
        tier = "HIGH"
        tier_summary = "Tor exit relay — anonymising proxy used by threat actors and privacy users."
    elif is_hosting:
        tier = "ELEVATED"
        tier_summary = "Hosting / VPN / datacenter network — elevated risk of automated attack traffic."
    else:
        tier = "HEALTHY"
        tier_summary = "Residential or commercial ISP — normal routing, no threat flags detected."

    # Malware threat name
    malware_threat = ""
    if malware_info and isinstance(malware_info, dict):
        malware_threat = malware_info.get("malware", malware_info.get("threat", "Malware C2"))
    elif malware_info:
        malware_threat = "Malware C2 server"

    # Subsea cables – find cables landing in this country
    cables_data = _load("cables.json").get("landing_points", [])
    subsea_cables: list[str] = []
    if net.country:
        seen: set[str] = set()
        for lp in cables_data:
            if lp.get("country") == net.country:
                cable_name = lp.get("cable", "")
                if cable_name and cable_name not in seen:
                    subsea_cables.append(cable_name)
                    seen.add(cable_name)
                if len(subsea_cables) >= 8:
                    break

    # Try to resolve hostname
    hostname = ""
    try:
        hostname = socket.gethostbyaddr(client_ip)[0]
    except Exception:
        pass

    threat_status_dict = {
        "level": tier,
        "summary": tier_summary,
        "malware_records": malware_info,
    }

    return {
        # Fields JS reads directly:
        "ip": client_ip,
        "threat_tier": tier,
        "is_tor": is_tor,
        "is_malware": is_malware,
        "is_criminal_network": is_criminal,
        "malware_threat": malware_threat,
        "subsea_cables": subsea_cables,
        "network": {
            "asn": net.asn,
            "network": net.network,
            "country": net.country,
            "type": net.label,
            "is_hosting_or_vpn": is_hosting,
            "is_tor_exit": is_tor,
            "is_criminal_network": is_criminal,
            "cloud_provider": getattr(net, "cloud_provider", None),
            "hostname": hostname or None,
        },
        # Verbose fields for API consumers
        "threat_status": threat_status_dict,
        "threat_detail": threat_status_dict,
        "nearest_subsea_landing": cables_data[0] if cables_data and not subsea_cables else None,
        "as_of": meta().get("fetched_at"),
        "sources": (
            "iptoasn · DB-IP · abuse.ch ThreatFox · abuse.ch Feodo · "
            "Spamhaus DROP · Tor Project · TeleGeography"
        ),
    }
