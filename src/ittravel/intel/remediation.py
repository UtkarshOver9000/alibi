"""
AI Plain-English Remediation Engine (Pillar 9).

Generates deterministic 3-card executive briefs and exact 60-second shell fixes
for CVEs, malicious IPs, and DGA botnet domains.

- CVE: looks up CISA KEV first; falls back to NVD API for any CVE in existence
- IP: checks local threat feeds + does real BGP/network lookup
- DGA domain: provides sinkhole commands + real entropy analysis
"""

from __future__ import annotations

import json
import os
from typing import Any

from .network import lookup
from .service import _load

_UA = "Alibi-Remediation/1.0 (+https://github.com/UtkarshOver9000/alibi)"


def _nvd_cve_fetch(cve_id: str) -> dict[str, Any] | None:
    """Fetch CVE description + CVSS from NVD 2.0 API (no key, rate-limited)."""
    if os.getenv("ALIBI_OFFLINE"):
        return None
    import urllib.parse
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id.upper())}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
            items = data.get("vulnerabilities", [])
            if not items:
                return None
            cve = items[0].get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            # CVSS score
            cvss_score = None
            severity_str = ""
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = cve.get("metrics", {}).get(key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity_str = cvss_data.get("baseSeverity", "")
                    break
            # Affected products
            products: list[str] = []
            for config in cve.get("configurations", [])[:3]:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        cpe = match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) > 5:
                            prod = f"{parts[3].replace('_', ' ').title()} {parts[4].replace('_', ' ').title()}"
                            if prod not in products:
                                products.append(prod)
            return {
                "cve": cve_id.upper(),
                "description": desc[:400],
                "cvss": cvss_score,
                "severity": severity_str,
                "products": products[:6],
                "published": cve.get("published", ""),
                "references": [r2.get("url") for r2 in cve.get("references", [])[:3] if r2.get("url")],
            }
    except Exception:
        return None


def remediate_cve(cve_id: str) -> dict[str, Any]:
    """
    Deterministic remediation card for ANY CVE.

    1. Checks local CISA KEV snapshot (real 2026 data, EPSS scores, ransomware flag)
    2. Falls back to NVD API for any CVE not yet in KEV
    """
    cve_clean = cve_id.strip().upper()
    all_flaws = _load("flaws.json")

    kev_match = next((f for f in all_flaws if f.get("cve", "").upper() == cve_clean), None)
    nvd = None
    if not kev_match:
        nvd = _nvd_cve_fetch(cve_clean)

    # --- Build data from whichever source has it ---
    if kev_match:
        vendor = kev_match.get("vendor", "Unknown Vendor")
        product = kev_match.get("product", "Unknown Product")
        name = kev_match.get("name", "Vulnerability")
        ransomware = kev_match.get("ransomware_use") or kev_match.get("ransomware", False)
        epss = kev_match.get("epss")
        cvss = kev_match.get("cvss")
        description = kev_match.get("short_description") or name
        date_added = kev_match.get("date_added") or kev_match.get("added") or ""
        in_kev = True
    elif nvd:
        vendor = nvd["products"][0].split()[0] if nvd["products"] else "Unknown Vendor"
        prod_parts = nvd["products"][0].split()[1:] if nvd["products"] else []
        product = " ".join(prod_parts) if prod_parts else "Software"
        name = cve_clean
        ransomware = False
        epss = None
        cvss = nvd.get("cvss")
        description = nvd.get("description", "")[:300]
        date_added = nvd.get("published", "")[:10]
        in_kev = False
    else:
        # CVE doesn't exist or NVD offline — still give generic but accurate playbook
        vendor = "Unknown Vendor"
        product = "Affected Software"
        name = cve_clean
        ransomware = False
        epss = None
        cvss = None
        description = f"Security vulnerability {cve_clean}. Check NVD for details."
        date_added = ""
        in_kev = False

    epss_text = f"FIRST EPSS: {epss * 100:.1f}% probability of exploitation in the next 30 days." if epss else ""
    cvss_text = f"CVSS base score: {cvss}." if cvss else ""
    kev_text = "⚠️ Confirmed exploited in the wild — in CISA Known Exploited Vulnerabilities catalog." if in_kev else ""
    rw_text = "🔴 Actively weaponized by ransomware syndicates." if ransomware else ""

    what_happened = (
        f"{cve_clean} is a vulnerability in {vendor} {product}. "
        f"{description} "
        f"{kev_text} {rw_text} {epss_text} {cvss_text}"
    ).strip()

    who_is_impacted = (
        f"Any organisation running unpatched {vendor} {product} is exposed. "
        + (
            "Ransomware groups are known to exploit this for initial access and data exfiltration. "
            if ransomware
            else "Threat actors can exploit this to gain unauthorised access or execute arbitrary code. "
        )
        + "Exposed internet-facing instances are at highest risk."
    )

    what_to_do_now = (
        f"1. Immediately identify all {vendor} {product} instances in your environment using your asset inventory. "
        "2. Apply the vendor's latest security patch (check vendor advisory linked below). "
        "3. If a patch is unavailable, restrict network access using the firewall rule below. "
        "4. Audit logs for exploitation indicators."
    )

    # Generate the firewall rule command
    if "fortinet" in vendor.lower() or "pulse" in vendor.lower() or "palo" in vendor.lower():
        port = "443"
    elif "exchange" in product.lower() or "iis" in product.lower():
        port = "443"
    elif "log4" in product.lower():
        port = "8080"
    else:
        port = "443"

    cmd = (
        f"# Block external access to {product} management interface\n"
        f"iptables -I INPUT -p tcp --dport {port} ! -s 10.0.0.0/8 -j DROP\n"
        f"# Or with nftables:\n"
        f"nft add rule inet filter input tcp dport {port} ip saddr != 10.0.0.0/8 drop\n"
        f"# Then immediately apply vendor patch:\n"
        f"# https://nvd.nist.gov/vuln/detail/{cve_clean}"
    )

    return {
        "target": cve_clean,
        "type": "cve",
        "vendor": vendor,
        "product": product,
        "in_kev": in_kev,
        "ransomware_weaponized": ransomware,
        "epss_score": epss,
        "cvss_score": cvss,
        "date_added_to_kev": date_added,
        "what_happened": what_happened,
        "who_is_impacted": who_is_impacted,
        "what_to_do_now": what_to_do_now,
        "who_impacted": who_is_impacted,
        "what_to_do": what_to_do_now,
        "bullets": [what_happened, who_is_impacted, what_to_do_now],
        "firewall_rule": cmd,
        "remediation_command": cmd,
        "recommended_command": cmd,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_clean}",
        "sources": "CISA KEV · FIRST EPSS · NVD",
    }


def remediate_ip(ip: str) -> dict[str, Any]:
    """
    Remediation card for ANY IP address.

    Looks up threat feed records, ASN/network, Tor, cloud provider.
    """
    net = lookup(ip)
    bad_ips = _load("bad_ips.json")
    report = bad_ips.get(ip, {})

    if report:
        malware = report.get("malware") or report.get("threat") or "Malware C2 server"
        source_feed = report.get("source") or "abuse.ch ThreatFox / Feodo"
        is_known_bad = True
    else:
        malware = "Not found in current threat feeds"
        source_feed = "abuse.ch ThreatFox / Feodo / URLhaus"
        is_known_bad = False

    is_tor = bool(net.tor_exit)
    is_drop = bool(net.criminal_network)
    is_hosting = bool(net.hosting)
    cloud = getattr(net, "cloud_provider", None)
    asn_str = f"AS{net.asn} ({net.network})" if net.asn else "unknown ASN"

    if is_known_bad:
        what_happened = (
            f"IP {ip} is actively listed on {source_feed} as a {malware} command-and-control server. "
            f"It belongs to {asn_str}, located in {net.country or 'unknown country'}."
            + (" It is a registered Tor exit relay." if is_tor else "")
            + (" It is in a Spamhaus-listed criminal network block." if is_drop else "")
        )
        who_is_impacted = (
            "Internal machines communicating with this IP are likely compromised or being directed to "
            "download payloads. This is an active threat requiring immediate containment."
        )
        what_to_do_now = (
            f"1. Block {ip} at your border firewall immediately using the commands below. "
            "2. Search your SIEM/firewall logs for any internal hosts that connected to this IP. "
            "3. Isolate any internal host that made outbound connections to this address. "
            "4. Run an EDR scan on isolated hosts for second-stage malware."
        )
    else:
        what_happened = (
            f"IP {ip} is not currently listed in our threat feeds (abuse.ch Feodo, ThreatFox, URLhaus, Spamhaus DROP). "
            f"It belongs to {asn_str}, located in {net.country or 'unknown'}."
            + (f" Cloud provider: {cloud}." if cloud else "")
            + (" It is a registered Tor exit relay — anonymising proxy." if is_tor else "")
            + (" It is a hosting/datacenter network." if is_hosting and not is_tor else "")
        )
        who_is_impacted = (
            "No active threat confirmed from current feeds. "
            + (
                "However, Tor exit relay traffic should be treated with elevated caution."
                if is_tor
                else "Monitor for unusual behaviour from this address if it appears in your logs."
                if is_hosting
                else "If this IP appears in your logs unexpectedly, investigate the connection."
            )
        )
        what_to_do_now = (
            f"1. Check your firewall and SIEM for {'all' if is_tor else 'recent'} connections from/to {ip}. "
            "2. Verify whether the traffic is expected (e.g. CDN, known service). "
            "3. If unexpected, apply the block rule below as a precaution. "
            "4. Re-query this IP in 24 hours — feeds update continuously."
        )

    cmd = (
        f"# Block with iptables:\n"
        f"iptables -I INPUT -s {ip} -j DROP\n"
        f"iptables -I FORWARD -d {ip} -j DROP\n"
        f"iptables -I OUTPUT -d {ip} -j DROP\n"
        f"# Or with nftables:\n"
        f"nft add element inet filter alibi_blocklist {{ {ip} }}"
    )

    return {
        "target": ip,
        "type": "ip",
        "is_known_malware": is_known_bad,
        "malware_family": malware if is_known_bad else None,
        "is_tor": is_tor,
        "is_criminal_network": is_drop,
        "is_hosting": is_hosting,
        "cloud_provider": cloud,
        "asn": net.asn,
        "carrier": net.network,
        "country": net.country,
        "what_happened": what_happened,
        "who_is_impacted": who_is_impacted,
        "what_to_do_now": what_to_do_now,
        "who_impacted": who_is_impacted,
        "what_to_do": what_to_do_now,
        "bullets": [what_happened, who_is_impacted, what_to_do_now],
        "firewall_rule": cmd,
        "remediation_command": cmd,
        "recommended_command": cmd,
        "sources": "abuse.ch ThreatFox · Feodo Tracker · Spamhaus DROP · iptoasn · Tor Project",
    }


def remediate_dga(domain: str, entropy: float = 0.0) -> dict[str, Any]:
    """
    Remediation card for a DGA botnet domain.

    Re-evaluates entropy if not provided; checks domain against ThreatFox URLhaus feed.
    """
    from .dns_shield import calculate_entropy, evaluate_domain
    domain = domain.strip().lower().rstrip(".")

    # Get real evaluation from DNS shield
    eval_result = evaluate_domain(domain)
    real_entropy = eval_result.get("entropy", entropy)
    status = eval_result.get("status", "UNKNOWN")
    is_blocked = status == "BLOCKED"
    reason = eval_result.get("reason", "")
    resolved = eval_result.get("resolved_ips", [])

    label = domain.split(".")[0]
    label_entropy = calculate_entropy(label)
    is_dga_by_entropy = label_entropy > 3.65 and len(label) > 10

    what_happened = (
        f"Domain '{domain}' was flagged"
        + (" by ThreatFox/URLhaus as an active malware C2 or download URL." if is_blocked and not is_dga_by_entropy else
           f" by DGA entropy analysis (Shannon entropy: {real_entropy:.3f} > threshold 3.65). "
           "High-entropy subdomain labels are a strong indicator of Domain Generation Algorithm (DGA) "
           "malware that rotates C2 domains algorithmically to evade static blocklists." if is_dga_by_entropy else
           f". Reason: {reason}")
    )
    if resolved and resolved[0] != "NXDOMAIN":
        what_happened += f" Currently resolves to: {', '.join(resolved[:3])}."

    who_is_impacted = (
        "Machines on your network that are querying or connecting to this domain are likely infected "
        "with botnet malware. DGA-based malware (Mirai, Mozi, Emotet, Cobalt Strike beacons) generates "
        "hundreds of domain names per day — blocking the current domain only delays the C2 connection."
    )

    what_to_do_now = (
        f"1. Sinkhole '{domain}' to 0.0.0.0 on your local recursive DNS resolver (see commands below). "
        "2. Search DNS query logs for ALL queries to this domain — each querying host is likely infected. "
        "3. Isolate each infected host and run a full EDR/AV scan. "
        "4. Block the resolved IPs at your border firewall. "
        "5. Enable DNS over HTTPS (DoH) filtering on your network to prevent DGA domains resolving."
    )

    cmd = (
        f"# Pi-hole or CoreDNS sinkhole:\n"
        f"echo '0.0.0.0 {domain}' >> /etc/hosts\n"
        f"# Or with dnsmasq (Pi-hole):\n"
        f"echo 'address=/{domain}/0.0.0.0' >> /etc/dnsmasq.d/alibi-block.conf && systemctl restart dnsmasq\n"
        + (
            "# Also block resolved IPs:\n"
            + "\n".join(f"iptables -I FORWARD -d {ip} -j DROP" for ip in resolved[:4] if ip != "NXDOMAIN")
            if resolved and resolved[0] != "NXDOMAIN" else ""
        )
    )

    return {
        "target": domain,
        "type": "dga",
        "entropy": real_entropy,
        "is_dga": is_dga_by_entropy,
        "is_threat_feed_blocked": is_blocked,
        "resolved_ips": resolved,
        "threat_reason": reason,
        "what_happened": what_happened,
        "who_is_impacted": who_is_impacted,
        "what_to_do_now": what_to_do_now,
        "who_impacted": who_is_impacted,
        "what_to_do": what_to_do_now,
        "bullets": [what_happened, who_is_impacted, what_to_do_now],
        "firewall_rule": cmd,
        "remediation_command": cmd,
        "recommended_command": cmd,
        "sources": "abuse.ch ThreatFox · URLhaus · DGA Entropy Analysis (Shannon)",
    }
