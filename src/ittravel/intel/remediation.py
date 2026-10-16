"""
AI Plain-English Remediation Engine (Pillar 9).
Generates deterministic 3-bullet executive cards and exact 60-second shell fixes
for CVEs, active malware servers, BGP anomalies, and leaked credentials.
"""

from __future__ import annotations

from typing import Any

from .network import lookup
from .service import _load


def remediate_cve(cve_id: str) -> dict[str, Any]:
    """Generate a 3-bullet plain-English remediation card for a CVE."""
    cve_clean = cve_id.strip().upper()
    all_flaws = _load("flaws.json")

    matched = next((f for f in all_flaws if f.get("cve", "").upper() == cve_clean), None)
    if not matched:
        return {
            "target": cve_clean,
            "type": "vulnerability",
            "bullets": [
                f"What happened: Security flaw {cve_clean} was identified in software infrastructure.",
                "What could happen: Attackers can exploit unpatched instances to gain unauthorized access.",
                "Exact 60-second fix: Apply the latest vendor security advisory patch immediately.",
            ],
            "recommended_command": (
                f"# Upgrade package:\napt-get update && apt-get --only-upgrade install {cve_clean.lower()}"
            ),
        }

    vendor = matched.get("vendor", "Vendor")
    product = matched.get("product", "Product")
    name = matched.get("name", "Vulnerability")
    ransomware = matched.get("ransomware", False)
    epss = matched.get("epss")
    epss_text = (
        f"FIRST EPSS calculates a {epss * 100:.1f}% chance of active exploitation in the wild."
        if epss
        else "Confirmed exploited in the wild by CISA."
    )

    b1 = (
        f"What happened: A critical vulnerability in {vendor} {product} ({name}) "
        f"allows threat actors to compromise the host. {epss_text}"
    )
    b2 = (
        "What could happen: Known ransomware syndicates actively target this vulnerability to exfiltrate "
        "proprietary data and encrypt network files."
        if ransomware
        else "What could happen: Threat actors can execute arbitrary code, bypass authentication, and establish "
        "persistent footholds on your network."
    )
    b3 = (
        f"Exact 60-second fix: Upgrade {vendor} {product} to the latest vendor-released patch and restrict "
        "management access from public interfaces."
    )

    fix_cmd = (
        f"# Update {product} perimeter rule:\n"
        "iptables -I INPUT -p tcp --dport 443 -s 10.0.0.0/8 -j ACCEPT\n"
        f"# Apply latest security patch for {vendor} {product}"
    )

    return {
        "target": cve_clean,
        "type": "vulnerability",
        "vendor": vendor,
        "product": product,
        "epss_score": epss,
        "ransomware_weaponized": ransomware,
        "bullets": [b1, b2, b3],
        "recommended_command": fix_cmd,
    }


def remediate_ip(ip: str) -> dict[str, Any]:
    """Generate a 3-bullet plain-English remediation card for a malicious IP."""
    net = lookup(ip)
    bad_ips = _load("bad_ips.json")
    report = bad_ips.get(ip, {})

    malware = report.get("malware", "Unknown malware")
    what = report.get("what", "Hostile C2 controller")
    source = report.get("source", "abuse.ch threat feed")

    b1 = f"What happened: IP {ip} is actively flagged on {source} as a {what} associated with {malware}."
    b2 = (
        "What could happen: Compromised internal machines connecting to this address are likely beaconing "
        "or downloading second-stage ransomware payloads."
    )
    b3 = (
        f"Exact 60-second fix: Immediately block {ip} at your border firewall and isolate any internal "
        f"hosts communicating with AS{net.asn} ({net.network})."
    )

    cmd = (
        f"nft add element inet filter alibi_threat_nodes {{ {ip} }}\n"
        "# Or with iptables:\n"
        f"iptables -I INPUT -s {ip} -j DROP\n"
        f"iptables -I FORWARD -d {ip} -j DROP"
    )

    return {
        "target": ip,
        "type": "hostile_ip",
        "malware": malware,
        "asn": net.asn,
        "carrier": net.network,
        "bullets": [b1, b2, b3],
        "recommended_command": cmd,
    }


def remediate_dga(domain: str, entropy: float) -> dict[str, Any]:
    """Generate a 3-bullet remediation card for a DGA domain."""
    b1 = (
        f"What happened: Domain '{domain}' exhibits elevated Shannon entropy ({entropy:.3f} > 3.65), "
        "characteristic of algorithmic botnet command-and-control generation."
    )
    b2 = (
        "What could happen: Malware infections on your local subnet use rotating DGA domains to evade "
        "static DNS blocklists and receive remote commands."
    )
    b3 = (
        f"Exact 60-second fix: Sinkhole '{domain}' to 0.0.0.0 on your local DNS resolver and inspect outbound "
        "port 53 / DoH queries from internal clients."
    )

    cmd = f"# CoreDNS / Pi-hole entry:\n0.0.0.0 {domain}\n# Linux hosts file:\necho '0.0.0.0 {domain}' >> /etc/hosts"

    return {
        "target": domain,
        "type": "dga_domain",
        "entropy": entropy,
        "bullets": [b1, b2, b3],
        "recommended_command": cmd,
    }
