"""
Active Protective DNS Shield & DGA Sinkhole Service.
"""

from __future__ import annotations

import math
import socket
from collections import Counter
from typing import Any

from .service import _load


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy to identify high-randomness DGA domains."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def evaluate_domain(domain: str) -> dict[str, Any]:
    """Inspect a domain against live ThreatFox/URLhaus feeds and DGA entropy."""
    domain = domain.strip().lower().rstrip(".")
    domain_label = domain.split(".")[0]
    entropy = calculate_entropy(domain_label)
    is_dga = len(domain_label) > 12 and entropy > 3.65

    # 1. High entropy DGA check
    if is_dga:
        return {
            "domain": domain,
            "status": "BLOCKED",
            "action": "SINKHOLED",
            "sinkhole_ip": "0.0.0.0",
            "reason": f"Domain Generation Algorithm (DGA) pattern detected (Entropy: {entropy:.2f})",
            "entropy": round(entropy, 2),
        }

    # 2. Resolve domain to check against bad_ips
    resolved_ips: list[str] = []
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        resolved_ips = ip_list
    except Exception:
        resolved_ips = ["NXDOMAIN"]

    bad_ips_data = _load("bad_ips.json")
    for ip in resolved_ips:
        if ip in bad_ips_data:
            hit = bad_ips_data[ip]
            threat_name = hit.get("threat", "malware/C2 server") if isinstance(hit, dict) else str(hit)
            return {
                "domain": domain,
                "status": "BLOCKED",
                "action": "SINKHOLED",
                "sinkhole_ip": "0.0.0.0",
                "reason": f"Domain resolves to active threat host ({ip}: {threat_name})",
                "entropy": round(entropy, 2),
                "resolved_ips": resolved_ips,
            }

    return {
        "domain": domain,
        "status": "ALLOWED",
        "action": "RESOLVED",
        "resolved_ips": resolved_ips,
        "reason": "Clean domain",
        "entropy": round(entropy, 2),
    }
