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


def parse_dns_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    """Parse DNS wire-format QNAME labels into dot-separated domain name."""
    labels: list[str] = []
    curr = offset
    while curr < len(data):
        length = data[curr]
        if length == 0:
            curr += 1
            break
        if (length & 0xC0) == 0xC0:
            curr += 2
            break
        curr += 1
        labels.append(data[curr : curr + length].decode("ascii", errors="replace"))
        curr += length
    return ".".join(labels), curr


def build_dns_response(query_packet: bytes, sinkhole: bool = False, resolved_ip: str | None = None) -> bytes:
    """Build an RFC 1035 / RFC 8484 DNS response packet with A record."""
    if len(query_packet) < 12:
        return b""
    tx_id = query_packet[:2]
    flags = b"\x81\x80"  # QR=1, RD=1, RA=1, RCODE=0 (NoError)
    _, q_end = parse_dns_qname(query_packet, 12)
    q_section = query_packet[12 : min(len(query_packet), q_end + 4)]

    ip_to_return = "0.0.0.0" if sinkhole else (resolved_ip or "127.0.0.1")
    try:
        ip_bytes = socket.inet_aton(ip_to_return)
    except Exception:
        ip_bytes = b"\x00\x00\x00\x00"

    header = tx_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ip_bytes
    return header + q_section + answer


def handle_wire_query(query_bytes: bytes) -> tuple[bytes, dict[str, Any]]:
    """Process an RFC 8484 wire-format DNS query and return (response_bytes, eval_dict)."""
    if len(query_bytes) < 12:
        return b"", {"status": "ERROR", "reason": "Malformed DNS packet"}
    domain, _ = parse_dns_qname(query_bytes, 12)
    eval_res = evaluate_domain(domain)
    is_blocked = eval_res.get("status") == "BLOCKED"
    res_ips = eval_res.get("resolved_ips", [])
    valid_ip = res_ips[0] if (res_ips and res_ips[0] != "NXDOMAIN") else "127.0.0.1"
    resp_bytes = build_dns_response(query_bytes, sinkhole=is_blocked, resolved_ip=valid_ip)
    return resp_bytes, eval_res

