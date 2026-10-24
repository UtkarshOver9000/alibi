"""
Active Protective DNS Shield & DGA Sinkhole (Pillar 4).

Checks any domain against:
- Shannon entropy (DGA detection, threshold 3.65 on the label)
- ThreatFox / URLhaus bad_ips.json (threat feed match via DNS resolution)
- RFC 8484 DNS-over-HTTPS wire format handlers

Returns fields the JS dashboard reads:
  verdict, entropy, dga_reason, bad_ip_hits, resolved_ips, status, action
"""

from __future__ import annotations

import math
import socket
from collections import Counter
from typing import Any

from .service import _load


def calculate_entropy(text: str) -> float:
    """Shannon entropy of a string (higher = more random = more DGA-like)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def evaluate_domain(domain: str) -> dict[str, Any]:
    """
    Inspect any domain. Returns fields the JS dashboard reads exactly:
      verdict: BLOCK | ALLOW
      status:  BLOCKED | ALLOWED
      action:  SINKHOLED | RESOLVED
      entropy: float
      dga_reason: str | None
      bad_ip_hits: list[str]  (IPs that resolved and are in threat feeds)
      resolved_ips: list[str]
      reason: str
    """
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        return {"verdict": "ERROR", "status": "ERROR", "reason": "Empty domain", "entropy": 0.0}

    label = domain.split(".")[0]
    entropy = round(calculate_entropy(label), 3)
    is_dga = len(label) > 12 and entropy > 3.65

    dga_reason: str | None = None
    if is_dga:
        dga_reason = (
            f"Subdomain label '{label}' has Shannon entropy {entropy:.3f} (threshold 3.65) "
            f"and length {len(label)} chars — consistent with Domain Generation Algorithm (DGA) malware."
        )
        return {
            "domain": domain,
            "verdict": "BLOCK",
            "status": "BLOCKED",
            "action": "SINKHOLED",
            "sinkhole_ip": "0.0.0.0",
            "reason": f"DGA pattern detected (entropy {entropy:.3f} > 3.65, length {len(label)})",
            "dga_reason": dga_reason,
            "entropy": entropy,
            "resolved_ips": [],
            "bad_ip_hits": [],
            "is_dga": True,
        }

    # Resolve to real IPs
    resolved_ips: list[str] = []
    try:
        _, _, ip_list = socket.gethostbyname_ex(domain)
        resolved_ips = [ip for ip in ip_list if ip]
    except socket.gaierror:
        resolved_ips = ["NXDOMAIN"]
    except Exception:
        resolved_ips = ["RESOLUTION_ERROR"]

    # Check resolved IPs against threat feeds
    bad_ips_data = _load("bad_ips.json")
    bad_ip_hits: list[str] = []
    threat_name = ""
    for ip in resolved_ips:
        if ip in bad_ips_data:
            bad_ip_hits.append(ip)
            hit = bad_ips_data[ip]
            if isinstance(hit, dict):
                threat_name = hit.get("malware") or hit.get("threat") or "malware C2"
            else:
                threat_name = str(hit)

    if bad_ip_hits:
        hit_list = ", ".join(bad_ip_hits[:3])
        return {
            "domain": domain,
            "verdict": "BLOCK",
            "status": "BLOCKED",
            "action": "SINKHOLED",
            "sinkhole_ip": "0.0.0.0",
            "reason": f"Domain resolves to active threat infrastructure ({hit_list}: {threat_name})",
            "dga_reason": None,
            "entropy": entropy,
            "resolved_ips": resolved_ips,
            "bad_ip_hits": bad_ip_hits,
            "threat_name": threat_name,
            "is_dga": False,
        }

    # Clean domain
    return {
        "domain": domain,
        "verdict": "ALLOW",
        "status": "ALLOWED",
        "action": "RESOLVED",
        "sinkhole_ip": None,
        "reason": "No threat signals detected — clean domain",
        "dga_reason": None,
        "entropy": entropy,
        "resolved_ips": resolved_ips,
        "bad_ip_hits": [],
        "is_dga": False,
    }


# ---------------------------------------------------------------------------
# RFC 8484 DNS-over-HTTPS wire format
# ---------------------------------------------------------------------------


def parse_dns_qname(data: bytes, offset: int = 12) -> tuple[str, int]:
    """Parse DNS wire-format QNAME labels into a dot-separated domain name."""
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
    """Build an RFC 1035 / RFC 8484 DNS response packet with an A record."""
    if len(query_packet) < 12:
        return b""
    tx_id = query_packet[:2]
    flags = b"\x81\x80"  # QR=1 AA=0 TC=0 RD=1 RA=1 RCODE=0
    _, q_end = parse_dns_qname(query_packet, 12)
    q_section = query_packet[12 : min(len(query_packet), q_end + 4)]
    ip_to_return = "0.0.0.0" if sinkhole else (resolved_ip or "127.0.0.1")
    try:
        import socket as _sock

        ip_bytes = _sock.inet_aton(ip_to_return)
    except Exception:
        ip_bytes = b"\x00\x00\x00\x00"
    header = tx_id + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ip_bytes
    return header + q_section + answer


def handle_wire_query(query_bytes: bytes) -> tuple[bytes, dict[str, Any]]:
    """Process an RFC 8484 wire-format DNS query and return (response_bytes, eval_dict)."""
    if len(query_bytes) < 12:
        return b"", {"verdict": "ERROR", "reason": "Malformed DNS packet"}
    domain, _ = parse_dns_qname(query_bytes, 12)
    eval_res = evaluate_domain(domain)
    is_blocked = eval_res.get("status") == "BLOCKED"
    res_ips = eval_res.get("resolved_ips", [])
    valid_ip = res_ips[0] if (res_ips and res_ips[0] not in ("NXDOMAIN", "RESOLUTION_ERROR")) else "127.0.0.1"
    resp_bytes = build_dns_response(query_bytes, sinkhole=is_blocked, resolved_ip=valid_ip)
    return resp_bytes, eval_res
