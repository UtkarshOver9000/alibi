"""
Threat intelligence export formats: STIX 2.1, MISP event JSON, CSV, plain blocklist,
Linux nftables set, and Suricata/Snort IDS rules.
Aligned with MISP, OpenCTI, and SOC tooling.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime
from typing import Any

from .service import _load, meta
from .stix import bundle, malware_server


def _get_indicators(limit: int) -> list[tuple[str, dict[str, Any]]]:
    bad_ips: dict[str, dict[str, Any]] = _load("bad_ips.json")
    # Sort with online/recent first
    sorted_ips = sorted(
        bad_ips.items(),
        key=lambda item: (item[1].get("online", False), item[1].get("seen", "")),
        reverse=True,
    )
    return sorted_ips[:limit]


def to_csv(limit: int = 1000) -> str:
    """Export threat indicators as standard CSV."""
    indicators = _get_indicators(limit)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "indicator",
            "type",
            "threat",
            "malware_family",
            "source",
            "first_seen",
            "asn",
            "network",
            "country",
            "online",
        ]
    )
    for ip, data in indicators:
        writer.writerow(
            [
                ip,
                "ipv4-addr",
                data.get("what", "Malware server"),
                data.get("malware", "Unknown"),
                data.get("source", "abuse.ch"),
                data.get("seen", ""),
                data.get("asn", ""),
                data.get("network", ""),
                data.get("country", ""),
                "true" if data.get("online") else "false",
            ]
        )
    return output.getvalue()


def to_stix(limit: int = 100) -> dict[str, Any]:
    """Export threat indicators as a STIX 2.1 JSON bundle."""
    indicators = _get_indicators(limit)
    objects: list[dict[str, Any]] = []
    for ip, data in indicators:
        objects.extend(malware_server(ip, data))
    return bundle(objects)


def to_misp(limit: int = 100) -> dict[str, Any]:
    """Export threat indicators as a standard MISP 2.4 Event JSON."""
    indicators = _get_indicators(limit)
    m = meta()
    event_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"alibi-misp-{m.get('fetched_at', '2026')}"))
    event_date = m.get("fetched_at", datetime.now(UTC).strftime("%Y-%m-%d"))[:10]

    attributes = []
    for ip, data in indicators:
        attr_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{ip}.alibi.threat"))
        attributes.append(
            {
                "uuid": attr_uuid,
                "type": "ip-dst",
                "category": "Network activity",
                "to_ids": True,
                "value": ip,
                "comment": (
                    f"{data.get('what', 'Malware node')} - {data.get('malware', '')} ({data.get('source', 'abuse.ch')})"
                ),
                "timestamp": str(data.get("t", int(datetime.now(UTC).timestamp()))),
            }
        )

    return {
        "Event": {
            "uuid": event_uuid,
            "info": "ALIBI 1.0 Planetary Threat Intelligence Feed (Real 2026 Telemetry)",
            "date": event_date,
            "threat_level_id": "2",  # Medium/High
            "analysis": "2",  # Completed
            "distribution": "3",  # All communities
            "Attribute": attributes,
        }
    }


def to_blocklist(limit: int = 1000) -> str:
    """Export threat indicators as a clean plaintext IP blocklist."""
    indicators = _get_indicators(limit)
    m = meta()
    lines = [
        "# ALIBI Planetary Threat Intelligence Blocklist",
        f"# As of: {m.get('fetched_at', '2026')}",
        "# Source: Verified 2026 telemetry (abuse.ch Feodo, ThreatFox, URLhaus)",
        "# License: MIT / Open Access (https://github.com/UtkarshOver9000/alibi)",
        f"# Total indicators in export: {len(indicators)}",
        "",
    ]
    lines.extend(ip for ip, _ in indicators)
    lines.append("")
    return "\n".join(lines)


def to_nftables(limit: int = 1000) -> str:
    """Export threat indicators as a drop-in Linux nftables ruleset."""
    indicators = _get_indicators(limit)
    m = meta()
    elements = ",\n        ".join(ip for ip, _ in indicators)
    return f"""# ALIBI Linux nftables Threat Denylist
# Generated: {m.get("fetched_at", "2026")}
# Drop-in usage: nft -f alibi_denylist.nft

table inet filter {{
    set alibi_threat_nodes {{
        type ipv4_addr
        flags interval
        elements = {{
        {elements}
        }}
    }}

    chain input {{
        type filter hook input priority -10; policy accept;
        ip saddr @alibi_threat_nodes counter drop
    }}
}}
"""


def to_suricata(limit: int = 250) -> str:
    """Export threat indicators as Suricata / Snort IDS rules."""
    indicators = _get_indicators(limit)
    rules = [
        "# ALIBI Suricata / Snort IDS Rules",
        "# Real 2026 Telemetry - abuse.ch Feodo, ThreatFox, URLhaus",
        "",
    ]
    base_sid = 9000000
    for i, (ip, data) in enumerate(indicators):
        sid = base_sid + i
        malware = data.get("malware", "Unknown")
        what = data.get("what", "C2 Server")
        rule = (
            f"alert ip $EXTERNAL_NET any -> $HOME_NET any ("
            f'msg:"ALIBI Hostile Node Detected [{ip}] [{malware} {what}]"; '
            f"ip.src == {ip}; classtype:trojan-activity; sid:{sid}; rev:1;)"
        )
        rules.append(rule)
    rules.append("")
    return "\n".join(rules)
