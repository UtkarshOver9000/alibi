"""
Prometheus Metrics Route (/metrics) for enterprise observability.
Exposes standard Prometheus text exposition format (RFC 8967) for Prometheus, Grafana, Datadog.
"""

from __future__ import annotations

from fastapi import APIRouter, Response

from ...intel import canary, compute_atlas, disruptions, service

router = APIRouter()


@router.get("/metrics", tags=["Observability"])
async def prometheus_metrics():
    """Prometheus exposition metrics for platform health, threat indicators, and canary tripwires."""
    lines: list[str] = [
        "# HELP alibi_up Alibi threat platform operational status (1 = healthy)",
        "# TYPE alibi_up gauge",
        "alibi_up 1",
    ]

    try:
        bad_ips = service._load("bad_ips.json")
        lines.extend(
            [
                "# HELP alibi_bad_ips_total Total active malicious IPs tracked in live snapshot",
                "# TYPE alibi_bad_ips_total gauge",
                f"alibi_bad_ips_total {len(bad_ips)}",
            ]
        )
    except Exception:
        pass

    try:
        kev_flaws = service._load("flaws.json")
        lines.extend(
            [
                "# HELP alibi_exploited_flaws_total CISA KEV actively exploited vulnerabilities tracked",
                "# TYPE alibi_exploited_flaws_total gauge",
                f"alibi_exploited_flaws_total {len(kev_flaws)}",
            ]
        )
    except Exception:
        pass

    try:
        alarms = canary.get_alarms()
        tokens = canary.get_tokens()
        lines.extend(
            [
                "# HELP alibi_canary_tokens_active Total deployed canary decoy tripwires",
                "# TYPE alibi_canary_tokens_active gauge",
                f"alibi_canary_tokens_active {len(tokens)}",
                "# HELP alibi_canary_alarms_total Total intrusion tripwires triggered by adversaries",
                "# TYPE alibi_canary_alarms_total counter",
                f"alibi_canary_alarms_total {len(alarms)}",
            ]
        )
    except Exception:
        pass

    try:
        disr = disruptions.get_disruptions_overview()
        lines.extend(
            [
                "# HELP alibi_active_disruptions Total active planetary BGP outages & internet blackouts",
                "# TYPE alibi_active_disruptions gauge",
                f"alibi_active_disruptions {len(disr.get('active_disruptions', []))}",
            ]
        )
    except Exception:
        pass

    try:
        atlas = compute_atlas.get_compute_atlas()
        lines.extend(
            [
                "# HELP alibi_compute_clusters_tracked Global AI supercomputing clusters and fabs mapped",
                "# TYPE alibi_compute_clusters_tracked gauge",
                f"alibi_compute_clusters_tracked {atlas.get('total_clusters', 0)}",
            ]
        )
    except Exception:
        pass

    lines.append("")
    return Response(content="\n".join(lines), media_type="text/plain; version=0.0.4; charset=utf-8")
