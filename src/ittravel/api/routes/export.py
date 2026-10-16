"""
Threat intelligence export endpoints (STIX 2.1, MISP 2.4, CSV, IP Blocklist, nftables, Suricata).
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Response

from ...intel import export

router = APIRouter()

CACHE_HEADER = {"Cache-Control": "public, max-age=1800"}


@router.get("/v1/intel/export/stix", tags=["Export"])
async def export_stix(limit: int = Query(100, ge=1, le=500)):
    """Export latest active threat indicators as an OASIS STIX 2.1 JSON bundle."""
    return export.to_stix(limit)


@router.get("/v1/intel/export/misp", tags=["Export"])
async def export_misp(limit: int = Query(100, ge=1, le=500)):
    """Export latest active threat indicators as standard MISP 2.4 Event JSON."""
    return export.to_misp(limit)


@router.get("/v1/intel/export/csv", tags=["Export"])
async def export_csv(limit: int = Query(1000, ge=1, le=5000)):
    """Export latest active threat indicators as standard CSV."""
    content = export.to_csv(limit)
    return Response(
        content=content,
        media_type="text/csv",
        headers={**CACHE_HEADER, "Content-Disposition": 'attachment; filename="alibi_indicators.csv"'},
    )


@router.get("/v1/intel/export/blocklist.txt", tags=["Export"])
async def export_blocklist(limit: int = Query(1000, ge=1, le=10000)):
    """Export plain text IP blocklist for firewall / proxy integration."""
    content = export.to_blocklist(limit)
    return Response(content=content, media_type="text/plain", headers=CACHE_HEADER)


@router.get("/v1/intel/export/nftables", tags=["Export"])
async def export_nftables(limit: int = Query(1000, ge=1, le=10000)):
    """Export drop-in Linux nftables ruleset."""
    content = export.to_nftables(limit)
    return Response(content=content, media_type="text/plain", headers=CACHE_HEADER)


@router.get("/v1/intel/export/suricata", tags=["Export"])
async def export_suricata(limit: int = Query(250, ge=1, le=1000)):
    """Export Suricata / Snort IDS rules for network perimeter detection."""
    content = export.to_suricata(limit)
    return Response(content=content, media_type="text/plain", headers=CACHE_HEADER)
