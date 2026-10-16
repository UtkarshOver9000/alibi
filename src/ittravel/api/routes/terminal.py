"""
Tech Bloomberg Terminal & Live Footprint API routes.
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request

from ...intel.terminal import company_dossier, live_footprint

router = APIRouter()


@router.get("/v1/terminal/company", tags=["Tech Terminal"])
async def get_company_terminal(
    q: str = Query(..., min_length=2, max_length=120, description="Company name, domain, or ASN"),
):
    """Compile an open-source Bloomberg-style tech dossier on any company, domain, or technology."""
    return company_dossier(q)


@router.get("/v1/terminal/footprint", tags=["Live Footprint"])
async def get_live_footprint(
    request: Request,
    ip: str = Query(None, description="IP address to audit; defaults to client IP"),
):
    """Audit the live digital footprint, ISP routing, and tripwire status of an IP address."""
    target_ip = ip
    if not target_ip:
        # Extract client IP safely
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            target_ip = forwarded.split(",")[0].strip()
        elif request.client and request.client.host:
            target_ip = request.client.host
        else:
            target_ip = "1.1.1.1"

    # Avoid private IP failure in local dev
    private_prefixes = ("127.", "192.168.", "10.")
    if target_ip == "::1" or any(target_ip.startswith(p) for p in private_prefixes):
        target_ip = "8.8.8.8"

    return live_footprint(target_ip)
