"""
Protective DNS Shield route (DGA detection + domain blocklist check).
"""

from __future__ import annotations

from fastapi import APIRouter, Query

from ...intel.dns_shield import evaluate_domain

router = APIRouter()


@router.get("/v1/shield/check", tags=["DNS Shield"])
async def dns_shield_check(domain: str = Query(..., min_length=3, max_length=253, description="Domain to inspect")):
    """Check a domain against ThreatFox/URLhaus feeds and ML-based DGA entropy scoring.
    Returns whether the domain would be allowed or sinkholed to 0.0.0.0."""
    return evaluate_domain(domain)
