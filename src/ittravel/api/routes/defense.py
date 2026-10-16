"""
Defense, Supply Chain, Canary, and Compute Atlas API routes (Pillars 5 through 10).
"""

from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response

from ...intel import canary, compute_atlas, disruptions, leak_hunter, remediation, supply_chain

router = APIRouter()


# Pillar 5: BGP Routing & Internet Disruption Radar
@router.get("/v1/intel/disruptions", tags=["Defense & Disruptions"])
async def intel_disruptions():
    """Real-time global internet outages, BGP anomalies, and cable disruptions (IODA + OONI)."""
    return disruptions.get_disruptions_overview()


# Pillar 6: Open-Source Supply Chain Analyzer
@router.get("/v1/supply-chain/analyze", tags=["Supply Chain"])
async def analyze_supply_chain(
    package: str = Query(..., min_length=1, max_length=150),
    ecosystem: str = Query("pypi", pattern="^(pypi|npm|go|cargo|maven)$"),
):
    """Analyze open-source software supply chain risk, dependencies, licenses, and CVEs (deps.dev + OSV)."""
    return supply_chain.analyze_package(package, ecosystem)


# Pillar 7: Corporate Breach & Leak Hunter
@router.get("/v1/terminal/leak-hunter", tags=["Leak Hunter"])
async def leak_hunter_domain(domain: str = Query(..., min_length=2, max_length=150)):
    """Audit corporate domain breach exposure and ransomware extortion claims (HIBP + RansomLook)."""
    return leak_hunter.corporate_leak_audit(domain)


@router.get("/v1/terminal/pwned-password", tags=["Leak Hunter"])
async def pwned_password_check(prefix: str = Query(..., min_length=5, max_length=5)):
    """Check SHA-1 password prefix with strict k-anonymity (zero raw passwords transmitted)."""
    return leak_hunter.check_password_hash_k_anonymity(prefix)


# Pillar 8: Canary Token & Hacker Tripwire
@router.post("/v1/canary/generate", tags=["Canary Tripwire"])
async def generate_canary_token(kind: str = Query("webhook"), memo: str = Query("Decoy credential")):
    """Generate a 1-click canary decoy asset (AWS keys, DB URI, tracked beacon)."""
    return canary.generate_canary(kind, memo)


@router.get("/v1/canary/trip/{token}", tags=["Canary Tripwire"])
async def trip_canary(token: str, request: Request):
    """Tripwire alarm beacon endpoint. Logs intruder IP, ASN, and user-agent; returns 1x1 GIF."""
    ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Unknown")
    canary.record_trip(token, ip, ua)
    return Response(content=canary.PIXEL_GIF, media_type="image/gif")


@router.get("/v1/canary/alarms", tags=["Canary Tripwire"])
async def get_canary_alarms():
    """Fetch recent intruder tripwire detections."""
    return {"alarms": canary.get_alarms()}


# Pillar 9: AI Plain-English Remediation Engine
@router.get("/v1/remediation/explain", tags=["Remediation"])
async def remediate_finding(
    type: str = Query(..., pattern="^(cve|ip|dga)$"),
    target: str = Query(..., min_length=1, max_length=150),
    entropy: float = Query(0.0),
):
    """Generate deterministic 3-bullet executive cards and exact 60-second shell fixes for any threat."""
    if type == "cve":
        return remediation.remediate_cve(target)
    elif type == "ip":
        return remediation.remediate_ip(target)
    else:
        return remediation.remediate_dga(target, entropy)


# Pillar 10: Global AI & Compute Infrastructure Atlas
@router.get("/v1/intel/compute-atlas", tags=["Compute Atlas"])
async def compute_atlas_overview():
    """Geospatial directory of hyperscaler AI supercomputing clusters, semiconductor fabs, and subsea interlinks."""
    return compute_atlas.get_compute_atlas()
