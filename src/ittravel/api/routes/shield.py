"""
Protective DNS Shield route (DGA detection + domain blocklist check + RFC 8484 DNS-over-HTTPS).
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, Query, Request, Response

from ...intel.dns_shield import evaluate_domain, handle_wire_query

router = APIRouter()


@router.get("/v1/shield/check", tags=["DNS Shield"])
async def dns_shield_check(domain: str = Query(..., min_length=3, max_length=253, description="Domain to inspect")):
    """Check a domain against ThreatFox/URLhaus feeds and ML-based DGA entropy scoring.
    Returns whether the domain would be allowed or sinkholed to 0.0.0.0."""
    return evaluate_domain(domain)


@router.get("/dns-query", tags=["DNS Shield"])
async def doh_query_get(
    request: Request,
    dns: str | None = Query(None, description="Base64url-encoded DNS wire query (RFC 8484)"),
    name: str | None = Query(None, description="Domain name for JSON DoH query"),
    type: str = Query("A", description="DNS record type"),
):
    """RFC 8484 DNS-over-HTTPS GET handler. Supports binary wire format (?dns=...) and JSON format (?name=...)."""
    if dns:
        # Base64url decode with padding
        padding = "=" * ((4 - len(dns) % 4) % 4)
        try:
            query_bytes = base64.urlsafe_b64decode(dns + padding)
        except Exception:
            return Response(content=b"Invalid base64url query", status_code=400)
        resp_bytes, _ = handle_wire_query(query_bytes)
        return Response(content=resp_bytes, media_type="application/dns-message")

    if name:
        eval_res = evaluate_domain(name)
        is_sinkhole = eval_res.get("status") == "BLOCKED"
        resolved = eval_res.get("resolved_ips", ["0.0.0.0" if is_sinkhole else "127.0.0.1"])
        ans_ip = "0.0.0.0" if is_sinkhole else (resolved[0] if resolved[0] != "NXDOMAIN" else "0.0.0.0")
        return {
            "Status": 0,
            "TC": False,
            "RD": True,
            "RA": True,
            "AD": False,
            "CD": False,
            "Question": [{"name": f"{name.rstrip('.')}.", "type": 1}],
            "Answer": [{"name": f"{name.rstrip('.')}.", "type": 1, "TTL": 60, "data": ans_ip}],
            "alibi_verdict": eval_res.get("action", "RESOLVED"),
            "alibi_reason": eval_res.get("reason", "Clean"),
        }

    return Response(content=b"Missing ?dns or ?name parameter", status_code=400)


@router.post("/dns-query", tags=["DNS Shield"])
async def doh_query_post(request: Request) -> Response:
    """RFC 8484 DNS-over-HTTPS POST wire-format handler. Accepts application/dns-message."""
    body = await request.body()
    if not body:
        return Response(content=b"Empty DNS message body", status_code=400)
    resp_bytes, _ = handle_wire_query(body)
    return Response(content=resp_bytes, media_type="application/dns-message")
