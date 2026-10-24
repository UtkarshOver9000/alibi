"""
Black October (October 2026) API Routes.
Exposes forensic autopsies, interactive exploit mechanics, live stack audits,
and 60-second emergency remediations for all 27 critical incidents.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from ...intel import black_october

router = APIRouter(prefix="/v1/black-october", tags=["Black October Crisis"])


class AuditRequest(BaseModel):
    target: str
    target_type: str = "domain"  # "domain" | "package" | "ip"


@router.get("/overview")
async def get_overview():
    """Retrieve the high-level catastrophe overview, severity matrix, and 27 incident dossiers."""
    return black_october.get_black_october_overview()


@router.get("/incident/{incident_id}")
async def get_incident(incident_id: str):
    """Retrieve detailed forensic autopsy and exploit mechanics for a specific Black October incident."""
    autopsy = black_october.get_incident_autopsy(incident_id)
    if not autopsy:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found in Black October database.")
    return autopsy


@router.get("/audit")
async def audit_get(
    target: str = Query(..., min_length=1, max_length=150, description="Target domain, IP, or package name"),
    target_type: str = Query("domain", pattern="^(domain|package|ip)$"),
):
    """Run real-time 1-click audit of any domain, IP, or package against Black October vulnerabilities."""
    return black_october.audit_black_october_target(target, target_type)


@router.post("/audit")
async def audit_post(payload: AuditRequest):
    """POST endpoint for auditing a domain, IP, or package against Black October vectors."""
    return black_october.audit_black_october_target(payload.target, payload.target_type)


@router.get("/remediate/{incident_id}")
async def get_remediation(incident_id: str):
    """Retrieve 60-second shell command, WAF mitigation rule, and hardening steps for an incident."""
    autopsy = black_october.get_incident_autopsy(incident_id)
    if not autopsy:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return {
        "incident_id": incident_id,
        "name": autopsy["name"],
        "cve": autopsy.get("cve"),
        "mitigation_shell_command": autopsy["mitigation"],
        "waf_rule": autopsy.get("waf_rule"),
        "alibi_fix_summary": autopsy["alibi_fix"],
    }
