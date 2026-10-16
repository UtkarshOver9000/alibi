"""
OASIS TAXII 2.1 (Trusted Automated Exchange of Intelligence Information) Read-Only Server.
Specification: OASIS Committee Specification 01 (TAXII Version 2.1).
Serves STIX 2.1 threat intelligence bundles to SIEMs (Splunk, Sentinel, QRadar, Cortex XSOAR).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from ...intel.export import to_stix

router = APIRouter()

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

COLLECTIONS: list[dict[str, Any]] = [
    {
        "id": "alibi-c2-malware",
        "title": "Active Malware Command & Control Hosts",
        "description": "Continuous real-time C2 and botnet distribution nodes from verified 2026 feeds.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "alibi-drop-networks",
        "title": "Spamhaus DROP Criminal Networks",
        "description": "Criminal-operated and hijacked BGP IP networks and subnets.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
    {
        "id": "alibi-exploited-flaws",
        "title": "CISA Known Exploited Vulnerabilities",
        "description": "Vulnerabilities weaponized in active campaigns and ransomware attacks.",
        "can_read": True,
        "can_write": False,
        "media_types": ["application/stix+json;version=2.1"],
    },
]


@router.get("/taxii2/", tags=["TAXII 2.1"])
async def taxii_server_discovery():
    """TAXII 2.1 Server Discovery endpoint."""
    return {
        "title": "Alibi 1.0 Planetary Threat Terminal TAXII 2.1 Server",
        "description": "Open-source planetary cyber defense and threat telemetry exchange.",
        "contact": "support@alibi-intel.org",
        "default": "/taxii2/v21/",
        "api_roots": ["/taxii2/v21/"],
    }


@router.get("/taxii2/v21/", tags=["TAXII 2.1"])
async def taxii_api_root():
    """TAXII 2.1 API Root Information."""
    return {
        "title": "Alibi 1.0 Global Intelligence Root",
        "description": "Real-time threat intelligence feeds in STIX 2.1 format.",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 10485760,
    }


@router.get("/taxii2/v21/collections/", tags=["TAXII 2.1"])
async def taxii_collections():
    """List available threat intelligence collections."""
    return {"collections": COLLECTIONS}


@router.get("/taxii2/v21/collections/{collection_id}/", tags=["TAXII 2.1"])
async def taxii_collection_detail(collection_id: str):
    """Get metadata for a specific TAXII collection."""
    col = next((c for c in COLLECTIONS if c["id"] == collection_id), None)
    if not col:
        raise HTTPException(status_code=404, detail="TAXII Collection Not Found")
    return col


@router.get("/taxii2/v21/collections/{collection_id}/objects/", tags=["TAXII 2.1"])
async def taxii_collection_objects(collection_id: str, limit: int = 100):
    """Fetch STIX 2.1 objects from a TAXII collection."""
    col = next((c for c in COLLECTIONS if c["id"] == collection_id), None)
    if not col:
        raise HTTPException(status_code=404, detail="TAXII Collection Not Found")
    bundle_data = to_stix(limit=min(limit, 500))
    return bundle_data


@router.get("/taxii2/v21/collections/{collection_id}/manifest/", tags=["TAXII 2.1"])
async def taxii_collection_manifest(collection_id: str, limit: int = 100):
    """Fetch manifest of object IDs and metadata in collection."""
    col = next((c for c in COLLECTIONS if c["id"] == collection_id), None)
    if not col:
        raise HTTPException(status_code=404, detail="TAXII Collection Not Found")
    bundle_data = to_stix(limit=min(limit, 500))
    objects = bundle_data.get("objects", [])
    manifest_records = [
        {
            "id": obj.get("id"),
            "date_added": obj.get("created", "2026-01-01T00:00:00.000Z"),
            "version": obj.get("modified", "2026-01-01T00:00:00.000Z"),
            "media_types": ["application/stix+json;version=2.1"],
        }
        for obj in objects
    ]
    return {"objects": manifest_records}
