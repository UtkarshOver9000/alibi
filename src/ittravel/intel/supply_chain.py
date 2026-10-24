"""
Open-Source Supply Chain Analyzer (Pillar 6).

Real API calls for ANY package in any ecosystem:
- Google deps.dev v3alpha: package metadata, versions, licenses, dependency counts
- OSV.dev: CVE/advisory lookup for any package version
Returns exact fields the JS dashboard expects.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

_UA = "Alibi-SupplyChain/1.0 (+https://github.com/UtkarshOver9000/alibi)"

ECOSYSTEM_MAP = {
    "pypi": "pypi",
    "python": "pypi",
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "go": "go",
    "golang": "go",
    "cargo": "cargo",
    "rust": "cargo",
    "maven": "maven",
    "java": "maven",
    "nuget": "nuget",
    "csharp": "nuget",
    "dotnet": "nuget",
    "hex": "hex",
    "elixir": "hex",
    "pub": "pub",
    "dart": "pub",
    "rubygems": "rubygems",
    "ruby": "rubygems",
}

# Maps deps.dev ecosystem name to OSV ecosystem name
OSV_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "pub": "Pub",
    "hex": "Hex",
}


def _deps_dev_package(eco: str, name: str) -> dict[str, Any]:
    """Fetch package metadata from deps.dev v3alpha (no key needed)."""
    if os.getenv("ALIBI_OFFLINE"):
        return {}
    encoded = urllib.parse.quote(name, safe="")
    # Use v3alpha endpoint which is stable and key-free
    url = f"https://api.deps.dev/v3alpha/systems/{eco}/packages/{encoded}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _deps_dev_version(eco: str, name: str, version: str) -> dict[str, Any]:
    """Fetch a specific version's metadata from deps.dev."""
    if os.getenv("ALIBI_OFFLINE"):
        return {}
    encoded_name = urllib.parse.quote(name, safe="")
    encoded_ver = urllib.parse.quote(version, safe="")
    url = f"https://api.deps.dev/v3alpha/systems/{eco}/packages/{encoded_name}/versions/{encoded_ver}"
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=4.0) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return {}


def _osv_query(name: str, eco: str, version: str | None = None) -> list[dict[str, Any]]:
    """Query OSV.dev for real CVEs/advisories for a package (any version or latest)."""
    if os.getenv("ALIBI_OFFLINE"):
        return []
    osv_eco = OSV_ECOSYSTEM.get(eco, "PyPI")
    pkg_obj: dict[str, Any] = {"name": name, "ecosystem": osv_eco}
    payload_dict: dict[str, Any] = {"package": pkg_obj}
    if version:
        payload_dict["version"] = version
    payload = json.dumps(payload_dict).encode()
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": _UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=5.0) as r:
            res = json.loads(r.read().decode("utf-8", errors="replace"))
            vulns = []
            for v in res.get("vulns", [])[:15]:
                # Determine worst severity
                severity = "UNKNOWN"
                for sev_entry in v.get("severity", []):
                    score = sev_entry.get("score", "")
                    # CVSS score strings like "CVSS:3.1/AV:N/..." or just a numeric
                    if "CRITICAL" in str(score).upper():
                        severity = "CRITICAL"
                    elif "HIGH" in str(score).upper() and severity != "CRITICAL":
                        severity = "HIGH"
                    elif "MEDIUM" in str(score).upper() and severity not in ("CRITICAL", "HIGH"):
                        severity = "MEDIUM"
                cvss_score = None
                db_specifics = v.get("database_specific", {})
                if db_specifics.get("cvss"):
                    cvss_score = db_specifics["cvss"]
                # Extract affected version ranges
                ranges: list[str] = []
                for aff in v.get("affected", []):
                    for rng in aff.get("ranges", []):
                        for evt in rng.get("events", []):
                            if evt.get("introduced"):
                                ranges.append(f">={evt['introduced']}")
                            if evt.get("fixed"):
                                ranges.append(f"<{evt['fixed']}")

                vulns.append(
                    {
                        "id": v.get("id"),
                        "summary": v.get("summary", "Security advisory published")[:200],
                        "details": (v.get("details") or "")[:300],
                        "published": v.get("published"),
                        "modified": v.get("modified"),
                        "severity": severity,
                        "cvss": cvss_score,
                        "aliases": v.get("aliases", [])[:5],
                        "affected_ranges": ranges[:6],
                        "references": [r2.get("url") for r2 in v.get("references", [])[:3] if r2.get("url")],
                    }
                )
            return vulns
    except Exception:
        return []


def analyze_package(package_name: str, ecosystem: str = "pypi") -> dict[str, Any]:
    """
    Full supply chain analysis for ANY package in ANY ecosystem.
    Calls deps.dev for metadata and OSV for real CVE/advisory data.
    """
    package_name = package_name.strip()
    eco = ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem.lower())

    if not package_name:
        return {"error": "Package name required"}

    # --- 1. deps.dev package metadata ---
    pkg_data = _deps_dev_package(eco, package_name)
    versions_raw = pkg_data.get("versions", [])

    # Sort versions; pick latest default version if marked, else last in list
    latest_version = "unknown"
    total_versions = len(versions_raw)
    for v in reversed(versions_raw):
        vk = v.get("versionKey", {})
        if vk.get("version"):
            latest_version = vk["version"]
            break

    # --- 2. Version-level detail (licenses, links) ---
    ver_detail: dict[str, Any] = {}
    if latest_version != "unknown":
        ver_detail = _deps_dev_version(eco, package_name, latest_version)

    # Collect licenses from version detail or package-level
    licenses: list[str] = []
    for lic in ver_detail.get("licenses", []):
        if isinstance(lic, str) and lic not in licenses:
            licenses.append(lic)
    if not licenses:
        for v in versions_raw[-3:]:
            for lic in v.get("licenses", []):
                if isinstance(lic, str) and lic not in licenses:
                    licenses.append(lic)

    has_copyleft = any(any(c in lic.upper() for c in ("GPL", "AGPL", "LGPL")) for lic in licenses)
    if has_copyleft:
        license_risk = "HIGH (Copyleft — GPL/AGPL)"
    elif licenses:
        license_risk = "LOW (Permissive)"
    else:
        license_risk = "UNKNOWN (Unlicensed or not declared)"

    # Dependency count
    dep_count = ver_detail.get("dependencyCount", {}).get("direct", 0)

    # Links (homepage, source, docs)
    links: list[dict[str, str]] = []
    for lnk in ver_detail.get("links", []) or pkg_data.get("links", []):
        if lnk.get("url"):
            links.append({"label": lnk.get("label", "link"), "url": lnk["url"]})

    # --- 3. OSV vulnerability scan ---
    vulns = _osv_query(package_name, eco, latest_version if latest_version != "unknown" else None)

    # Determine overall security status
    if any(v.get("severity") == "CRITICAL" for v in vulns):
        security_status = "CRITICAL"
    elif any(v.get("severity") == "HIGH" for v in vulns):
        security_status = "VULNERABLE"
    elif vulns:
        security_status = "VULNERABLE"
    else:
        security_status = "CLEAN"

    # --- 4. Package registry URL ---
    registry_url = {
        "pypi": f"https://pypi.org/project/{package_name}/",
        "npm": f"https://www.npmjs.com/package/{package_name}",
        "go": f"https://pkg.go.dev/{package_name}",
        "cargo": f"https://crates.io/crates/{package_name}",
        "maven": f"https://search.maven.org/search?q={package_name}",
        "nuget": f"https://www.nuget.org/packages/{package_name}/",
        "rubygems": f"https://rubygems.org/gems/{package_name}",
        "pub": f"https://pub.dev/packages/{package_name}",
        "hex": f"https://hex.pm/packages/{package_name}",
    }.get(eco, f"https://deps.dev/{eco}/{urllib.parse.quote(package_name)}")

    # Fallback: if deps.dev returned nothing, OSV still has data
    not_found = total_versions == 0 and not ver_detail
    if not_found and not vulns:
        return {
            "package": package_name,
            "ecosystem": eco,
            "latest_version": "not found",
            "total_versions": 0,
            "licenses": [],
            "has_restrictive_license": False,
            "license_risk": "UNKNOWN",
            "vulnerabilities": [],
            "total_cves": 0,
            "security_status": "UNKNOWN — package not found in deps.dev",
            "direct_dependencies": 0,
            "registry_url": registry_url,
            "source": "Google deps.dev + OSV.dev",
        }

    return {
        "package": package_name,
        "ecosystem": eco,
        "latest_version": latest_version,
        "total_versions": total_versions,
        "licenses": licenses or ["Not declared"],
        "has_restrictive_license": has_copyleft,
        "license_risk": license_risk,
        "vulnerabilities": vulns,
        "total_cves": len(vulns),
        "security_status": security_status,
        "direct_dependencies": dep_count,
        "links": links[:8],
        "registry_url": registry_url,
        "source": "Google deps.dev + OSV.dev (Open Source Vulnerabilities)",
    }
