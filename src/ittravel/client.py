"""
ALIBI Python Client Library (`alibi-client`).
Lightweight, typed SDK for interacting with the ALIBI Planetary Threat & Defense Terminal API.
Zero hard dependencies (uses standard library `urllib.request` with optional `httpx` acceleration).
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any


class AlibiClientError(Exception):
    """Raised when an ALIBI API call fails."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"ALIBI API error {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class AlibiClient:
    """Client for querying the ALIBI Planetary Tech & Defense API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _get(self, path: str, params: dict[str, Any] | None = None, is_json: bool = True) -> Any:
        url = f"{self.base_url}{path}"
        if params:
            query_str = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
            url = f"{url}?{query_str}"

        headers = {
            "User-Agent": "Alibi-Python-Client/1.0 (+https://github.com/UtkarshOver9000/alibi)",
            "Accept": "application/json" if is_json else "*/*",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data) if is_json else data
        except urllib.error.HTTPError as exc:
            err_msg = exc.read().decode("utf-8", errors="replace")
            raise AlibiClientError(exc.code, err_msg) from exc
        except Exception as exc:
            raise AlibiClientError(500, str(exc)) from exc

    def company_dossier(self, query: str) -> dict[str, Any]:
        """Compile a Bloomberg-style security & tech dossier for a company, domain, or ASN."""
        return self._get("/v1/terminal/company", {"q": query})

    def live_footprint(self, ip: str) -> dict[str, Any]:
        """Audit an IP against threat feeds, Tor exits, hosting subnets, and subsea cables."""
        return self._get("/v1/terminal/footprint", {"ip": ip})

    def shield_check(self, domain: str) -> dict[str, Any]:
        """Check domain with Shannon entropy DGA scoring and sinkhole protection."""
        return self._get("/v1/shield/check", {"domain": domain})

    def state_dossier(self, state_or_code: str) -> dict[str, Any]:
        """Fetch threat density, malware C2 nodes, and censorship metrics for a state/province."""
        code_encoded = urllib.parse.quote(state_or_code)
        return self._get(f"/v1/intel/state/{code_encoded}")

    def overview(self) -> dict[str, Any]:
        """Fetch headline numbers across all active feeds."""
        return self._get("/v1/intel/overview")

    def search(self, query: str) -> dict[str, Any]:
        """Unified search across IPs, CVEs, companies, and domains."""
        return self._get("/v1/intel/search", {"q": query})

    def ip_lookup(self, ip: str) -> dict[str, Any]:
        """Lookup ASN, carrier, and hosting/Tor flags for an IP address."""
        return self._get(f"/v1/intel/ip/{ip}")

    def ip_stix(self, ip: str) -> dict[str, Any]:
        """Export per-IP STIX 2.1 observable bundle."""
        return self._get(f"/v1/intel/ip/{ip}/stix")

    def export_stix(self, limit: int = 100) -> dict[str, Any]:
        """Export latest active threat indicators as an OASIS STIX 2.1 bundle."""
        return self._get("/v1/intel/export/stix", {"limit": limit})

    def export_misp(self, limit: int = 100) -> dict[str, Any]:
        """Export latest active threat indicators as standard MISP 2.4 Event JSON."""
        return self._get("/v1/intel/export/misp", {"limit": limit})

    def export_csv(self, limit: int = 1000) -> str:
        """Export latest threat indicators as CSV string."""
        return self._get("/v1/intel/export/csv", {"limit": limit}, is_json=False)

    def export_blocklist(self, limit: int = 1000) -> str:
        """Export plaintext IP blocklist for firewall and proxy ingestion."""
        return self._get("/v1/intel/export/blocklist.txt", {"limit": limit}, is_json=False)

    def export_nftables(self, limit: int = 1000) -> str:
        """Export drop-in Linux nftables packet filter ruleset."""
        return self._get("/v1/intel/export/nftables", {"limit": limit}, is_json=False)

    def export_suricata(self, limit: int = 250) -> str:
        """Export Suricata / Snort IDS perimeter detection rules."""
        return self._get("/v1/intel/export/suricata", {"limit": limit}, is_json=False)

    def health(self) -> dict[str, Any]:
        """Check feed freshness and system health status."""
        return self._get("/v1/health")
