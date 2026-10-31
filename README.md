<p align="center"><img src="docs/img/logo.svg" width="132" alt="Alibi logo: planetary cyber intelligence terminal"></p>

# ALIBI 1.0: Planetary Tech & Defense Terminal

[![CI](https://github.com/UtkarshOver9000/alibi/actions/workflows/ci.yml/badge.svg)](https://github.com/UtkarshOver9000/alibi/actions/workflows/ci.yml)
[![Refresh](https://github.com/UtkarshOver9000/alibi/actions/workflows/refresh-intel.yml/badge.svg)](https://github.com/UtkarshOver9000/alibi/actions/workflows/refresh-intel.yml)
[![Uptime](https://github.com/UtkarshOver9000/alibi/actions/workflows/uptime.yml/badge.svg)](https://github.com/UtkarshOver9000/alibi/actions/workflows/uptime.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **ALIBI is the open-source planetary intelligence terminal for engineers — a free, real-data alternative to Palantir's God's Eye view and Bloomberg's $30,000/year corporate terminal.**

---

## The Core Promise

- **100% Real 2026 Data.** Zero synthetic records. Zero honeypot approximations. Zero outdated static datasets.
- **Free Forever.** Open-source MIT license.
- **Built for Engineers & Leaders:** Ethical hackers, DevOps/cloud architects, ML engineers, and technical leadership.

---

## Core Pillars (Alibi 1.0)

### 1. 🌐 God's Eye 3D Planetary Radar
A full-screen 3D WebGL Earth (NASA Blue Marble) mapping all **4,596 world states and provinces**:
- **Active Malware C2 & Botnets:** Live botnet controllers and malware distribution points (abuse.ch Feodo, ThreatFox, URLhaus) mapped via DB-IP.
- **Censorship & Internet Interference:** Confirmed web blocks and tampering telemetry from OONI Explorer.
- **Submarine Cable Infrastructure:** 733 global undersea fiber-optic cable routes and landing stations (TeleGeography).
- **State Cyber Threat Density Score:** Hostile nodes per million IP addresses.

### 2. 💼 Open-Source Tech Bloomberg Terminal
Search any company, domain, or technology (`Cloudflare`, `CrowdStrike`, `Stripe`, `your-org.com`):
- **Corporate Cloud Footprint:** BGP ASNs, upstream ISPs, and network ranges.
- **Attack Surface Discovery:** Real-time Certificate Transparency log enumeration (`crt.sh`) for subdomains.
- **Exploited Flaws & Weaponization:** CISA Known Exploited Vulnerabilities (KEV) cross-referenced with FIRST EPSS exploit probabilities.
- **Breach History:** Have I Been Pwned breach archives with total accounts exposed and leaked data types.
- **Ransomware Watch:** Active extortion claims from RansomLook.
- **Security Health Grade (A–F):** 100-point posture scoring with an executive summary.

### 3. ⚡ Live Personal Footprint & Hacker Tripwire
Real-time network diagnostic for any client or target IP:
- **Routing & ASN Intelligence:** Upstream carrier, ASN classification (residential ISP vs cloud hosting / VPN vs Tor exit).
- **Threat Feed Interception:** Instant check against abuse.ch threat lists and Spamhaus DROP criminal network blocks.
- **Subsea Infrastructure Adjacency:** Nearest physical undersea cable landing station.
- **Tripwire Diagnostic:** Flags connections routing through malicious subnets, hostile anonymizers, or compromised nodes.

### 4. 🛡️ Active Protective DNS Shield & RFC 8484 DoH
Protective DNS endpoint with machine learning DGA detection and DNS-over-HTTPS:
- **DGA Botnet Entropy Scorer:** Shannon entropy scoring flags algorithmic botnet domains (entropy > 3.65 on domain labels).
- **Instant Sinkhole Response:** Sinkholes confirmed malware C2 and phishing domains to `0.0.0.0` in <15ms.
- **RFC 8484 Standard:** Full binary wire format (`application/dns-message`) and JSON DoH at `/dns-query`.

### 5. 📡 Planetary BGP & Internet Disruption Radar
Real-time macro-level internet blackout and outage telemetry:
- **CAIDA IODA & RIPE RIS:** Monitors routing table withdrawals, BGP leaks, and country-scale transit anomalies.
- **Impact Analysis:** Severity scoring, transit volume loss percentage, and affected ASNs.

### 6. 📦 Open-Source Supply Chain Analyzer
Deep package dependency and license audit via Google deps.dev & OSV.dev:
- **Multi-Ecosystem:** PyPI, npm, Go, Cargo (Rust), and Maven (Java).
- **Vulnerability Mapping:** Direct correlation with published OSV and GHSA security advisories.
- **License Risk Analysis:** Detects copyleft / restrictive licenses (AGPL, GPL, LGPL) vs permissive licenses.

### 7. 🕵️ Corporate Breach & Credential Leak Hunter
Audit domain employee breach exposures and credential safety:
- **Zero-Knowledge k-Anonymity:** Hashes passwords client-side via SHA-1; only transmits the 5-character prefix (never transmits plaintext or full hashes).
- **Ransomware Extortion Tracking:** Cross-references corporate domains against active ransomware gang extortion catalogs.

### 8. 🪤 Canary Tokens & Hacker Tripwires
Deploy deceptive decoy assets into private git repos, configuration files, and databases:
- **Decoy Formats:** Fake AWS IAM access keys (`.aws/credentials`), Postgres database URIs, and 1x1 tracking beacons.
- **Instant Intrusion Alarms:** Captures intruder IP, ASN, carrier, reverse geolocation, and user-agent the instant a token is probed.

### 9. 🤖 AI Plain-English Defense Remediation Engine
Deterministic, actionable mitigations for CVEs, malicious IPs, and DGA botnets:
- **3-Bullet Executive Card:** What happened, Who is impacted, What to do right now.
- **60-Second Shell Fixes:** Drop-in shell commands for `iptables`, `nftables`, Suricata, and Windows Firewall.

### 10. 🏭 Global AI & Compute Infrastructure Atlas
Planetary geospatial registry of frontier computing hubs:
- **Hyperscaler Superclusters:** AWS US-East, GCP Council Bluffs, Azure Boydton, Meta Prineville, OCI Abilene.
- **Semiconductor Fabs:** TSMC Tainan, ASML Veldhoven, Intel Chandler.
- **Integrated Globe Layer:** Visualized directly on the 3D planetary globe.

---

## Open Protocols & Standards

| Standard | Endpoint | Description |
|:---|:---|:---|
| **OASIS TAXII 2.1** | `/taxii2/`, `/taxii2/v21/collections/` | Industry standard threat intelligence sharing for SIEMs |
| **OASIS STIX 2.1** | `/v1/intel/export/stix` | Complete STIX 2.1 JSON indicator bundle |
| **MISP 2.4** | `/v1/intel/export/misp` | Standard MISP Event JSON export |
| **RFC 8484 DoH** | `/dns-query` | DNS-over-HTTPS binary wire and JSON resolution |
| **Prometheus** | `/metrics` | RFC 8967 text exposition metrics for Grafana / Datadog |
| **Linux nftables** | `/v1/intel/export/nftables` | Drop-in packet filtering ruleset |
| **Suricata / Snort** | `/v1/intel/export/suricata` | Intrusion Detection System perimeter rules |

---

## Python SDK (`AlibiClient`)

ALIBI includes a zero-dependency, type-safe Python client library:

```python
from ittravel import AlibiClient

client = AlibiClient()

# Check IP footprint & threat posture
footprint = client.footprint("1.1.1.1")
print(f"Tier: {footprint.threat_tier}, ASN: {footprint.network.get('asn')}")

# Analyze company tech attack surface
company = client.company_tech("Cloudflare")
print(f"Health Grade: {company.security_grade}, ASNs: {len(company.asns)}")

# Inspect domain via DNS Shield
shield = client.dns_shield("xq7b9kz1m0w8p2r4j6f.biz")
print(f"Verdict: {shield.verdict}, Reason: {shield.dga_reason}")

# Analyze open-source package supply chain
pkg = client.supply_chain("fastapi", ecosystem="pypi")
print(f"Status: {pkg.security_status}, License: {pkg.license_risk}")
```

---

## Real 2026 ThreatFox Network-Risk Model

ALIBI ships with a production-grade machine learning model (`netrisk_model.joblib`) trained on **real 2026 ThreatFox telemetry**:
- **Task:** Predict the risk percentile of any autonomous system (ASN) hosting new malicious infrastructure.
- **ROC-AUC:** **0.964** · **PR-AUC:** **0.941**
- **Evaluation:** Out-of-time evaluation against real-world network routing allocations.
- Detailed metrics, calibration curves, and feature importance available in [`netrisk_card.json`](src/ittravel/artifacts/netrisk_card.json).

---

## Live Numbers

<!-- numbers:start -->
Numbers from the snapshot of **31 October 2026** (the live app shows the current ones):

| Module | Today |
|---|---|
| Breaches | 1,029 breaches, 16.29 billion accounts; 105 breaches and 475.8 million accounts in the last 12 months |
| Attacks | 9,021 malware and botnet servers; 7,126 threat indicators in 48 hours; 447 criminal networks; 265 ransomware victims (24 October 2026 to 31 October 2026) |
| Exploited flaws | 1,766 flaws; 36 added in the last 30 days; 361 used by ransomware; highest exploit chance CVE-2026-109618 at 100.0% |
| Live globe | 4,596 states and provinces, 733 undersea cables, websites confirmed blocked in 76 countries |

**A finding worth knowing:** only 11% of the malware servers sit on hosting or VPN networks, about the same as those networks' 11% share of all addresses; 50% are home routers, cameras and other devices hijacked by botnets such as Mozi and Mirai. Blocking data centers alone misses most of them.
<!-- numbers:end -->

---

## Data Pipeline & Sources

> **Every single number, indicator, and record in ALIBI comes from a verified, publicly available, live 2026 data pipeline.**

<!-- sources:start -->
| Source | Licence / terms | Refreshed | Used for |
|---|---|---|---|
| Have I Been Pwned breach list | CC BY 4.0 (attribution and link required) | daily | Every published breach with its date, size, data types and write-up. |
| CISA Known Exploited Vulnerabilities catalog | US government public data | daily | Vulnerabilities confirmed as exploited in real attacks. |
| FIRST EPSS exploit prediction scores | free to use with attribution to FIRST (Exploit Prediction Scoring System) | daily | Daily probability that each CVE is exploited in the next 30 days. |
| iptoasn.com IP-to-ASN table | PDDL (public domain) | daily | Which network (ASN) and country announce every IPv4 range. |
| public-dns.info nameserver list | public list; only counts and city locations are published | daily | Working public DNS resolvers by country. |
| OONI web-connectivity aggregation, last 30 days | CC BY-NC-SA 4.0 | daily | Censorship tests, anomalies and confirmed blocks per country. |
| abuse.ch Feodo Tracker botnet C2 blocklist | CC0 | daily | Botnet command-and-control servers. |
| abuse.ch URLhaus recent malware URLs | CC0 | daily | Malware download URLs reported in the last 30 days. |
| abuse.ch ThreatFox recent indicators | CC0 | daily | Indicators of compromise shared in the last 48 hours. |
| abuse.ch ThreatFox full export | CC0 | daily | Every indicator ThreatFox still holds (about the last six months) with the day it was first seen; the network-risk model learns from it and scores every network with it. |
| Spamhaus DROP (IPv4) | free to use per the Spamhaus DROP terms | daily | Address blocks hijacked or run by criminals. |
| Spamhaus ASN-DROP | free to use per the Spamhaus DROP terms | daily | Whole networks (ASNs) run by criminals. |
| RansomLook ransomware leak-site posts, last 7 days | CC BY 4.0 (RansomLook); Alibi shows totals by day and gang only, never victim names or links | daily | Every post on ransomware gangs' leak sites in the last 7 days. |
| TeleGeography Submarine Cable Map, cables | CC BY-NC-SA 3.0 (as published by TeleGeography; not re-confirmed on their site in Oct 2026) | weekly | Undersea internet cable routes. |
| TeleGeography Submarine Cable Map, landing points | CC BY-NC-SA 3.0 (as above) | weekly | Where undersea cables come ashore. |
| DB-IP IP to City Lite | CC BY 4.0 ("IP Geolocation by DB-IP") | monthly | Approximate city of each IP range, used to pin servers to places. |
| Natural Earth admin-1 states and provinces (1:10m) | public domain | every 6 months | State and province borders (reference geography, changes rarely). |
| Tor Project Onionoo exit relays | Tor Metrics data, public | daily | Running Tor exit relays and their addresses. |

Generated from [`sources.yaml`](sources.yaml) by `scripts/readme_numbers.py`.
<!-- sources:end -->

---

## API Reference

All read endpoints are keyless, rate-limited, and return an `X-Data-As-Of` timestamp header.

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/v1/terminal/company?q=` | Bloomberg-style company tech, breach, and KEV dossier |
| `GET` | `/v1/terminal/footprint?ip=` | Live visitor digital footprint & tripwire diagnostic |
| `GET` | `/v1/shield/check?domain=` | Domain threat check with Shannon entropy DGA scoring |
| `GET, POST` | `/dns-query` | RFC 8484 DNS-over-HTTPS wire-format and JSON resolver |
| `GET` | `/v1/intel/disruptions` | Planetary BGP and CAIDA IODA internet outages |
| `GET` | `/v1/supply-chain/analyze` | Open-source supply chain risk (deps.dev + OSV) |
| `GET` | `/v1/terminal/leak-hunter` | Corporate domain employee breach & ransomware audit |
| `GET` | `/v1/terminal/pwned-password`| Zero-knowledge k-Anonymity password check |
| `POST` | `/v1/canary/generate` | Generate decoy AWS keys, DB URIs, and tripwires |
| `GET` | `/v1/canary/alarms` | Intrusion detection alarms from triggered decoys |
| `GET` | `/v1/remediation/explain` | AI plain-English remediation card & 60s shell commands |
| `GET` | `/v1/intel/compute-atlas` | Global AI superclusters and semiconductor fab atlas |
| `GET` | `/taxii2/` | OASIS TAXII 2.1 Server Discovery |
| `GET` | `/taxii2/v21/collections/` | OASIS TAXII 2.1 Collections list |
| `GET` | `/metrics` | Prometheus metrics (RFC 8967) for platform health |
| `GET` | `/v1/intel/state/{code}` | Full 4,596-state intelligence dossier |
| `GET` | `/v1/intel/overview` | Planetary headline numbers across all feeds |
| `GET` | `/v1/intel/search?q=` | Unified search across IPs, CVEs, companies, domains |
| `GET` | `/v1/intel/ip/{ip}` | Deep IP analysis (ASN, Tor, hosting, malware, DROP) |
| `GET` | `/v1/intel/export/stix` | Planetary STIX 2.1 threat intelligence bundle |
| `GET` | `/v1/intel/export/misp` | Standard MISP 2.4 Event JSON export |
| `GET` | `/v1/intel/export/csv` | Clean CSV export of active threat indicators |
| `GET` | `/v1/intel/export/blocklist.txt`| Plaintext IP blocklist for firewalls and proxies |
| `GET` | `/v1/intel/export/nftables` | Drop-in Linux nftables packet filter ruleset |
| `GET` | `/v1/intel/export/suricata` | Suricata / Snort IDS perimeter detection rules |
| `GET` | `/v1/health` | Per-feed download health, record counts, freshness |

Interactive Swagger documentation is available locally at `http://localhost:8000/docs`.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/UtkarshOver9000/alibi.git
cd alibi

# Install dependencies using uv
uv sync --all-extras

# Start the development server
uv run uvicorn ittravel.api.app:app --reload --port 8000

# Run full test suite
uv run pytest
```

Visit `http://localhost:8000` in your browser to explore the interactive terminal and 3D globe.

---

## Project Documentation

- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Platform Roadmap](ROADMAP.md)
- [Security Disclosures](.well-known/security.txt)

---

## License

Code is licensed under the [MIT License](LICENSE). Data feeds remain under their respective source licenses (see [`sources.yaml`](sources.yaml)).
