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
- **Exploited Flaws & Weaponization:** CISA Known Exploited Vulnerabilities (KEV) cross-referenced with FIRST EPSS exploit probabilities and ransomware weaponization status.
- **Breach History:** Have I Been Pwned breach archives with total accounts exposed and leaked data types.
- **Ransomware Watch:** Active extortion claims from RansomLook.
- **Security Health Grade (A–F):** 100-point posture scoring with a 3-bullet plain-English executive summary.

### 3. ⚡ Live Personal Footprint & Hacker Tripwire
Real-time network diagnostic for any client or target IP:
- **Routing & ASN Intelligence:** Upstream carrier, ASN classification (residential ISP vs cloud hosting / VPN vs Tor exit).
- **Threat Feed Interception:** Instant check against abuse.ch threat lists and Spamhaus DROP criminal network blocks.
- **Subsea Infrastructure Adjacency:** Nearest physical undersea cable landing station.
- **Tripwire Diagnostic:** Flags connections routing through malicious subnets, hostile anonymizers, or compromised nodes.

### 4. 🛡️ Active Protective DNS Shield
Protective DNS endpoint with machine learning DGA detection:
- **DGA Botnet Entropy Scorer:** Shannon entropy scoring flags algorithmic botnet domains (entropy > 3.65 on domain labels).
- **Instant Sinkhole Response:** Sinkholes confirmed malware C2 and phishing domains to `0.0.0.0` in <15ms.

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
Numbers from the snapshot of **10 October 2026** (the live app shows the current ones):

| Module | Today |
|---|---|
| Breaches | 1,024 breaches, 16.29 billion accounts; 104 breaches and 479.6 million accounts in the last 12 months |
| Attacks | 8,913 malware and botnet servers; 7,242 threat indicators in 48 hours; 431 criminal networks; 215 ransomware victims (3 October 2026 to 10 October 2026) |
| Exploited flaws | 1,739 flaws; 36 added in the last 30 days; 361 used by ransomware; highest exploit chance CVE-2021-26086 at 100.0% |
| Live globe | 4,596 states and provinces, 733 undersea cables, websites confirmed blocked in 67 countries |

**A finding worth knowing:** only 11% of the malware servers sit on hosting or VPN networks, about the same as those networks' 11% share of all addresses; 49% are home routers, cameras and other devices hijacked by botnets such as Mozi and Mirai. Blocking data centers alone misses most of them.
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
| `GET` | `/v1/intel/overview` | Planetary headline numbers across all feeds |
| `GET` | `/v1/intel/search?q=` | Unified search across IPs, CVEs, companies, and domains |
| `GET` | `/v1/intel/ip/{ip}` | Deep IP analysis (ASN, Tor, hosting, malware, Spamhaus DROP) |
| `GET` | `/v1/intel/ip/{ip}/stix` | STIX 2.1 JSON bundle export for security operations |
| `GET` | `/v1/intel/flaws/priority` | CISA KEV flaws prioritized by EPSS & ransomware weaponization |
| `GET` | `/v1/intel/globe/{metric}.jpg`| Server-rendered globe texture maps |
| `GET` | `/v1/health` | Per-feed download health, record counts, and freshness |

Interactive Swagger documentation is available locally at `http://localhost:8000/docs`.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/UtkarshOver9000/alibi.git
cd alibi

# Install dependencies
pip install -r requirements-dev.txt

# Start the development server
make dev
# or: uvicorn ittravel.api.app:app --reload --port 8000

# Run full test suite
make test
```

Visit `http://localhost:8000` in your browser to explore the interactive terminal and 3D globe.

---

## Architecture Overview

```
Public Sources (abuse.ch, CISA KEV, EPSS, HIBP, Spamhaus, iptoasn, DB-IP, OONI, TeleGeography)
          │
          ▼ GitHub Actions every 6h (scripts/fetch_intel.sh)
    data/intel/ (raw feed downloads)
          │
          ▼ python -m ittravel.intel.snapshot
    src/ittravel/intel_data/ (~15 MB compressed JSON + NumPy)
          │
          ├── netrisk/train.py  →  artifacts/netrisk_model.joblib (ROC-AUC 0.964)
          │
          ▼
    FastAPI Application (src/ittravel/api/app.py)
          ├── /v1/intel/*       Planetary intelligence, cross-feed search, STIX 2.1
          ├── /v1/terminal/*    Bloomberg tech dossiers & live visitor footprint
          ├── /v1/shield/*      Protective DNS Shield & DGA entropy scorer
          ├── /v1/globe/*       Server-rendered globe textures and pick maps
          └── /v1/health        Per-feed freshness and health monitors
          │
          ▼
    Browser UI (dashboard/index.html)
          ├── 3D God's Eye Earth (WebGL, 4,596 world states, 733 undersea cables)
          ├── Tech Bloomberg Terminal (corporate attack surface, KEV flaws, ASNs)
          ├── Live Footprint & Tripwire diagnostic console
          └── Threat Feed Monitors & Global Cyber News
```

---

## License

Code is licensed under the [MIT License](LICENSE). Data feeds remain under their respective source licenses (see [`sources.yaml`](sources.yaml)).
