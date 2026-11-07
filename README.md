<p align="center"><img src="docs/img/logo.svg" width="120" alt="Alibi logo"></p>

# Alibi

[![CI](https://github.com/UtkarshOver9000/alibi/actions/workflows/ci.yml/badge.svg)](https://github.com/UtkarshOver9000/alibi/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Alibi is an open-source threat-intelligence dashboard and API built only on public security
feeds. It refreshes 18 feeds (abuse.ch, CISA KEV, FIRST EPSS, Spamhaus, Have I Been Pwned,
OONI, TeleGeography and others), maps them on a 3D globe, and scores every network on how
likely it is to host a new attack server next week.

**Live demo:** https://impossible-travel-auth-anomaly-engi.vercel.app

## What it does

- **Threat globe.** Botnet controllers and malware servers (abuse.ch Feodo, ThreatFox, URLhaus)
  placed with DB-IP geolocation, OONI censorship results, undersea cables and Tor exits, across
  4,596 states and provinces.
- **Company and domain lookup.** Networks (ASNs) and upstream providers, subdomains from
  Certificate Transparency (crt.sh), exploited CVEs (CISA KEV with FIRST EPSS scores), breach
  history (HIBP), ransomware leak-site mentions (RansomLook) and an A–F posture grade.
- **IP footprint.** Network type (home ISP, hosting, VPN, Tor), matches against abuse.ch and
  Spamhaus DROP lists, and the nearest cable landing point.
- **DNS shield.** Blocklist lookups plus a Shannon-entropy heuristic for algorithmically
  generated domains, served over DNS-over-HTTPS (RFC 8484).
- **Supply-chain check.** Known vulnerabilities and licence risk for PyPI, npm, Go, Cargo and
  Maven packages, from deps.dev and OSV.
- **Breach and password checks.** Breach exposure for a domain, and a k-anonymity password
  check that only ever sends the first 5 characters of a SHA-1 hash.
- **Canary tokens.** Decoy AWS keys, database URIs and tracking pixels that record the caller's
  IP and network when someone uses them.
- **Remediation cards.** Rule-based fix steps and firewall snippets (iptables, nftables,
  Suricata, Windows Firewall) for CVEs, IPs and suspicious domains.
- **Exports.** STIX 2.1, MISP, TAXII 2.1, CSV, plain blocklists, nftables and Suricata rules,
  plus Prometheus metrics.

**About the "Black October" war room.** That tab holds 27 hand-written summaries of incidents
from October 2026. They are editorial write-ups, not one of the data feeds below, and they don't
yet link their sources, so check each one against the vendor's advisory before relying on it.

## The network-risk model

**Question:** how likely is an address in a given network to become a new attack server next week?

- **Data:** the abuse.ch ThreatFox full export (CC0): 13,142 attack-server IPs across 79,175 networks.
- **Split by time, not at random:** train 1 Jun to 10 Aug 2026, validate 10 Aug to 7 Sep, test
  7 Sep to 12 Oct. The test weeks come strictly after everything the model saw.
- **Model choice:** a Poisson GLM on 8 features (recent servers per million addresses, malware
  families, weeks since the last server, network size, hosting or not). It beat gradient boosting
  on validation (ROC-AUC 0.966 vs 0.892), so the simpler model ships.

| Held-out test: 395,875 network-weeks, 3,646 new attack servers | Model | Simple rule (servers per address, last 4 weeks) |
|---|---|---|
| ROC-AUC | **0.964** | 0.880 |
| New attack servers caught in the riskiest 1% of address space | **69%** (95% CI 61–78%) | 68% |
| New attack servers caught in the riskiest 0.1% of address space | **39%** (95% CI 33–51%) | 38% |

**What this means:** at the very top of the list the simple rule is almost as good, because
networks that hosted attack servers recently tend to host them again. The model's gain is in
ranking the long tail of networks. Confidence intervals come from 100 bootstrap resamples. The
full model card is in [`netrisk_card.json`](src/ittravel/artifacts/netrisk_card.json).

**Earlier versions** scored logins with account-takeover models trained on the RBA dataset
(Wiefling et al., CC BY 4.0). That data dates from 2020–21, its values are synthesised from real
logins, and only 22 takeovers fell in the test window, so Alibi 1.0 retired those models instead
of advertising their scores.

## Open protocols and standards

| Standard | Endpoint | Description |
|:---|:---|:---|
| **OASIS TAXII 2.1** | `/taxii2/`, `/taxii2/v21/collections/` | Threat-intelligence sharing for SIEMs |
| **OASIS STIX 2.1** | `/v1/intel/export/stix` | STIX 2.1 JSON indicator bundle |
| **MISP 2.4** | `/v1/intel/export/misp` | MISP event JSON export |
| **RFC 8484 DoH** | `/dns-query` | DNS-over-HTTPS, binary wire format and JSON |
| **Prometheus** | `/metrics` | Prometheus text exposition format for Grafana or Datadog |
| **Linux nftables** | `/v1/intel/export/nftables` | Drop-in packet-filter ruleset |
| **Suricata / Snort** | `/v1/intel/export/suricata` | IDS rules for the current indicators |

## Python SDK (`AlibiClient`)

A small typed client with no extra dependencies:

```python
from ittravel import AlibiClient

client = AlibiClient()

footprint = client.footprint("1.1.1.1")
print(f"Tier: {footprint.threat_tier}, ASN: {footprint.network.get('asn')}")

company = client.company_tech("Cloudflare")
print(f"Grade: {company.security_grade}, ASNs: {len(company.asns)}")

shield = client.dns_shield("xq7b9kz1m0w8p2r4j6f.biz")
print(f"Verdict: {shield.verdict}, Reason: {shield.dga_reason}")

pkg = client.supply_chain("fastapi", ecosystem="pypi")
print(f"Status: {pkg.security_status}, License: {pkg.license_risk}")
```

## Live numbers

<!-- numbers:start -->
Numbers from the snapshot of **7 November 2026** (the live app shows the current ones):

| Module | Today |
|---|---|
| Breaches | 1,030 breaches, 16.30 billion accounts; 105 breaches and 476.4 million accounts in the last 12 months |
| Attacks | 9,021 malware and botnet servers; 7,126 threat indicators in 48 hours; 454 criminal networks; 241 ransomware victims (31 October 2026 to 7 November 2026) |
| Exploited flaws | 1,769 flaws; 35 added in the last 30 days; 361 used by ransomware; highest exploit chance CVE-2026-109618 at 100.0% |
| Live globe | 4,596 states and provinces, 734 undersea cables, websites confirmed blocked in 78 countries |

**A finding worth knowing:** only 11% of the malware servers sit on hosting or VPN networks, about the same as those networks' 11% share of all addresses; 50% are home routers, cameras and other devices hijacked by botnets such as Mozi and Mirai. Blocking data centers alone misses most of them.
<!-- numbers:end -->

---

## Data sources

Every feed is public. The URLhaus and ThreatFox exports need a free abuse.ch Auth-Key
(`ABUSE_CH_AUTH_KEY`, from https://auth.abuse.ch); without it the fetcher skips those two feeds.

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

## API reference

All read endpoints are keyless, rate-limited, and return an `X-Data-As-Of` timestamp header.

| Method | Endpoint | Description |
|:---|:---|:---|
| `GET` | `/v1/terminal/company?q=` | Company networks, subdomains, exploited CVEs and breaches |
| `GET` | `/v1/terminal/footprint?ip=` | Network type and threat-list matches for an IP |
| `GET` | `/v1/shield/check?domain=` | Domain threat check with Shannon entropy DGA scoring |
| `GET, POST` | `/dns-query` | RFC 8484 DNS-over-HTTPS wire-format and JSON resolver |
| `GET` | `/v1/intel/disruptions` | Internet outages from CAIDA IODA and RIPE RIS |
| `GET` | `/v1/supply-chain/analyze` | Open-source supply chain risk (deps.dev + OSV) |
| `GET` | `/v1/terminal/leak-hunter` | Breach and ransomware exposure for a domain |
| `GET` | `/v1/terminal/pwned-password`| Zero-knowledge k-Anonymity password check |
| `POST` | `/v1/canary/generate` | Generate decoy AWS keys, DB URIs, and tripwires |
| `GET` | `/v1/canary/alarms` | Intrusion detection alarms from triggered decoys |
| `GET` | `/v1/remediation/explain` | Rule-based remediation card with firewall snippets |
| `GET` | `/v1/intel/compute-atlas` | Curated list of major data centres and chip fabs |
| `GET` | `/taxii2/` | OASIS TAXII 2.1 Server Discovery |
| `GET` | `/taxii2/v21/collections/` | OASIS TAXII 2.1 Collections list |
| `GET` | `/metrics` | Prometheus metrics for platform health |
| `GET` | `/v1/intel/state/{code}` | Everything known about one state or province |
| `GET` | `/v1/intel/overview` | Headline numbers across all feeds |
| `GET` | `/v1/intel/search?q=` | Unified search across IPs, CVEs, companies, domains |
| `GET` | `/v1/intel/ip/{ip}` | Deep IP analysis (ASN, Tor, hosting, malware, DROP) |
| `GET` | `/v1/intel/export/stix` | STIX 2.1 bundle of current indicators |
| `GET` | `/v1/intel/export/misp` | Standard MISP 2.4 Event JSON export |
| `GET` | `/v1/intel/export/csv` | Clean CSV export of active threat indicators |
| `GET` | `/v1/intel/export/blocklist.txt`| Plaintext IP blocklist for firewalls and proxies |
| `GET` | `/v1/intel/export/nftables` | Drop-in Linux nftables packet filter ruleset |
| `GET` | `/v1/intel/export/suricata` | Suricata / Snort IDS perimeter detection rules |
| `GET` | `/v1/health` | Per-feed download health, record counts, freshness |

Interactive Swagger documentation is available locally at `http://localhost:8000/docs`.

---

## Quick start

```bash
# Clone the repository
git clone https://github.com/UtkarshOver9000/alibi.git
cd alibi

# Install dependencies using uv
uv sync --all-extras

# Start the development server
uv run uvicorn ittravel.api.app:app --reload --port 8000

# Run the test suite
uv run pytest

# Refresh the feeds (URLhaus and ThreatFox need ABUSE_CH_AUTH_KEY, see .env.example)
make fetch
```

Then open `http://localhost:8000`.

---

## Project documentation

- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Platform Roadmap](ROADMAP.md)
- [Security Disclosures](.well-known/security.txt)

---

## License

Code is licensed under the [MIT License](LICENSE). Data feeds remain under their respective source licenses (see [`sources.yaml`](sources.yaml)).
