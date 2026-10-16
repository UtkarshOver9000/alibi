# ALIBI 1.0 Architecture

ALIBI is the open-source planetary tech & defense terminal for engineers. It runs as a single FastAPI application (`src/ittravel`) that powers a 3D WebGL God's Eye radar, an open-source Tech Bloomberg Terminal, a real-time visitor digital footprint & tripwire diagnostic, and an active protective DNS shield with ML-based DGA sinkholing.

## Modules

| Path | What it does |
|---|---|
| `api/app.py` | FastAPI application: middleware (CORS, gzip, rate limits, 256 KB body cap, `X-Data-As-Of`), static mounts, dashboard |
| `api/routes/` | Modular API routers: `intel` (snapshot data, search, IP lookup, STIX), `terminal` (Bloomberg company dossiers, live footprint), `shield` (DNS shield & DGA entropy checks), `globe` (textures, pick map, legends), `health` (feed freshness) |
| `api/ratelimit.py` | Per-IP token-bucket rate limits for public endpoints with reverse-proxy trust verification |
| `api/bodylimit.py` | 256 KB cap on incoming request payloads |
| `schema.py` | Clean Pydantic schemas for queries (`CompanyQuery`, `FootprintQuery`, `DomainQuery`) |
| `intel/terminal.py` | Tech Bloomberg Terminal dossier builder & live personal footprint / tripwire diagnostic |
| `intel/dns_shield.py` | Protective DNS Shield: Shannon entropy calculation for DGA detection + domain sinkholing |
| `intel/network.py` | Sub-millisecond IP lookup: ASN owner (iptoasn), hosting flag, Tor exit status, abuse.ch malware hit, Spamhaus DROP |
| `intel/service.py` | Reads compiled `intel_data/*.json` files and shapes planetary intelligence summaries |
| `intel/stix.py` | STIX 2.1 JSON bundle exporter for threat intelligence feeds |
| `intel/news.py` | Live RSS / Atom cybersecurity news fetch with 30-minute in-memory caching |
| `intel/snapshot.py` | Offline pipeline: fetches and compiles public 2026 data into compressed snapshots |
| `netrisk/` | Real 2026 ThreatFox Network-Risk model training & scoring (ROC-AUC 0.964) |
| `dashboard/` | Full frontend: WebGL 3D Globe (globe.gl, Three.js), Leaflet, D3, custom cybersecurity HUD |
| `api/index.py` | Vercel serverless gateway importing `ittravel.api.app:app` |

## Data Flow

```
Public 2026 Sources (abuse.ch, CISA KEV, FIRST EPSS, HIBP, Spamhaus, iptoasn, DB-IP, OONI, TeleGeography)
          │
          ▼ scripts/fetch_intel.sh (every 6 hours)
    data/intel/ (raw feed downloads)
          │
          ▼ python -m ittravel.intel.snapshot
    src/ittravel/intel_data/ (~15 MB compressed JSON + NumPy binaries)
          ├── breaches.json, flaws.json, threats.json, bad_ips.json
          ├── countries.json, states.json, cables.json, heat.json
          └── network.npz, drop.npz, meta.json
          │
          ├── netrisk/train.py  →  artifacts/netrisk_model.joblib (2026 ThreatFox ML, ROC-AUC 0.964)
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

## Data Principles

1. **100% Real 2026 Data**: Zero synthetic records. Zero honeypot approximations. Zero outdated static datasets.
2. **Deterministic Lookups**: Sub-millisecond IP-to-ASN and threat matching using binary search over sorted NumPy arrays.
3. **Open Access**: Clean, keyless public read endpoints protected by in-memory token-bucket rate limiters.
