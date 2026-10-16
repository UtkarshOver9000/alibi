# ALIBI 1.0 Platform Roadmap

This roadmap documents the transition to **ALIBI 1.0** and the multi-year vision for the open-source planetary tech & defense terminal.

---

## Shipped Milestones (Alibi 1.0 — 2026)

### Phase 1: Engine Modernization & Clean Telemetry Pipeline
- [x] Stripped legacy 2020–2021 synthetic RBA datasets and impossible-travel artifacts.
- [x] Implemented 100% verified 2026 threat telemetry feeds (abuse.ch Feodo, URLhaus, ThreatFox full export, Spamhaus DROP, CISA KEV, FIRST EPSS).
- [x] Built and deployed the 2026 ThreatFox Network-Risk model (`netrisk_model.joblib`), achieving an out-of-time evaluation ROC-AUC of 0.964 and PR-AUC of 0.941.

### Phase 2: State Intelligence Dossier (4,596 Subdivisions)
- [x] Mapped regional cyber density, malware C2 nodes, OONI censorship telemetry, and submarine fiber landings for all 4,596 world states and provinces.
- [x] Interactive modal dossier wired to the 3D WebGL globe.

### Phase 3: Tech Terminal, Footprint, & DNS Shield
- [x] Open-source corporate tech Bloomberg Terminal (`/v1/terminal/company`) with live Certificate Transparency (`crt.sh`) attack surface enumeration.
- [x] Live personal footprint and tripwire diagnostic (`/v1/terminal/footprint`).
- [x] Active Protective DNS Shield with real-time Shannon entropy DGA detection (`/v1/shield/check`).

### Phase 4: The 10 Pillars of Defense Terminal
- [x] **Pillar 1:** God's Eye 3D WebGL Globe & 4,596 State Dossiers.
- [x] **Pillar 2:** Corporate Attack Surface & Tech Bloomberg Terminal.
- [x] **Pillar 3:** Live Digital Footprint & Subsea Cable Landing Telemetry.
- [x] **Pillar 4:** Protective DNS Shield & DGA Sinkholing.
- [x] **Pillar 5:** Planetary BGP & Internet Disruption Radar (`/v1/intel/disruptions`).
- [x] **Pillar 6:** Open-Source Supply Chain Analyzer via deps.dev & OSV (`/v1/supply-chain/analyze`).
- [x] **Pillar 7:** Corporate Breach & Credential Leak Hunter with k-Anonymity SHA-1 hashing (`/v1/terminal/leak-hunter`, `/v1/terminal/pwned-password`).
- [x] **Pillar 8:** Canary Token & Hacker Tripwire Generator (`/v1/canary/generate`, `/v1/canary/alarms`).
- [x] **Pillar 9:** AI Plain-English Defense Remediation Engine with 60-second copy-paste shell commands (`/v1/remediation/explain`).
- [x] **Pillar 10:** Global AI & Compute Infrastructure Atlas (`/v1/intel/compute-atlas`).

### Phase 5: Open Standards, Protocols & Interoperability
- [x] **OASIS STIX 2.1 Bundle Export:** `/v1/intel/export/stix`
- [x] **MISP 2.4 Event JSON Export:** `/v1/intel/export/misp`
- [x] **OASIS TAXII 2.1 Server:** `/taxii2/`, `/taxii2/v21/`, `/taxii2/v21/collections/`
- [x] **RFC 8484 DNS-over-HTTPS (DoH):** Binary wire format + JSON DoH at `/dns-query`
- [x] **Prometheus Observability:** `/metrics` endpoint with real-time operational telemetry
- [x] **Cloud Hyperscaler ASN Mapping:** AWS, GCP, Azure, Cloudflare, DigitalOcean, OCI

---

## Upcoming Roadmap (2026 – 2027)

### Q4 2026: SIEM & Orchestration Integrations
- [ ] Native OpenCTI external import connector package.
- [ ] Splunk Technology Add-on (TA) and Microsoft Sentinel Data Connector.
- [ ] Zero-touch Linux nftables / Suricata daemon auto-sync agent.

### Q1 2027: Autonomous Defense Mesh
- [ ] Decentralized p2p canary alarm gossiping using libp2p.
- [ ] On-premise offline air-gapped deployment bundle.
- [ ] Expanded AI hardware supply chain tracking (semiconductor packaging, ASML lithography nodes, high-bandwidth memory corridors).
