# Changelog

Changes from the Alibi master plan (`#` numbers refer to its 299 items). Newest last.

## Unreleased

- Fix the line break in the DB-IP fallback of fetch_intel.sh
- Write a one-page architecture note (master plan #1)
- Record performance and API baselines before the master plan (#2)
- Rename the key to ALIBI_API_KEY and drop the public master key (#12, #13)
- Keep the last good feed copy and hide an empty Videos panel (#15)
- Colour the risk bar by tier (#16)
- Describe false alarms as "not labelled as takeovers" (#17)
- Add a tier legend under the risk percentile (#18)
- Self-host the front-end libraries, fonts and globe textures
- Show the Mumbai to London story in the README, with story links (#19)
- Note the self-hosted vendor files in the architecture doc
- Add sources.yaml listing every data feed (#29)
- Add one fetcher for every feed in sources.yaml (#30)
- Refresh feeds on their own cadence every 6 hours (#33)
- Write the training-data policy (#62)
- Render globe textures on the server, binned per million IPs (#151, #153)
- Lazy-load the globe, 2048 textures on phones, pause off-screen (#154, #155, #158, #159)
- Define a STIX 2.1-aligned data model, with a per-IP export (#115)
- Rewrite Data & accuracy to match reality (#277)
- Read every setting through one settings module, add .env.example (#4)
- Add pre-commit hooks: ruff, ruff-format and gitleaks (#5)
- Record after screenshots: desktop globe still complete (#168)
- Add a Makefile: dev, test, lint, fetch, snapshot, train (#10)
- Add a pull-request template (#11)
- Scan the git history for secrets and record the result (#6)
- Lock dependency versions with uv.lock and enable Dependabot (#7)
- Mark the current month as month to date in the flaws chart (#21)
- Add a "Try the sign-in checker" button to the hero (#22)
- Say "unusual for this user" when HIGH comes without impossible travel (#26)
- Add a plain-language "How to read this" under the risk score (#27)
- Keep only security-relevant headlines and videos (#23)
- Reject truncated downloads in the fetcher (fix for #30)
- Add loading skeletons and error and empty states to every tab (#24)
- Show "updated X ago" on every tab (#25)
- Add a global search for IPs, domains, CVEs and companies (#28)
- Report every feed's status in /v1/health (#36)
- Put the snapshot date on every API response (#39)
- Check every feed's format and size before it can replace the last copy (#31)
- Keep the last good network table when iptoasn is unreachable (#35)
- Hash every snapshot and keep each version for 90 days (#32)
- Add FIRST EPSS exploit chances to the exploited flaws (#42)
- Score exploited flaws for patch priority (#136)
- Add a "Patch these first" list for the vendors a company runs (#137)
- Split the API into routers: intel, globe, demo, auth, health (#9)
- Keep the last good state borders when Natural Earth can't be fetched (#35)
- Report the real date of reused borders and network tables (#35)
- Write a 60-second pitch and a 2-minute demo script (#293)
- Keep docs, tests and reports out of the Vercel bundle
- Switch ransomware data to RansomLook (CC BY 4.0)
- Type-check the package with mypy in CI (#8)
- Test the snapshot parsers on real feed excerpts (#61)
- Fix a 500 error when an IP is checked against Spamhaus DROP ranges
- Rewrite the README around the live app (#276)
- Generate the README numbers and source table from the data (#40)
- Start a CHANGELOG listing every shipped plan item (#3)

- Publish snapshots to a data branch so main holds only human commits
- Self-host IBM Plex Sans and Plex Mono for the console redesign
- Save report times and typed points; add events, activity and country ranks
- Redesign the dashboard as an analyst console with a full-screen globe (#152, #160, #169)
- Log the console redesign in the changelog

- Add the Alibi logo: a dark-red @ wrapped in an iron chain
- Show the logo at the top of the README
- Add Open Graph and Twitter share cards with a 1200x630 image (#175)
- Raise dim text to WCAG AA contrast (#172)
- Send security headers and a strict CSP for the dashboard (#259)
- Tighten CORS to the headers the API uses (#260)
- Publish security.txt and a responsible-disclosure policy (#265)
- Add cache headers to the read endpoints (#241)
- Add request IDs to every response (#243)
- Validate login inputs and cap request bodies (#244)
- Fall back to a rule-based verdict when model files are missing (#246)
- Use a multi-stage Dockerfile with a non-root user and a healthcheck (#248)
- Audit dependencies for known vulnerabilities in CI (#261)
- Log the security hardening batch in the changelog
- Annotate the reused EPSS feed record so mypy passes again (#300)
- Score keyless demo checks in a throwaway sandbox (#302)
- Bound the users and IPs kept in memory (#301)
- Read X-Forwarded-For only behind a configured proxy (#303)
- Cap streamed request bodies too, not just ones with Content-Length (#304)
- Stop the README claiming ransomware by industry and country (#308)
- Say where live scoring sees less than training did (#306)
- Test training end to end on real RBA rows (#305)
- Require mypy 2.4 or newer, as Dependabot proposed (#307)
- Check the live site's health every hour and fail loudly when a feed is stale (#37)
- Add a network-risk trainer on 2026 ThreatFox data, split strictly by time (#78)
- Ship the network-risk model trained on June to October 2026 (#312)
- Score every network from ThreatFox's full export on each snapshot

Covered without a separate change:

- API keys are issued server-side only and never shown in the UI (done with #12 and #13) (#14)
- The globe legend names what is counted and per what unit (done with #151) (#20)
- Each feed has its own max age in sources.yaml, and stale feeds are flagged (done with #29, #30 and #36) (#38)
- The RBA dataset (Wiefling et al., CC BY 4.0) is cited in the README, sources.yaml and the model card (#113)
- Per-IP token-bucket rate limits with Retry-After were already in place (api/ratelimit.py) (#240)

Plan items done so far: 82 of 314 (#172, #175, #241, #243, #244, #246, #248, #259, #260, #261, #265, #152, #160, #169, #1, #2, #3, #4, #5, #6, #7, #8, #9, #10, #11, #12, #13, #14, #15, #16, #17, #18, #19, #20, #21, #22, #23, #24, #25, #26, #27, #28, #29, #30, #31, #32, #33, #35, #36, #38, #39, #40, #42, #61, #62, #115, #136, #137, #151, #153, #154, #155, #158, #159, #168, #276, #277, #293, #300, #302, #301, #303, #304, #113, #240, #308, #306, #305, #307, #37, #78, #312).

## 1.0 plan

Items from the Alibi 1.0 plan (148 items), newest last.
- Keep the last EPSS scores when the daily download fails (1.0 #1)
- Add the Design 1.0 colour, spacing, depth and motion tokens (1.0 #4)
- Self-host Chakra Petch for HUD labels and use tabular numerals (1.0 #5)
- Turn panels into glass with HUD corner brackets (1.0 #6)
- Add a self-hosted icon sprite and replace text glyphs (1.0 #7)
- Move navigation to a left icon rail with counts of what is new (1.0 #17)
- Name a late feed in the header's feed-health tooltip (1.0 #3)
- Add a HUD status strip: UTC clock, live state, data age, feeds, points (1.0 #16)
- Keep the live globe behind every module and pause it when covered (1.0 #18)
- Open on the live globe and turn the overview into its situation panel (1.0 #18)
- Keep the globe's colour, layers and selected country in the URL (1.0 #19)
- Add a command palette for search: Ctrl+K or / (1.0 #20)
- Add keyboard shortcuts and a "?" list of them (1.0 #21)
- Add the wire: a ticker of the newest real events along the bottom (1.0 #22)
- Give every point on the globe its IP address

## 1.0.0 — Platform Transition (Phase 1)
- Stripped legacy RBA login dataset and 2020 Norwegian login models.
- Decommissioned impossible-travel and account takeover heuristics.
- Shifted architecture to 100% real 2026 threat intelligence pipelines.
- Implemented Tech Bloomberg Terminal (`/v1/terminal/company`) with corporate ASN, KEV flaws, and breach aggregation.
- Implemented Live Visitor Footprint & Tripwire diagnostic (`/v1/terminal/footprint`).
- Implemented Active Protective DNS Shield (`/v1/shield/check`) with Shannon entropy DGA botnet detection.
- Streamlined engine to export 2026 ThreatFox network-risk machine learning model (ROC-AUC 0.964).
- Cleaned test suite and verified 100% test coverage for all active modules.

## 1.0.1 — State Intelligence Dossier (Phase 2)
- Added full state/province intelligence dossier (`/v1/intel/state/{code}`) covering all 4,596 world subdivisions.
- Aggregated real cyber threat density per million IPs, active malware C2 nodes, OONI web censorship anomalies, and physical submarine cables.
- Added interactive `#state-modal` dialog and dossier inspector button to the frontend HUD.

## 1.0.2 — Terminal, Footprint & DNS Shield UI (Phase 3)
- Fully wired Tech Bloomberg Terminal tab (`#terminal`) with corporate ASN, CISA KEV, and breach summary.
- Added live Certificate Transparency integration (`fetch_crtsh_subdomains()`) querying `crt.sh` JSON API for real-time attack surface enumeration.
- Wired Live Footprint diagnostic tab (`#check`) with threat tiers and network carrier lookups.
- Wired Active Protective DNS Shield tab (`#shield`) with real-time Shannon entropy DGA botnet scoring and sinkhole verdicts.
- Removed all legacy ATO check code and invalid map references.

## 1.0.3 — Standard Threat Intelligence Exports (Phase 4)
- Added planetary STIX 2.1 JSON bundle export (`/v1/intel/export/stix`) aligning with OASIS and OpenCTI standards (#115, #128).
- Added standard MISP 2.4 Event JSON export (`/v1/intel/export/misp`) (#128).
- Added clean CSV export of active threat indicators (`/v1/intel/export/csv`) (#128).
- Added plaintext IP blocklist (`/v1/intel/export/blocklist.txt`) for firewall and proxy ingestion (#146).
- Added drop-in Linux nftables packet filter ruleset (`/v1/intel/export/nftables`) (#146).
- Added Suricata / Snort IDS perimeter detection rules (`/v1/intel/export/suricata`) (#146).
- Updated Makefile train recipe to target 2026 ThreatFox network-risk trainer.
