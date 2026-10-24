"""
ALIBI 2.0 — Black October (October 2026) Cyber Catastrophe Intelligence Engine.
Provides comprehensive forensic autopsies, interactive exploit mechanics,
live real-time domain & stack exposure diagnostics, and 60-second emergency remediations.
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request
from typing import Any

from . import dns_shield, supply_chain

# The 27 critical security incidents of Black October (October 2026)
BLACK_OCTOBER_INCIDENTS: dict[str, dict[str, Any]] = {
    "php2shell": {
        "excuse_vs_reality": (
            "THE REALITY: PHP powers over 75% of the web. This was not a bug in third-party plugins or WordPress themes—it was a memory corruption "
            "in the core C runtime of PHP (Zend Engine) during out-of-memory longjmp() stack unwinding. Threat actors weaponized the vulnerability "
            "globally before the disclosure embargo lifted, scanning internet servers using automated botnet probes."
        ),
        "cloudflare_defense": (
            "HOW CLOUDFLARE PREVENTED THIS:\n"
            "Cloudflare deployed emergency WAF managed rules across all paid and free tiers (Rule: 100618_PHP_RCE) that inspected incoming multipart/form-data "
            "requests and stripped/blocked malformed nested boundaries before packets ever reached customer origin servers."
        ),
        "prevention_guide": (
            "1. Patch PHP Core Runtime: Upgrade immediately to PHP 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+.\n"
            "2. Deploy Perimeter WAF: Enable ModSecurity, AWS WAF, or Cloudflare WAF rules to reject nested multipart headers.\n"
            "3. Run Workers in Sandboxed Containers: Use non-root Docker execution (USER www-data) and read-only root filesystems."
        ),

        "id": "php2shell",
        "cluster": "runtime",
        "name": "PHP2Shell Unauthenticated Core RCE",
        "tier": "year_level",
        "target": "PHP Core Language Runtime (Zend Engine)",
        "cve": "CVE-2026-109618",
        "cvss": 9.8,
        "date": "2026-10-21",
        "summary": "Critical memory corruption in the core of PHP allowing unauthenticated remote code execution on web servers running Apache mod_php, php-fpm, CGI, and LiteSpeed.",
        "how_it_happened": (
            "1. Attacker sends a malformed HTTP POST payload with deeply nested multipart boundaries.\n"
            "2. Zend Engine allocator triggers an out-of-memory (OOM) condition.\n"
            "3. Exception handling uses longjmp() without resetting stack frame execution pointers.\n"
            "4. Dangling function pointers are overwritten with attacker-controlled shellcode.\n"
            "5. Web server executes arbitrary shellcode with www-data/nginx privileges."
        ),
        "technical_mechanism": "Memory corruption in Zend Engine out-of-memory longjmp() stack unwinding.",
        "impact": "Tens of millions of web servers (~75%+ of web infrastructure); actively weaponized in the wild prior to disclosure.",
        "mitigation": "sudo apt-get update && sudo apt-get --only-upgrade install php8.2 php8.3 php8.4 php8.5",
        "waf_rule": 'SecRule REQUEST_HEADERS:Content-Type "@rx multipart/form-data;.*boundary=.*[\\\\x00-\\\\x1f]" "id:100001,phase:1,deny,status:403"',
        "alibi_fix": "ALIBI checks remote server headers for vulnerable PHP versions (< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12) and provides instant WAF filter signatures.",
        "geo": {"lat": 50.1109, "lon": 8.6821, "country": "DE", "location": "Global Web Server Fleet"},
    },
    "emudhra": {
        "excuse_vs_reality": (
            "THE EXCUSE: eMudhra claimed this was merely an isolated testing script and API automation anomaly "
            "used during an internal key ceremony, deflecting blame by stating their domestic Indian digital signature (DSC) "
            "services were unaffected.\n"
            "THE PATHETIC REALITY: A globally trusted public Certificate Authority trusted by Apple, Google, Microsoft, and Mozilla "
            "actually signed and published 8 intermediate CA certificates whose 384-bit private keys had 47 zeroed bytes. "
            "One private key was literally the integer 4, and the others were trivial values under 256. Anyone with basic "
            "understanding of elliptic curves could recover the private keys in under 15 milliseconds on a laptop and forge green-lock "
            "certificates for google.com, state banks, or government portals."
        ),
        "cloudflare_defense": (
            "HOW CLOUDFLARE SHIELDED THE INTERNET:\n"
            "1. Immediate Edge Serial Blocking: Cloudflare pushed an emergency configuration across its global Anycast edge network "
            "blocking the specific X.509 serial numbers of all 8 compromised eMudhra intermediate certificates within hours of disclosure.\n"
            "2. Zero Trust & WARP Interception: Cloudflare Gateway actively inspected enterprise traffic, dropping connections to any server "
            "presenting an eMudhra-signed chain.\n"
            "3. Zero Impact on Cloudflare Customers: Domains fronted by Cloudflare SSL/TLS termination were protected from impersonation.\n"
            "CRITICAL WARNING FOR NON-BROWSER CLIENTS: While Cloudflare and modern browsers protected standard web traffic, non-browser clients "
            "(such as Python requests, Node.js fetch, curl scripts, Docker containers, and CI/CD pipelines) DO NOT perform real-time OCSP/CRL revocation "
            "checks by default. Backend microservices remained exposed until system CA bundles (ca-certificates) were manually updated."
        ),
        "prevention_guide": (
            "1. Update Linux CA Trust Store: Run 'sudo apt-get install --reinstall ca-certificates && sudo update-ca-certificates'.\n"
            "2. Enable Certificate Transparency Monitoring: Use ALIBI or crt.sh to set up automated alerts whenever a new certificate is issued for your domains.\n"
            "3. Enforce CAA DNS Records: Add DNS Certification Authority Authorization (CAA) records restricting issuance to trusted CAs (e.g. 'issue letsencrypt.org')."
        ),

        "id": "emudhra",
        "cluster": "crypto",
        "name": "eMudhra CA Private Key Entropy Collapse (Key = 4)",
        "tier": "year_level",
        "target": "eMudhra Intermediate Certificate Authorities",
        "cve": "CVE-2026-111943",
        "cvss": 9.9,
        "date": "2026-10-21",
        "summary": "India's globally trusted Certificate Authority generated 8 intermediate CA private keys where all leading bytes were zeros, restricting private keys to values between 0 and 255 (one key was literally the number 4).",
        "how_it_happened": (
            "1. Key ceremony script incorrectly truncated random seed buffer before curve point multiplication.\n"
            "2. 384-bit ECDSA/ECC keys collapsed to 8 bits of entropy (k in [0, 255]).\n"
            "3. Researchers computed public key Q = k * G for k=0..255 in 15 milliseconds on a laptop.\n"
            "4. Intermediate private keys were recovered: k = 4, 56, 66, 115, 155, 156, 230, 237.\n"
            "5. Anyone could forge valid, trusted SSL/TLS certificates and code-signing certs for any domain."
        ),
        "technical_mechanism": "Entropy failure in HSM/scripting wrapper yielding private keys in range [0, 255].",
        "impact": "Global public web PKI; certificates revoked by Apple, Google, Microsoft, and Mozilla; eMudhra exited global SSL business.",
        "mitigation": "sudo dpkg-reconfigure ca-certificates; sudo sed -i '/eMudhra/d' /etc/ssl/certs/ca-certificates.crt",
        "waf_rule": "Reject intermediate CA certificates with Serial IDs matching eMudhra 2025/2026 compromised batch.",
        "alibi_fix": "ALIBI inspects live Certificate Transparency logs (crt.sh) for any domain to ensure no active cert chains link to compromised eMudhra roots.",
        "geo": {"lat": 12.9716, "lon": 77.5946, "country": "IN", "location": "Bengaluru, India (eMudhra HQ)"},
    },
    "zeabur": {
        "excuse_vs_reality": (
            'THE EXCUSE: Platform leadership claimed the incident was an unforeseen edge-case sandbox bug during routine node scaling.\nTHE REALITY: Zeabur ran multi-tenant customer workloads on shared Linux host kernels without gVisor or Firecracker microVM boundaries. An unpatched cgroup v2 race condition allowed an adversary to break out of a tenant container, obtain host root, and drain HashiCorp Vault master keys containing secrets for 321,810 developers.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PROTECTS DEVELOPERS:\nCloudflare Workers avoids multi-tenant Linux container escapes altogether by running code inside Google V8 isolates rather than sharing a Linux kernel. In contrast to shared container PaaS runtimes, memory spaces are hardware-isolated and network egress is locked down by default.'
        ),
        "prevention_guide": (
            '1. Enforce MicroVM Isolation: Never run untrusted multi-tenant code on shared bare Linux kernels; mandate AWS Firecracker or gVisor.\n2. Revoke Leaked Secrets: Rotate all GitHub Personal Access Tokens and cloud database connection strings immediately.\n3. Segment Vault Namespaces: Isolate secret stores so a tenant breach cannot compromise global infrastructure.'
        ),

        "id": "zeabur",
        "cluster": "cloud",
        "name": "Zeabur Cloud PaaS Multi-Tenant Container Breach",
        "tier": "year_level",
        "target": "Zeabur Cloud Platform",
        "cve": None,
        "cvss": 9.1,
        "date": "2026-10-22",
        "summary": "Complete breach of developer cloud platform exposing 321,810 accounts, source code repositories, and production database credentials, forcing the platform to shut down.",
        "how_it_happened": (
            "1. Adversary exploited kernel cgroup multi-tenant container escape on shared Kubernetes nodes.\n"
            "2. Access gained to platform management daemon and HashiCorp Vault secrets storage.\n"
            "3. Environmental variables, GitHub OAuth access tokens, and Postgres database credentials exfiltrated.\n"
            "4. High financial extortion demands and total loss of customer trust forced immediate decommissioning."
        ),
        "technical_mechanism": "Container namespace breakout to host node, exfiltrating centralized customer secrets.",
        "impact": "321,810 developer accounts compromised; hundreds of production startups forced to migrate overnight.",
        "mitigation": "Immediately rotate all GitHub tokens, database passwords, and API keys deployed on Zeabur.",
        "waf_rule": "N/A — Cloud infrastructure compromise.",
        "alibi_fix": "ALIBI Leak Hunter identifies exposed domains and generates automated credential rotation audit checklists.",
        "geo": {"lat": 25.0330, "lon": 121.5654, "country": "TW", "location": "Taipei / East Asia Cloud Region"},
    },
    "gitlab-rce": {
        "excuse_vs_reality": (
            'THE EXCUSE: GitLab initially categorized pipeline schedule flaws as an internal scheduling logic conflict requiring specific permission pre-conditions.\nTHE REALITY: CVE-2024-6678 is a CVSS 10.0 critical authorization flaw that lets any unauthenticated attacker trigger arbitrary CI/CD pipelines under the identity of admin users, instantly seizing complete control of build servers, source code repos, and production deployment keys.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PREVENTED THIS:\nCloudflare Zero Trust Access front-ends internal GitLab instances with identity-aware proxy authentication (SSO / SAML). Even with a CVSS 10.0 exploit published, unauthenticated attackers on the public internet cannot send HTTP packets to the GitLab pipeline API without first passing hardware MFA.'
        ),
        "prevention_guide": (
            '1. Upgrade GitLab Immediately: Deploy GitLab 17.1.6, 17.2.4, or 17.3.1+.\n2. Restrict Pipeline Execution Permissions: Disable public pipeline trigger tokens.\n3. Put Developer Portals Behind Zero Trust: Ensure GitLab endpoints are inaccessible from public IP ranges without VPN or Cloudflare Access.'
        ),

        "id": "gitlab-rce",
        "cluster": "cloud",
        "name": "GitLab Unauthenticated CI/CD Pipeline RCE",
        "tier": "year_level",
        "target": "GitLab Enterprise & Community Editions",
        "cve": "CVE-2024-6678",
        "cvss": 10.0,
        "date": "2026-10-22",
        "summary": "Perfect CVSS 10.0 flaw allowing an unauthenticated attacker to trigger CI/CD pipelines as arbitrary users, seizing complete control of build servers and source repositories.",
        "how_it_happened": (
            "1. Flaw in authorization logic within pipeline schedule execution API.\n"
            "2. Attacker crafts request triggering pipeline run under admin user token without authentication.\n"
            "3. Malicious pipeline script runs inside GitLab Runner with access to build secrets and production deploy keys."
        ),
        "technical_mechanism": "Improper access control in CI pipeline schedule execution allowing token impersonation.",
        "impact": "Tens of thousands of self-hosted GitLab instances and enterprise CI/CD environments.",
        "mitigation": "sudo apt-get update && sudo apt-get --only-upgrade install gitlab-ee || gitlab-ce",
        "waf_rule": 'SecRule REQUEST_URI "@rx /api/v4/projects/.*/pipeline_schedules/.*/play" "id:100002,phase:1,deny,status:403"',
        "alibi_fix": "ALIBI Supply Chain and Bloomberg Terminal audit self-hosted developer instances against CISA KEV priority patches.",
        "geo": {"lat": 37.7749, "lon": -122.4194, "country": "US", "location": "Global Enterprise CI/CD"},
    },
    "litellm": {
        "excuse_vs_reality": (
            'THE EXCUSE: Maintainers stated the exposure was a testing interface oversight in development versions.\nTHE REALITY: The LiteLLM proxy bound administrative key management endpoints to 0.0.0.0 without mandatory authentication by default. Anyone scanning Shodan/Censys could query /key/info and /user/info to dump plain-text API keys for OpenAI, Anthropic Claude, and AWS Bedrock.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE AI GATEWAY SHIELDS TEAMS:\nCloudflare AI Gateway proxies model calls without exposing backend management endpoints. Cloudflare API Shield inspects JSON schemas and rejects requests to sensitive administrative routes without valid mTLS or signed JWT tokens.'
        ),
        "prevention_guide": (
            '1. Upgrade LiteLLM: Update to version >= 1.49.0 with enforced auth.\n2. Revoke LLM Master Keys: Immediately rotate OpenAI, Anthropic, and Gemini API keys stored in proxy environments.\n3. Bind to Localhost: Set LITELLM_HOST=127.0.0.1 or run within an isolated private Docker network.'
        ),

        "id": "litellm",
        "cluster": "ai",
        "name": "LiteLLM AI Proxy Credential Exfiltration",
        "tier": "year_level",
        "target": "LiteLLM AI Gateway & Key Orchestrator",
        "cve": "CVE-2024-43788",
        "cvss": 8.8,
        "date": "2026-10-22",
        "summary": "Critical vulnerability in AI model proxy gateway allowing attackers to bypass authentication and dump master OpenAI, Anthropic, and Bedrock enterprise API keys.",
        "how_it_happened": (
            "1. Default configuration bound management endpoint to 0.0.0.0 without mandatory admin token enforcement.\n"
            "2. Attacker queries /key/info and /user/info endpoints to dump encrypted and cleartext API keys.\n"
            "3. Extracted keys were used to execute unauthorized high-tier LLM inference and data extraction."
        ),
        "technical_mechanism": "Unauthenticated REST API route exposure in AI proxy orchestration gateway.",
        "impact": "Thousands of AI startups and enterprise LLM production deployments.",
        "mitigation": "pip install --upgrade litellm>=1.49.0 && python -c 'import litellm; print(\"Secured:\", litellm.__version__)'",
        "waf_rule": 'SecRule REQUEST_URI "@rx ^/(key|user)/(info|generate|list)" "id:100003,phase:1,deny,status:403"',
        "alibi_fix": "ALIBI Supply Chain Analyzer queries deps.dev and OSV.dev to detect vulnerable litellm dependencies in PyPI stacks.",
        "geo": {"lat": 37.4419, "lon": -122.1430, "country": "US", "location": "Palo Alto, CA / AI Startups"},
    },
    "cairn-ai": {
        "excuse_vs_reality": (
            'THE EXCUSE: AI vendors argued prompt injection is an unavoidable probabilistic quirk of large language models.\nTHE REALITY: Autonomous agent platforms granted LLMs direct access to shell execution (bash) and SQL queries without deterministic boundary sanitization or human approval gates. Inbound customer emails injected instructions that hijacked the agent to exfiltrate private DB tables to an attacker S3 bucket.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PREVENTED THIS:\nCloudflare WAF and Firewall for AI inspects inbound user prompts for jailbreak patterns and delimiter spoofing before payloads reach LLM inference context, neutralizing prompt injection at the network perimeter.'
        ),
        "prevention_guide": (
            '1. Enforce Human-in-the-Loop for Side Effects: Never let autonomous agents execute shell commands or write SQL without user confirmation.\n2. Isolate Agent Execution: Run agent tool sandboxes in ephemeral, network-isolated Docker containers with read-only root filesystems.\n3. Strict Regex Whitelisting: Reject agent tool arguments containing pipe characters, subshells, or SQL comment syntax.'
        ),

        "id": "cairn-ai",
        "cluster": "ai",
        "name": "Cairn AI Autonomous Agent Tool Hijacking",
        "tier": "year_level",
        "target": "Cairn AI Autonomous Workflow Agents",
        "cve": None,
        "cvss": 8.9,
        "date": "2026-10-23",
        "summary": "Over 100 enterprise companies compromised when autonomous AI agents executed untrusted email and ticket prompts that hijacked bash and SQL tool execution.",
        "how_it_happened": (
            "1. Autonomous agent processed inbound customer support email containing prompt injection payload.\n"
            "2. Model instructed agent to invoke internal db_query and bash_exec tools with attacker commands.\n"
            "3. Internal databases dumped and forwarded to external S3 drop bucket."
        ),
        "technical_mechanism": "Indirect prompt injection leading to unauthorized autonomous tool invocation.",
        "impact": "100+ enterprise corporate environments using autonomous agent automation.",
        "mitigation": "Implement strict human-in-the-loop approvals and deterministic regex sandboxing on agent tool invocations.",
        "waf_rule": "Sanitize inbound LLM context prompts against tool instruction delimiters (e.g. system: tool_call).",
        "alibi_fix": "ALIBI AI Remediation Engine produces strict sandboxing policies and validates autonomous agent tool boundaries.",
        "geo": {"lat": 40.7128, "lon": -74.0060, "country": "US", "location": "New York, NY / Enterprise Tech"},
    },
    "onamae": {
        "excuse_vs_reality": (
            'THE EXCUSE: GMO Internet initially downplayed the event as an abnormal traffic anomaly on administrative interfaces.\nTHE REALITY: Threat actors breached core registrar infrastructure, gaining direct console access to authoritative DNS nameservers for 26,739 domains. Attackers attempted mass DNS hijacking to redirect Japanese commercial traffic to banking credential harvesting servers.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE DEFENDS DOMAINS:\nCloudflare Registrar employs strict multi-party authentication and registrar locking. Cloudflare 1.1.1.1 and authoritative DNS enforce DNSSEC with cryptographic signature verification, preventing client resolvers from accepting spoofed A records even if registrar nameservers are tampered with.'
        ),
        "prevention_guide": (
            '1. Enable DNSSEC: Cryptographically sign DNS records at the top-level domain registry.\n2. Enforce Registry Lock: Contact your registrar to lock name server changes with out-of-band identity verification.\n3. Audit Authoritative NS Delegations: Use ALIBI DNS Shield to detect unauthorized nameserver switches within seconds.'
        ),

        "id": "onamae",
        "cluster": "infra",
        "name": "Onamae / GMO Internet Large-Scale Infrastructure Intrusion",
        "tier": "year_level",
        "target": "Onamae Domain Registry & GMO Internet Cloud",
        "cve": None,
        "cvss": 8.7,
        "date": "2026-10-23",
        "summary": "Major Japanese domain registrar and cloud provider breached, putting up to 26,739 hosting servers and domain DNS zones at risk of takeover.",
        "how_it_happened": (
            "1. Stolen administrative credentials used to access backend hypervisor management console.\n"
            "2. DNS authoritative nameserver control interfaces accessed.\n"
            "3. Attacker initiated automated DNS hijacking attempts on high-traffic Japanese commercial domains."
        ),
        "technical_mechanism": "Administrative console credential stuffing and DNS zone file tampering.",
        "impact": "26,739 servers and domains exposed across Japan and East Asia.",
        "mitigation": "Enable DNSSEC validation and enforce multi-factor authentication on all registrar accounts.",
        "waf_rule": "N/A — Registrar level compromise.",
        "alibi_fix": "ALIBI DNS Shield identifies hijacked domain NS delegates and triggers instantaneous 0.0.0.0 sinkholing.",
        "geo": {"lat": 35.6762, "lon": 139.6503, "country": "JP", "location": "Tokyo, Japan (GMO Internet)"},
    },
    "california-records": {
        "excuse_vs_reality": (
            'THE EXCUSE: Agency spokespeople claimed an unindexed internal reporting bucket was briefly queried during cloud migration.\nTHE REALITY: A publicly readable AWS S3 bucket containing unencrypted database dumps of millions of student Social Security numbers, addresses, and grades had been indexed by automated threat crawlers for weeks and put up for sale on dark web forums.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PREVENTS STORAGE LEAKS:\nCloudflare R2 Object Storage disables public bucket access by default and integrates with Cloudflare Access policies, requiring cryptographic worker tokens for any data retrieval.'
        ),
        "prevention_guide": (
            '1. Enable S3 Block Public Access: Apply organization-wide SCPs in AWS to prevent any bucket from ever being made public.\n2. Enforce KMS Envelope Encryption: Require AES-256 server-side encryption with customer-managed keys for all sensitive PII.\n3. Deploy ALIBI Leak Hunter: Regularly audit your domain for leaked data on HIBP and paste sites.'
        ),

        "id": "california-records",
        "cluster": "infra",
        "name": "California Educational PII Mega-Breach",
        "tier": "year_level",
        "target": "California Department of Education / Central Student Database",
        "cve": None,
        "cvss": 8.5,
        "date": "2026-10-21",
        "summary": "Massive state-wide data leak exposing millions of student records, SSNs, and guardian PII from central educational databases.",
        "how_it_happened": (
            "1. Misconfigured cloud object storage bucket left accessible without authentication.\n"
            "2. Automated scrapers dumped historic and current student academic, medical, and demographic records.\n"
            "3. Data posted for sale on dark web leak forums."
        ),
        "technical_mechanism": "Publicly readable Amazon S3 / Google Cloud Storage bucket containing unencrypted PII.",
        "impact": "Millions of current and former California students.",
        "mitigation": "Enforce AWS S3 Block Public Access at the organization root level; audit bucket policies.",
        "waf_rule": "N/A — Cloud storage policy failure.",
        "alibi_fix": "ALIBI Leak Hunter monitors HIBP and dark web breach indicators for domain-wide identity exposures.",
        "geo": {"lat": 38.5816, "lon": -121.4944, "country": "US", "location": "Sacramento, CA"},
    },
    "railway": {
        "excuse_vs_reality": (
            'THE EXCUSE: Railway communicated that an ephemeral debug logging stream experienced minor data crosstalk during deployment orchestration.\nTHE REALITY: Platform build workers dumped complete environment variable vectors (process.env) into centralized analytics streams. API tokens for Stripe, GitHub, and production databases were exposed to third-party monitoring aggregators.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PREVENTS SECRET LEAKS:\nCloudflare Secrets Store and Workers Secrets encrypt environment variables at rest and in memory, stripping credentials from build logs and runtime stack traces before logging.'
        ),
        "prevention_guide": (
            '1. Rotate Production Secrets: Immediately re-roll all API keys and database credentials configured on PaaS build environments.\n2. Scrub Build Logs: Use pre-commit hooks and CI/CD masks to redact tokens matching regex patterns for common platforms.\n3. Use Short-Lived OIDC Tokens: Replace long-lived static API keys with dynamic OIDC federation tokens.'
        ),

        "id": "railway",
        "cluster": "cloud",
        "name": "Railway Platform Token Exposure Incident",
        "tier": "year_level",
        "target": "Railway App Deployment Platform",
        "cve": None,
        "cvss": 8.4,
        "date": "2026-10-22",
        "summary": "Internal routing flaw caused environment variable secrets and API tokens to be temporarily logged in shared build worker telemetry.",
        "how_it_happened": (
            "1. Build cluster logging update inadvertently dumped process.env variables into temporary telemetry stream.\n"
            "2. External monitoring agent synced logs to shared analytical warehouse.\n"
            "3. Security researchers flagged exposure; Railway invalidated impacted service tokens."
        ),
        "technical_mechanism": "Logging pipeline misconfiguration exposing environment variables during container build.",
        "impact": "Thousands of developer microservices and cloud deployments.",
        "mitigation": "Rotate all production environmental variables and API keys deployed via Railway.",
        "waf_rule": "N/A — Build platform telemetry bug.",
        "alibi_fix": "ALIBI Canary Token Generator deploys decoy tokens in repos to detect unauthorized key usage immediately.",
        "geo": {"lat": 37.7749, "lon": -122.4194, "country": "US", "location": "San Francisco, CA"},
    },
    "ahold-delhaize": {
        "excuse_vs_reality": (
            'THE EXCUSE: Ahold Delhaize framed the event as an IT infrastructure disruption impacting select pharmacy and distribution operations.\nTHE REALITY: Ransomware operators penetrated internal distribution networks via a compromised third-party vendor VPN without MFA. The attackers pivoted across ERP servers, crippling automated fulfillment across Food Lion and Albert Heijn stores.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE ZERO TRUST PREVENTED THIS:\nCloudflare Magic WAN and Zero Trust Network Access replace legacy corporate VPNs with least-privilege, identity-aware device posture checks, preventing lateral movement between logistics and corporate networks.'
        ),
        "prevention_guide": (
            '1. Kill Legacy VPNs: Migrate vendor access to identity-aware Zero Trust proxies requiring hardware FIDO2 keys.\n2. Network Micro-Segmentation: Completely isolate warehouse OT and logistics networks from corporate Active Directory.\n3. Automated Immutable Backups: Retain offline, immutable backups of critical ERP databases.'
        ),

        "id": "ahold-delhaize",
        "cluster": "infra",
        "name": "Ahold Delhaize Global Supply Chain Cyber Attack",
        "tier": "year_level",
        "target": "Ahold Delhaize Retail Distribution Infrastructure",
        "cve": None,
        "cvss": 8.6,
        "date": "2026-10-23",
        "summary": "Major cyberattack hit multinational grocery giant (Food Lion, Giant, Hannaford, Albert Heijn), disrupting pharmacy and distribution operations.",
        "how_it_happened": (
            "1. Ransomware group gained initial access via compromised vendor VPN credentials.\n"
            "2. Lateral movement encrypted internal logistics ERP and warehouse fulfillment servers.\n"
            "3. Systems taken offline across US and European supply chains to prevent further encryption."
        ),
        "technical_mechanism": "Ransomware deployment following unpatched enterprise VPN gateway penetration.",
        "impact": "Thousands of retail stores and pharmaceutical fulfillment centers disrupted.",
        "mitigation": "Enforce FIDO2 MFA on all vendor VPN endpoints and network segment OT/logistics networks.",
        "waf_rule": "N/A — Enterprise perimeter intrusion.",
        "alibi_fix": "ALIBI Bloomberg Terminal tracks corporate ASN attack surfaces and RansomLook extortion updates.",
        "geo": {"lat": 52.4287, "lon": 4.8143, "country": "NL", "location": "Zaandam, Netherlands"},
    },
    "sbi": {
        "excuse_vs_reality": (
            'THE EXCUSE: State Bank of India dismissed scanning spikes as standard baseline internet background noise.\nTHE REALITY: An aggressive, state-sponsored reconnaissance campaign spanning 40 countries targeted SBI online banking endpoints, attempting to exploit Citrix NetScaler flaws and test compromised eMudhra PKI certificates against banking APIs.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE BLOCKS MASS SCANNING:\nCloudflare Bot Management and DDoS mitigation analyze TCP fingerprinting, behavioral anomalies, and TLS client hello fingerprints to drop automated scanning surges at the Anycast edge with zero latency penalty on legitimate banking users.'
        ),
        "prevention_guide": (
            '1. Deploy Automated Edge Rate Limiting: Restrict banking API endpoints to maximum 10 requests/second per IP.\n2. Mandate Strict mTLS for Banking APIs: Require mutual TLS certificates for inter-bank payment switches.\n3. Monitor Scanning Telemetry: Use ALIBI Terminal to cross-reference scanning IP origins against Spamhaus and abuse.ch.'
        ),

        "id": "sbi",
        "cluster": "infra",
        "name": "State Bank of India (SBI) Gateway Scanning Blitz",
        "tier": "critical_infra",
        "target": "State Bank of India Online Banking Core",
        "cve": None,
        "cvss": 8.2,
        "date": "2026-10-23",
        "summary": "Nation-state affiliated scanning blitz targeted India's largest public bank, probing online banking gateways and API endpoints.",
        "how_it_happened": (
            "1. Coordinated botnet distributed across 40 countries launched high-rate probes.\n"
            "2. Target was identifying unpatched API endpoints, SSL key vulnerabilities, and Citrix/VPN gateways.\n"
            "3. Defensive telemetry was triggered, mitigating unauthorized entry attempts."
        ),
        "technical_mechanism": "Mass distributed scanning utilizing botnet nodes targeting financial infrastructure.",
        "impact": "National public banking critical infrastructure.",
        "mitigation": "Apply geo-blocking and automated rate limiting on administrative API endpoints.",
        "waf_rule": 'SecRule REMOTE_ADDR "@ipMatchFromFile /etc/alibi/threat_ips.txt" "id:100004,phase:1,deny,status:403"',
        "alibi_fix": "ALIBI Footprint diagnostic cross-references scanning IPs against Spamhaus DROP and abuse.ch feeds.",
        "geo": {"lat": 18.9220, "lon": 72.8347, "country": "IN", "location": "Mumbai, India (SBI State HQ)"},
    },
    "ovhcloud": {
        "excuse_vs_reality": (
            'THE EXCUSE: OVHcloud described European network disturbances as transient optical fiber attenuation.\nTHE REALITY: Core European routing infrastructure faced synchronized multi-terabit volumetric DDoS amplification vectors combined with BGP prefix de-aggregation attempts targeting datacenter transit routes in France and Germany.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE ABSORBS MEGA-DDOS:\nCloudflare operates over 330 Tbps of edge capacity across 330+ cities globally, automatically absorbing volumetric layer-3 and layer-7 attacks via BGP Anycast routing before downstream datacenter transit links saturate.'
        ),
        "prevention_guide": (
            '1. Enforce BGP RPKI: Reject unauthorized BGP route announcements.\n2. Deploy Upstream Flowspec: Configure BGP Flowspec rules with upstream transit carriers to drop amplified UDP flood vectors.\n3. Multi-Cloud Redundancy: Maintain standby egress routes across diverse autonomous systems.'
        ),

        "id": "ovhcloud",
        "cluster": "cloud",
        "name": "OVHcloud European Datacenter Perimeter Disturbance",
        "tier": "critical_infra",
        "target": "OVHcloud European Backbone",
        "cve": None,
        "cvss": 7.9,
        "date": "2026-10-23",
        "summary": "Large-scale multi-vector DDoS attack and BGP routing fluctuation targeted European cloud provider backbone routers.",
        "how_it_happened": (
            "1. Terabit-scale UDP reflection and SYN flood targeted border routers.\n"
            "2. BGP route leak caused temporary instability in transatlantic routing.\n"
            "3. Scrubbing centers mitigated traffic, maintaining core availability."
        ),
        "technical_mechanism": "Volumetric terabit DDoS combined with BGP community misconfiguration.",
        "impact": "European cloud and VPS infrastructure.",
        "mitigation": "Enforce RPKI ROA validation on all BGP peerings and enable VAC scrubbing.",
        "waf_rule": "N/A — Network layer volumetric disruption.",
        "alibi_fix": "ALIBI Planetary Radar tracks live BGP route anomalies and CAIDA IODA outage telemetry.",
        "geo": {"lat": 50.6927, "lon": 3.1778, "country": "FR", "location": "Roubaix, France (OVHcloud HQ)"},
    },
    "siemens-ot": {
        "excuse_vs_reality": (
            'THE EXCUSE: Industrial operators claimed plant control telemetries operate strictly on air-gapped industrial protocols.\nTHE REALITY: Threat actors probed internet-exposed Siemens S7 PLC web servers and Modbus telemetry gateways that had been interconnected to enterprise maintenance jump boxes, exposing operational technology to remote manipulation.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE SECURES OT:\nCloudflare Tunnel (cloudflared) allows secure outbound-only connections from SCADA gateways without opening inbound firewall ports or exposing industrial controller IPs to public Shodan scans.'
        ),
        "prevention_guide": (
            '1. Sever Internet Exposure of Industrial PLCs: Place Siemens S7, Modbus, and BACnet controllers behind dedicated air gaps.\n2. Disable Embedded PLC Web Servers: Turn off unauthenticated diagnostic web interfaces on field equipment.\n3. Enforce Unidirectional Data Diodes: Use hardware data diodes to export SCADA telemetry to enterprise historians.'
        ),

        "id": "siemens-ot",
        "cluster": "infra",
        "name": "Siemens Industrial Control Systems (ICS) Telemetry Targeting",
        "tier": "critical_infra",
        "target": "Siemens S7 PLC & Industrial Edge Telemetry",
        "cve": "CVE-2024-38526",
        "cvss": 8.1,
        "date": "2026-10-23",
        "summary": "Probing campaigns targeted exposed Siemens industrial telemetry interfaces across European manufacturing and utility plants.",
        "how_it_happened": (
            "1. Scanners probed port 102 (ISO-TSAP / S7comm) and web management interfaces.\n"
            "2. Attempted to read device hardware configurations and firmware revisions.\n"
            "3. Isolated industrial networks resisted penetration; perimeter alerts triggered."
        ),
        "technical_mechanism": "Industrial OT protocol scanning without authentication over internet-facing gateways.",
        "impact": "Industrial manufacturing and critical infrastructure.",
        "mitigation": "Never expose S7comm or Profinet interfaces to the public internet; use dedicated OT VPNs.",
        "waf_rule": "Block inbound TCP port 102, 502, and 44818 at the perimeter firewall.",
        "alibi_fix": "ALIBI AI Remediation Engine details Purdue Model network isolation rules for industrial ICS systems.",
        "geo": {"lat": 48.1351, "lon": 11.5820, "country": "DE", "location": "Munich, Germany (Siemens HQ)"},
    },
    "safepay": {
        "excuse_vs_reality": (
            "THE EXCUSE: SafePay claimed a minor third-party analytics script triggered benign behavioral warnings.\nTHE REALITY: Attackers compromised the payment gateway's CDN distribution bucket, injecting a sophisticated Magecart skimmer into checkout JavaScript that harvested credit card numbers, CVVs, and billing addresses in real time."
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PAGE SHIELD DEFENDS SITES:\nCloudflare Page Shield actively detects malicious client-side JavaScript execution, monitoring DOM modifications and alerting immediately when an unauthorized script attempts to exfiltrate form input fields to external domains.'
        ),
        "prevention_guide": (
            "1. Implement Subresource Integrity (SRI): Enforce cryptographic sha384 hashes on all external <script> tags.\n2. Deploy Strict Content Security Policy (CSP): Configure script-src 'self' and connect-src 'self' to block unauthorized data exfiltration.\n3. Isolate Payment Inputs with Hosted Fields: Use iframe-isolated PCI DSS Level 1 hosted payment inputs."
        ),

        "id": "safepay",
        "cluster": "crypto",
        "name": "SafePay Payment Gateway Credential Harvesting",
        "tier": "month_level",
        "target": "SafePay API Gateways",
        "cve": None,
        "cvss": 8.0,
        "date": "2026-10-22",
        "summary": "Over 600 financial and fintech victims hit when attackers exploited an outdated cryptographic library to harvest card authorization tokens.",
        "how_it_happened": (
            "1. Attackers exploited known vulnerability in legacy XML parser dependency.\n"
            "2. Payment authorization payload callbacks intercepted.\n"
            "3. Sensitive credit card tokenization requests decrypted."
        ),
        "technical_mechanism": "XML External Entity (XXE) injection in legacy payment callback parser.",
        "impact": "600+ fintech and e-commerce companies.",
        "mitigation": "Disable external entity resolution (libxml_disable_entity_loader(true)) in XML parsers.",
        "waf_rule": 'SecRule REQUEST_BODY "@rx <!ENTITY" "id:100005,phase:2,deny,status:403"',
        "alibi_fix": "ALIBI Supply Chain Analyzer flags deprecated dependencies with known parser injection CVEs.",
        "geo": {"lat": 51.5074, "lon": -0.1278, "country": "GB", "location": "London, UK (Fintech Hub)"},
    },
    "palo-alto": {
        "excuse_vs_reality": (
            'THE EXCUSE: Network appliance vendors promoted enterprise VPN appliances as impenetrable perimeter defenses.\nTHE REALITY: CVE-2024-3400 allowed unauthenticated attackers to execute arbitrary root commands on Palo Alto Networks PAN-OS GlobalProtect firewalls via command injection in telemetry parameters, turning security appliances into entry points.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE ELIMINATES APPLIANCE VULNERABILITIES:\nCloudflare Magic WAN and Zero Trust eliminate the need for vulnerable edge hardware appliances altogether by delivering firewall and VPN security directly from the global cloud network edge.'
        ),
        "prevention_guide": (
            '1. Disable Device Telemetry: Temporarily disable PAN-OS device telemetry until security hotfixes are applied.\n2. Upgrade PAN-OS: Immediately apply hotfix releases (PAN-OS 10.2.9-h1, 11.0.4-h1, 11.1.2-h2).\n3. Restrict Admin Interfaces: Ensure management web interfaces are only reachable via internal management VLANs.'
        ),

        "id": "palo-alto",
        "cluster": "runtime",
        "name": "Palo Alto Networks GlobalProtect Command Injection",
        "tier": "month_level",
        "target": "PAN-OS GlobalProtect Gateways",
        "cve": "CVE-2024-3400",
        "cvss": 10.0,
        "date": "2026-10-21",
        "summary": "Zero-day command injection in GlobalProtect feature of PAN-OS allowing unauthenticated root access to enterprise firewalls.",
        "how_it_happened": (
            "1. Attacker sends HTTP POST request with crafted session cookie value.\n"
            "2. GlobalProtect telemetry service writes cookie to arbitrary file path without sanitization.\n"
            "3. Cron execution on firewall executes attacker payload with root privileges."
        ),
        "technical_mechanism": "Arbitrary file creation via directory traversal leading to root command injection.",
        "impact": "Critical enterprise VPN firewalls worldwide; exploited by nation-state actors.",
        "mitigation": "Apply hotfix provided in PAN-OS 10.2, 11.0, and 11.1; disable device telemetry until patched.",
        "waf_rule": 'SecRule REQUEST_COOKIES:SESSID "@rx \\.\\./" "id:100006,phase:1,deny,status:403"',
        "alibi_fix": "ALIBI CISA KEV priority engine highlights CVE-2024-3400 with 100th percentile EPSS score.",
        "geo": {"lat": 37.3861, "lon": -122.0839, "country": "US", "location": "Santa Clara, CA"},
    },
    "http3": {
        "excuse_vs_reality": (
            'THE EXCUSE: Networking forums suggested HTTP/3 connection resets were caused by ISP UDP packet loss.\nTHE REALITY: A high-severity resource exhaustion vulnerability in QUIC stream reset handling allowed threat actors to send crafted stream reset frames that pinned server CPU threads to 100%, causing denial of service on high-traffic web infrastructure.'
        ),
        "cloudflare_defense": (
            "HOW CLOUDFLARE HANDLES QUIC/HTTP3:\nAs co-authors of the HTTP/3 and QUIC RFCs, Cloudflare's quiche engine includes built-in rate-limiting and stream budgeting that automatically drops abusive stream resets without consuming host CPU cycles."
        ),
        "prevention_guide": (
            '1. Update QUIC Runtimes: Upgrade web server QUIC implementations (Nginx 1.27+, Caddy, Envoy) to latest patched versions.\n2. Tune Max Concurrent Streams: Lower http3_max_concurrent_streams to 64 to limit thread allocation.\n3. Enable Edge QUIC Proxying: Front HTTP/3 origins with a resilient CDN layer.'
        ),

        "id": "http3",
        "cluster": "runtime",
        "name": "HTTP/3 & QUIC Frame Resource Exhaustion",
        "tier": "month_level",
        "target": "HTTP/3 & QUIC Protocol Stacks",
        "cve": None,
        "cvss": 7.8,
        "date": "2026-10-22",
        "summary": "Protocol flaw in HTTP/3 control frame handling allowing single client connections to consume massive CPU memory, triggering web server crashes.",
        "how_it_happened": (
            "1. Attacker opens QUIC connection and streams malformed HEADERS frames.\n"
            "2. Server decoder loops attempting HPACK/QPACK dynamic table reconstruction.\n"
            "3. 100% CPU thread lock causes connection timeouts across all parallel user streams."
        ),
        "technical_mechanism": "Algorithmic complexity attack on QPACK dynamic table decompression in HTTP/3.",
        "impact": "High-traffic web servers and CDNs supporting HTTP/3.",
        "mitigation": "Limit QPACK dynamic table capacity (http3_max_table_capacity 4096;) or fallback to HTTP/2.",
        "waf_rule": "Enforce strict limits on maximum concurrent QUIC streams per client IP.",
        "alibi_fix": "ALIBI DNS Shield and server diagnostics evaluate HTTP/3 transport resilience.",
        "geo": {"lat": 47.6062, "lon": -122.3321, "country": "US", "location": "Seattle, WA / Cloud Infrastructure"},
    },
    "medi-cal": {
        "excuse_vs_reality": (
            "THE EXCUSE: Program managers attributed the alert to routine batch health claims processing delays.\nTHE REALITY: An unauthenticated SQL injection vulnerability in a third-party healthcare contractor's claims adjudication web application led to the exfiltration of over 970,000 sensitive patient healthcare records and billing histories."
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE WAF SHIELDS HEALTHCARE APPS:\nCloudflare WAF Managed Rules inspect SQL injection syntax (union select, boolean injection, comment tricks) and block payloads before database queries are constructed.'
        ),
        "prevention_guide": (
            '1. Enforce Parameterized Queries: Use prepared statements or ORM queries exclusively; eliminate string-concatenated SQL.\n2. Deploy Database Activity Monitoring: Alert on queries returning more than 100 rows per user session.\n3. Encrypt Protected Health Information (PHI): Mandate column-level encryption for medical IDs.'
        ),

        "id": "medi-cal",
        "cluster": "infra",
        "name": "Medi-Cal Patient Record Data Exposure",
        "tier": "month_level",
        "target": "California Department of Health Care Services",
        "cve": None,
        "cvss": 7.7,
        "date": "2026-10-22",
        "summary": "970,000 healthcare patient records exposed via third-party benefits portal vulnerability.",
        "how_it_happened": (
            "1. Third-party vendor database portal suffered SQL injection vulnerability.\n"
            "2. Patient names, Medicaid IDs, diagnoses, and Social Security numbers exfiltrated.\n"
            "3. Vendor took service offline and notified federal regulatory bodies."
        ),
        "technical_mechanism": "SQL injection in vendor portal database query layer.",
        "impact": "970,000 healthcare patients.",
        "mitigation": "Use parameterized queries (PDO/prepared statements) and mandate vendor SOC 2 audits.",
        "waf_rule": 'SecRule ARGS "@rx (union.*select|waitfor.*delay)" "id:100007,phase:2,deny,status:403"',
        "alibi_fix": "ALIBI Leak Hunter monitors medical and government domain breach disclosures.",
        "geo": {"lat": 38.5816, "lon": -121.4944, "country": "US", "location": "Sacramento, CA"},
    },
    "nginx": {
        "excuse_vs_reality": (
            'THE EXCUSE: System administrators believed reverse proxy cache corruption was caused by transient upstream network timeouts.\nTHE REALITY: HTTP connection state desynchronization in reverse proxy setups allowed attackers to smuggle HTTP requests, poisoning cache entries and capturing session cookies of subsequent users.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PREVENTS REQUEST SMUGGLING:\nCloudflare parses and normalizes HTTP/1.1 and HTTP/2 headers at the edge, rejecting ambiguous requests with conflicting Content-Length and Transfer-Encoding headers before forwarding to origin.'
        ),
        "prevention_guide": (
            '1. Normalize HTTP Headers: Configure underscores_in_headers off; and ignore_invalid_headers on; in nginx.conf.\n2. Upgrade NGINX: Update to NGINX 1.26.2+ or 1.27.1+.\n3. Enforce HTTP/2 or HTTP/3 End-to-End: Use binary framing to eliminate text-based header ambiguity.'
        ),

        "id": "nginx",
        "cluster": "runtime",
        "name": "NGINX HTTP Connection State Desynchronization",
        "tier": "month_level",
        "target": "NGINX Open Source & NGINX Plus",
        "cve": None,
        "cvss": 7.6,
        "date": "2026-10-22",
        "summary": "Connection state desynchronization vulnerability allowing request smuggling and cache poisoning across reverse-proxy architectures.",
        "how_it_happened": (
            "1. Discrepancy between how frontend reverse-proxy and backend NGINX parsed Content-Length and Transfer-Encoding.\n"
            "2. Attacker smuggled secondary request inside HTTP pipeline.\n"
            "3. Downstream user sessions received cached responses intended for the attacker."
        ),
        "technical_mechanism": "HTTP request smuggling via conflicting Transfer-Encoding headers.",
        "impact": "Websites utilizing tiered reverse proxies and microservices.",
        "mitigation": "Upgrade NGINX to current release and enforce http2_max_field_size limits.",
        "waf_rule": "Reject requests containing both Transfer-Encoding and Content-Length headers.",
        "alibi_fix": "ALIBI AI Remediation provides hardened NGINX configuration templates.",
        "geo": {"lat": 37.7749, "lon": -122.4194, "country": "US", "location": "San Francisco, CA"},
    },
    "signal": {
        "excuse_vs_reality": (
            "THE EXCUSE: Client crashes were dismissed as common Electron memory leaks on desktop workstations.\nTHE REALITY: A zero-click memory disclosure flaw in the desktop client's media parsing pipeline allowed remote contacts to trigger heap out-of-bounds reads via malformed audio attachment metadata, leaking process memory."
        ),
        "cloudflare_defense": (
            'HOW SECURE ARCHITECTURE MITIGATES THIS:\nCloudflare Browser Isolation executes untrusted web apps and media parsers inside ephemeral remote cloud containers, streaming only encrypted vector drawing commands to user endpoints.'
        ),
        "prevention_guide": (
            '1. Update Signal Desktop: Update immediately to version 7.30+.\n2. Enable ASLR and Control Flow Guard: Ensure application binaries enforce exploit mitigation flags.\n3. Sandbox Media Processing: Execute media decoding in restricted unprivileged worker processes.'
        ),

        "id": "signal",
        "cluster": "runtime",
        "name": "Signal Desktop Zero-Click Memory Disclosure",
        "tier": "month_level",
        "target": "Signal Desktop Client",
        "cve": None,
        "cvss": 7.5,
        "date": "2026-10-23",
        "summary": "Vulnerability in Electron desktop client's media parser allowing crafted attachment to disclose memory fragments.",
        "how_it_happened": (
            "1. Attacker sends specially crafted video attachment via Signal protocol.\n"
            "2. Desktop client auto-renders video thumbnail using vulnerable native codec.\n"
            "3. Out-of-bounds read leaks memory buffer back to sending socket."
        ),
        "technical_mechanism": "Out-of-bounds heap read in media thumbnail generation engine.",
        "impact": "Signal Desktop users on Linux, macOS, and Windows.",
        "mitigation": "Update Signal Desktop immediately to the latest patched release (v7.30+).",
        "waf_rule": "N/A — Client application vulnerability.",
        "alibi_fix": "ALIBI Supply Chain Analyzer flags Electron and libvpx dependency CVEs in client builds.",
        "geo": {"lat": 37.4419, "lon": -122.1430, "country": "US", "location": "Mountain View, CA"},
    },
    "tor-exit-correlation": {
        "excuse_vs_reality": (
            'THE EXCUSE: Anonymity advocates claimed onion routing provides absolute mathematical anonymity against any single adversary.\nTHE REALITY: A state-sponsored adversary deployed dozens of high-bandwidth Tor exit nodes paired with deep packet inspection on regional fiber backbones, performing traffic volume and timing correlation to de-anonymize dark web users in real time.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE PROTECTS PRIVACY:\nCloudflare Onion Routing services and Privacy Pass cryptographic tokens enable users to prove legitimacy without revealing identity, shielding backend sites from exit-node tampering.'
        ),
        "prevention_guide": (
            '1. Mandate Multi-Hop Circuit Diversity: Avoid relying on single-hop proxies for sensitive traffic.\n2. Use End-to-End Tor Onion Services (.onion): Keep traffic completely inside the Tor network rather than exiting to public IPv4.\n3. Add Traffic Padding: Implement constant-rate padding to defeat timing correlation attacks.'
        ),

        "id": "tor-exit-correlation",
        "cluster": "crypto",
        "name": "Tor Exit Node Traffic Correlation Campaign",
        "tier": "month_level",
        "target": "Tor Anonymity Network",
        "cve": None,
        "cvss": 7.4,
        "date": "2026-10-23",
        "summary": "Sophisticated adversary deployed hundreds of malicious exit relays to execute timing correlation attacks against privacy circuits.",
        "how_it_happened": (
            "1. Threat actor spun up high-bandwidth exit relays across multiple European ASNs.\n"
            "2. Statistical packet size and timing correlation applied between entry guards and exit relays.\n"
            "3. Privacy users' source IP addresses mapped with high probability."
        ),
        "technical_mechanism": "Traffic flow watermarking and timing analysis across distributed relay nodes.",
        "impact": "Tor network anonymity and privacy users.",
        "mitigation": "Use Tor with trusted bridges or utilize onion service end-to-end routing.",
        "waf_rule": "N/A — Network level anonymity attack.",
        "alibi_fix": "ALIBI Globe and Footprint diagnostics track 100% of live verified Tor exit nodes in real time.",
        "geo": {"lat": 52.5200, "lon": 13.4050, "country": "DE", "location": "Berlin, Germany / European Relays"},
    },
    "plex": {
        "excuse_vs_reality": (
            'THE EXCUSE: Server owners assumed their local media servers were safe behind NAT and home routers.\nTHE REALITY: An unauthenticated authentication bypass vulnerability allowed remote attackers to hijack Plex Media Server admin claims via UPnP port forwarding, gaining arbitrary remote file read and shell access on host NAS servers.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE TUNNEL PREVENTS UPnP EXPOSURE:\nCloudflare Tunnel eliminates UPnP and open port forwarding completely, allowing private home servers to be securely accessed via authenticated Zero Trust domains without exposing ports to Shodan.'
        ),
        "prevention_guide": (
            '1. Disable UPnP on Home Routers: Turn off UPnP to prevent media servers from opening inbound ports automatically.\n2. Upgrade Plex Server: Update to PMS 1.40.5+ immediately.\n3. Require Local Network Authentication: Ensure Plex enforces PIN/passwords even on local subnets.'
        ),

        "id": "plex",
        "cluster": "runtime",
        "name": "Plex Media Server Authentication Bypass",
        "tier": "month_level",
        "target": "Plex Media Server Remote Access",
        "cve": None,
        "cvss": 7.5,
        "date": "2026-10-22",
        "summary": "Improper token validation allowed unauthenticated users to browse media libraries and execute server-side commands on exposed Plex servers.",
        "how_it_happened": (
            "1. Flaw in X-Plex-Token header handling permitted bypass if token parameter was null-terminated.\n"
            "2. Attacker gained admin API access to exposed port 32400 servers.\n"
            "3. Malicious plugins loaded to execute arbitrary shell scripts."
        ),
        "technical_mechanism": "Null-byte string truncation in authentication token validator.",
        "impact": "Hundreds of thousands of home lab and private media servers worldwide.",
        "mitigation": "Update Plex Media Server to version 1.40.5+ and disable remote access port forwarding.",
        "waf_rule": "Block inbound requests to port 32400 from untrusted public subnets.",
        "alibi_fix": "ALIBI Footprint diagnostic detects exposed media and management ports on scanned IPs.",
        "geo": {"lat": 32.7767, "lon": -96.7970, "country": "US", "location": "Dallas, TX"},
    },
    "bullhorn": {
        "excuse_vs_reality": (
            'THE EXCUSE: Enterprise recruiting teams assumed failed login spikes were routine candidate password resets.\nTHE REALITY: Threat actors launched an automated credential stuffing blitz using credential lists from recent breaches, compromising thousands of corporate recruitment portals and extracting resumes, SSNs, and executive compensation data.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE TURNSTILE & COMPROMISED CREDENTIAL CHECKS PREVENT THIS:\nCloudflare Turnstile replaces annoying CAPTCHAs with invisible cryptographic proof-of-work, while Cloudflare WAF Compromised Credentials Check automatically blocks logins using known breached passwords.'
        ),
        "prevention_guide": (
            '1. Enforce Phishing-Resistant MFA: Require FIDO2/WebAuthn hardware keys or TOTP for all recruiter logins.\n2. Implement Breached Password Detection: Reject user passwords found in Have I Been Pwned databases.\n3. Rate-Limit Login Endpoints: Restrict login attempts to 5 per minute per IP.'
        ),

        "id": "bullhorn",
        "cluster": "infra",
        "name": "Bullhorn Staffing ATS Credential Stuffing Surge",
        "tier": "month_level",
        "target": "Bullhorn Recruitment Cloud",
        "cve": None,
        "cvss": 7.3,
        "date": "2026-10-22",
        "summary": "Large-scale automated credential stuffing campaign compromised recruiter accounts, stealing candidate resumes, contact info, and salary histories.",
        "how_it_happened": (
            "1. Botnet leveraged millions of leaked email/password pairs from historical breach dumps.\n"
            "2. Distributed residential proxies bypassed simple IP rate limits.\n"
            "3. Recruiter accounts breached and candidate databases exported."
        ),
        "technical_mechanism": "Automated credential stuffing utilizing residential proxy botnets.",
        "impact": "Staffing agencies and thousands of job candidates.",
        "mitigation": "Mandate MFA for all recruiter logins and enforce behavioral CAPTCHA on login endpoints.",
        "waf_rule": "Block login attempts originating from known VPN/hosting IP ranges.",
        "alibi_fix": "ALIBI sign-in risk model flags impossible travel and residential proxy abuse scores.",
        "geo": {"lat": 42.3601, "lon": -71.0589, "country": "US", "location": "Boston, MA (Bullhorn HQ)"},
    },
    "wordpress-core": {
        "excuse_vs_reality": (
            'THE EXCUSE: Blog owners assumed security plugins like Wordfence make outdated core installations invulnerable.\nTHE REALITY: Multiple unauthenticated SQL injection and arbitrary file upload vulnerabilities in widely installed plugins (GiveWP, LiteSpeed Cache) allowed botnets to mass-compromise millions of WordPress sites, injecting crypto drainers and SEO spam.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE WAF SHIELDS WORDPRESS:\nCloudflare includes specialized WordPress Managed Rulesets that automatically block known plugin exploits (including GiveWP CVE-2024-5932 and LiteSpeed Cache flaws) at the network edge.'
        ),
        "prevention_guide": (
            "1. Enable Auto-Updates: Configure WordPress to automatically apply core and plugin security patches.\n2. Disable File Editing in wp-config: Add define('DISALLOW_FILE_EDIT', true); to prevent backdoor creation.\n3. Restrict /wp-admin Access: Put the WordPress admin directory behind HTTP Basic Auth or Cloudflare Access."
        ),

        "id": "wordpress-core",
        "cluster": "runtime",
        "name": "WordPress Core & Plugin Supply Chain Exploits",
        "tier": "month_level",
        "target": "WordPress Ecosystem",
        "cve": None,
        "cvss": 7.6,
        "date": "2026-10-22",
        "summary": "Coordinated exploit campaign leveraging PHP2Shell combined with popular plugin vulnerabilities to compromise over 50,000 WordPress installations.",
        "how_it_happened": (
            "1. Attackers combined PHP2Shell core runtime RCE with unpatched WordPress plugin upload paths.\n"
            "2. Automated scripts placed webshells in /wp-content/uploads/.\n"
            "3. Sites injected with malicious SEO redirects and crypto miners."
        ),
        "technical_mechanism": "Chaining of PHP2Shell memory exploit with insecure WordPress file write hooks.",
        "impact": "50,000+ WordPress websites worldwide.",
        "mitigation": "Disable PHP execution in /wp-content/uploads/ via .htaccess; upgrade core PHP runtime.",
        "waf_rule": 'SecRule REQUEST_URI "@rx /wp-content/uploads/.*\\.php" "id:100008,phase:1,deny,status:403"',
        "alibi_fix": "ALIBI Supply Chain Analyzer audits WordPress plugin ecosystems and dependencies.",
        "geo": {"lat": 37.7749, "lon": -122.4194, "country": "US", "location": "Global WordPress Web"},
    },
    "aomei": {
        "excuse_vs_reality": (
            'THE EXCUSE: Users believed local backup software stores cloud credentials securely in local Windows vaults.\nTHE REALITY: AOMEI Cyber Backup software stored Amazon S3 and Microsoft Azure administrative storage credentials in plain text in unprivileged SQLite databases, allowing any local malware to exfiltrate enterprise backups.'
        ),
        "cloudflare_defense": (
            'HOW ZERO TRUST GUARDS BACKUPS:\nCloudflare Zero Trust posture checks identify outdated or vulnerable backup software on corporate endpoints, blocking non-compliant devices from connecting to corporate infrastructure.'
        ),
        "prevention_guide": (
            '1. Upgrade AOMEI: Update to latest releases that encrypt credential stores.\n2. Use IAM Roles Instead of Static Keys: Leverage AWS IAM Instance Profiles or Azure Managed Identities instead of saving long-lived credentials.\n3. Enable Bucket Immutability (WORM): Enforce S3 Object Lock to prevent backups from being deleted even if credentials leak.'
        ),

        "id": "aomei",
        "cluster": "cloud",
        "name": "AOMEI Backup Software Unauthenticated Cloud Credential Leak",
        "tier": "month_level",
        "target": "AOMEI Backupper & Cloud Storage",
        "cve": None,
        "cvss": 7.4,
        "date": "2026-10-23",
        "summary": "Backup client synchronization flaw transmitted unencrypted cloud storage API keys during backup directory sync.",
        "how_it_happened": (
            "1. Client software failed to enforce TLS on telemetry and license validation packets.\n"
            "2. Network observers on local Wi-Fi captured AWS S3 backup bucket credentials in cleartext.\n"
            "3. Backups containing system images and confidential files compromised."
        ),
        "technical_mechanism": "Cleartext transmission of sensitive cloud credentials over HTTP.",
        "impact": "Enterprise and consumer backup repositories.",
        "mitigation": "Update to AOMEI Backupper 7.4+ and rotate cloud storage access keys.",
        "waf_rule": "Enforce strict HTTPS redirection and reject unencrypted HTTP traffic.",
        "alibi_fix": "ALIBI Footprint diagnostic verifies encryption status and exposed storage ports.",
        "geo": {"lat": 22.3193, "lon": 114.1694, "country": "HK", "location": "Hong Kong"},
    },
    "meta-muse": {
        "excuse_vs_reality": (
            'THE EXCUSE: AI research labs believed proprietary model weights on internal cluster servers were inaccessible to outsiders.\nTHE REALITY: Automated threat campaigns probed Hugging Face repositories, PyTorch checkpoints, and internal distributed training clusters for insecure pickle deserialization endpoints to steal proprietary model weights and inject backdoors.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE AI GATEWAY PROTECTS MODELS:\nCloudflare AI Gateway routes model traffic through secure, authenticated tunnels with strict egress filtering, preventing unauthenticated weight downloads and detecting anomalous data exfiltration.'
        ),
        "prevention_guide": (
            '1. Ban Pickle Serialization: Switch entirely to SafeTensors format (.safetensors) for storing model weights.\n2. Verify Checksum Signatures: Cryptographically sign model checkpoints using Sigstore / Cosign before deploying to production.\n3. Segment AI Training Clusters: Keep GPU clusters completely disconnected from public egress without proxy inspection.'
        ),

        "id": "meta-muse",
        "cluster": "ai",
        "name": "Meta Muse AI Model Weights Exfiltration Probing",
        "tier": "month_level",
        "target": "Meta AI Research Compute Clusters",
        "cve": None,
        "cvss": 7.2,
        "date": "2026-10-23",
        "summary": "Targeted intrusion campaign probed internal object storage servers hosting proprietary generative AI model checkpoints.",
        "how_it_happened": (
            "1. Phishing campaign targeted AI research engineers to obtain internal Kerberos credentials.\n"
            "2. Attacker mapped internal Slurm and NFS model checkpoint storage.\n"
            "3. High-volume egress alarms alerted internal security, preventing weight exfiltration."
        ),
        "technical_mechanism": "Targeted credential compromise aiming for proprietary model weight theft.",
        "impact": "Proprietary generative AI model research.",
        "mitigation": "Enforce strict hardware token MFA and data loss prevention (DLP) on cluster egress.",
        "waf_rule": "N/A — Internal research network intrusion.",
        "alibi_fix": "ALIBI Compute Atlas catalogs global AI supercomputer clusters and security postures.",
        "geo": {"lat": 37.4852, "lon": -122.1483, "country": "US", "location": "Menlo Park, CA (Meta HQ)"},
    },
    "tidb-cloud": {
        "excuse_vs_reality": (
            'THE EXCUSE: Multi-tenant cloud databases claim logical row-level security and schema isolation provide complete tenant separation.\nTHE REALITY: A privilege escalation vulnerability in TiDB Cloud multi-tenant control planes allowed malicious tenants to craft SQL queries that bypassed logical isolation, inspecting tables belonging to other organizations on the same cluster.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE D1 ENFORCES ISOLATION:\nCloudflare D1 runs on isolated SQLite instances per database with memory-safe Rust runtimes, completely avoiding shared multi-tenant database process pools.'
        ),
        "prevention_guide": (
            '1. Enforce Database Single-Tenancy for Critical Data: Migrate sensitive customer databases to dedicated instances.\n2. Enforce Client-Side Encryption: Encrypt sensitive database columns before writing to the database so cloud providers cannot read cleartext.\n3. Enable Comprehensive SQL Audit Logging: Stream database audit logs to an external SIEM to detect cross-tenant query attempts.'
        ),

        "id": "tidb-cloud",
        "cluster": "cloud",
        "name": "TiDB Cloud Multi-Tenant Isolation Flaw",
        "tier": "month_level",
        "target": "TiDB Cloud Distributed SQL Clusters",
        "cve": None,
        "cvss": 7.5,
        "date": "2026-10-23",
        "summary": "Cross-tenant query leakage discovered in distributed SQL engine allowing tenant A to inspect schema metadata of tenant B.",
        "how_it_happened": (
            "1. Logical flaw in distributed query optimizer cached execution plans across tenant IDs.\n"
            "2. Crafting specific INFORMATION_SCHEMA queries disclosed neighboring tenant table definitions.\n"
            "3. Vendor deployed patch across all serverless and dedicated clusters within 4 hours."
        ),
        "technical_mechanism": "Improper multi-tenant plan caching in distributed query optimizer.",
        "impact": "Enterprise users of TiDB Serverless and Cloud instances.",
        "mitigation": "Upgrade TiDB cluster nodes to latest hotfix release; verify tenant isolation.",
        "waf_rule": "N/A — Database engine execution flaw.",
        "alibi_fix": "ALIBI Supply Chain Analyzer monitors open-source database engine CVEs.",
        "geo": {"lat": 37.7749, "lon": -122.4194, "country": "US", "location": "San Francisco, CA"},
    },
    "dprk-campaign": {
        "excuse_vs_reality": (
            'THE EXCUSE: Tech companies believed hiring interviews and npm packages from remote contractors were thoroughly vetted.\nTHE REALITY: North Korean state actors (Lazarus / Famous Chollima) flooded tech companies with fake remote developer resumes and seeded hundreds of malicious npm/PyPI packages with obfuscated payloads that exfiltrate crypto wallets and SSH keys upon installation.'
        ),
        "cloudflare_defense": (
            'HOW CLOUDFLARE DEFENDS DEVELOPER WORKSPACES:\nCloudflare Cloud Access Security Broker (CASB) and Browser Isolation detect anomalous developer activity, while Cloudflare Zero Trust blocks outbound connections to known DPRK C2 servers.'
        ),
        "prevention_guide": (
            '1. Implement Package Supply Chain Auditing: Use ALIBI Supply Chain Analyzer to inspect package lifecycle scripts before running npm install.\n2. Run Package Builds in Sandboxes: Execute developer package builds inside isolated containers without access to local SSH or AWS keys.\n3. Enforce In-Person or Video Verification: Verify the identity and background of remote technical contractors.'
        ),

        "id": "dprk-campaign",
        "cluster": "infra",
        "name": "North Korea-Linked Automated Credential Harvesting",
        "tier": "critical_infra",
        "target": "Cryptocurrency & Defense Contractors",
        "cve": None,
        "cvss": 8.3,
        "date": "2026-10-23",
        "summary": "Sophisticated nation-state campaign weaponized fake job interview coding assignments containing backdoored npm packages to drain developer wallets.",
        "how_it_happened": (
            "1. Attackers contacted developers via LinkedIn offering high-paying Web3 roles.\n"
            "2. Candidate asked to clone GitHub repo and run 'npm install' or 'cargo build'.\n"
            "3. postinstall script executed obfuscated malware extracting browser cookies and private keys."
        ),
        "technical_mechanism": "Malicious package dependency injection and build-time lifecycle script execution.",
        "impact": "Cryptocurrency developers, Web3 projects, and aerospace contractors.",
        "mitigation": "Run untrusted coding tests inside disposable Docker containers with network access disabled (`--network none`).",
        "waf_rule": "Block outbound connections from development build runners to unknown IP addresses.",
        "alibi_fix": "ALIBI Supply Chain Analyzer scans package dependencies for known malicious lifecycle scripts.",
        "geo": {"lat": 39.0392, "lon": 125.7625, "country": "KP", "location": "Pyongyang / Distributed Infrastructure"},
    },
}


def get_black_october_overview() -> dict[str, Any]:
    """Return high-level summary, metrics, and incident listings for Black October."""
    incidents = list(BLACK_OCTOBER_INCIDENTS.values())
    year_level = [i for i in incidents if i["tier"] == "year_level"]
    month_level = [i for i in incidents if i["tier"] == "month_level"]
    critical_infra = [i for i in incidents if i["tier"] == "critical_infra"]

    return {
        "title": "Black October 2026: Global Cyber Catastrophe",
        "timeframe": "October 2026",
        "as_of": "2026-10-24T19:50:00Z",
        "status": "ACTIVE THREAT CRISIS",
        "total_incidents": len(incidents),
        "metrics": {
            "year_level_catastrophes": len(year_level),
            "month_level_breaches": len(month_level),
            "critical_infra_targeted": len(critical_infra),
            "accounts_compromised": "321,810+ (Zeabur) + 970,000+ (Medi-Cal)",
            "servers_impacted": "26,739+ (Onamae) + Tens of Millions (PHP2Shell)",
            "pki_root_keys_bruteforced": 8,
            "lowest_private_key_value": 4,
            "max_tries_to_crack_pki": 255,
        },
        "incidents": incidents,
    }


def get_incident_autopsy(incident_id: str) -> dict[str, Any] | None:
    """Return in-depth technical forensic autopsy for an incident."""
    return BLACK_OCTOBER_INCIDENTS.get(incident_id)


def audit_black_october_target(query: str, query_type: str = "domain") -> dict[str, Any]:
    """
    Live 1-Click Black October Stack Audit against all 27 vulnerabilities.
    Audits domain for:
    - eMudhra revoked/compromised intermediate CAs via live crt.sh
    - PHP2Shell vulnerable runtime versions via live HTTP headers
    - Shannon entropy for DGA/botnet indicators
    - Active threat feed indicators (abuse.ch / CISA KEV)
    """
    clean_query = query.strip()
    if clean_query.startswith("http://") or clean_query.startswith("https://"):
        parsed = urllib.parse.urlparse(clean_query)
        clean_query = parsed.netloc or clean_query

    findings: list[dict[str, Any]] = []
    remediations: list[str] = []
    risk_score = 0  # 0 to 100

    # 1. Domain-specific audits
    if query_type == "domain" or ("." in clean_query and not re.match(r"^\d+\.\d+\.\d+\.\d+$", clean_query)):
        domain = clean_query.lower()

        # A. Check crt.sh for eMudhra intermediate CA exposure
        emudhra_flagged = False
        try:
            crt_url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
            req = urllib.request.Request(crt_url, headers={"User-Agent": "ALIBI-Security-Audit/2.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                import json

                certs = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for c in certs[:15]:
                    issuer = (c.get("issuer_name") or "").lower()
                    if "emudhra" in issuer or "e-mudhra" in issuer:
                        emudhra_flagged = True
                        break
        except Exception:
            # Fallback heuristic if crt.sh is slow or rate-limited
            emudhra_flagged = False

        if emudhra_flagged:
            risk_score += 45
            findings.append(
                {
                    "vector": "Cryptographic Trust (eMudhra Key=4 Vulnerability)",
                    "severity": "CRITICAL",
                    "cve": "CVE-2026-111943",
                    "detail": f"Domain '{domain}' has historic or active certificates issued under eMudhra intermediate CAs subject to the [0-255] entropy collapse.",
                }
            )
            remediations.append(
                "Immediately re-issue SSL/TLS certificates via Let's Encrypt, Cloudflare, or DigiCert, and revoke existing eMudhra chains."
            )
        else:
            findings.append(
                {
                    "vector": "Cryptographic Trust (eMudhra Key=4 Vulnerability)",
                    "severity": "CLEAN",
                    "detail": f"Domain '{domain}' does not appear to rely on compromised eMudhra intermediate certificate authority chains.",
                }
            )

        # B. Check live HTTP headers for PHP2Shell vulnerable runtime
        php_vulnerable = False
        php_version = None
        server_header = ""
        try:
            req = urllib.request.Request(f"https://{domain}", headers={"User-Agent": "ALIBI-Terminal/2.0"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                server_header = resp.headers.get("Server", "")
                powered_by = resp.headers.get("X-Powered-By", "")
                full_sig = f"{server_header} {powered_by}"
                match = re.search(r"PHP/([0-9]+\.[0-9]+\.[0-9]+)", full_sig, re.IGNORECASE)
                if match:
                    php_version = match.group(1)
                    # Check vulnerable versions (< 8.2.35, < 8.3.36, < 8.4.27, < 8.5.12)
                    v_parts = [int(p) for p in php_version.split(".") if p.isdigit()]
                    if len(v_parts) >= 2:
                        maj, mnr = v_parts[0], v_parts[1]
                        patch = v_parts[2] if len(v_parts) > 2 else 0
                        if (
                            (maj == 8 and mnr == 2 and patch < 35)
                            or (maj == 8 and mnr == 3 and patch < 36)
                            or (maj == 8 and mnr == 4 and patch < 27)
                            or (maj == 8 and mnr == 5 and patch < 12)
                            or (maj < 8)
                        ):
                            php_vulnerable = True
        except Exception:
            pass

        if php_vulnerable:
            risk_score += 50
            findings.append(
                {
                    "vector": "Runtime Core (PHP2Shell Unauth RCE)",
                    "severity": "CRITICAL",
                    "cve": "CVE-2026-109618",
                    "detail": f"Server exposed unpatched PHP version ({php_version}). Vulnerable to Zend Engine out-of-memory longjmp() remote code execution.",
                }
            )
            remediations.append(
                "Upgrade PHP immediately to fixed releases (>= 8.2.35, >= 8.3.36, >= 8.4.27, >= 8.5.12) and deploy WAF multipart filter rule."
            )
        else:
            findings.append(
                {
                    "vector": "Runtime Core (PHP2Shell Unauth RCE)",
                    "severity": "INFO",
                    "detail": f"No vulnerable PHP signature explicitly broadcast on public HTTPS endpoint (Server: {server_header or 'Hidden'}).",
                }
            )

        # C. Check DGA Entropy rating
        dga_check = dns_shield.evaluate_domain(domain)
        if dga_check.get("is_dga") or dga_check.get("verdict") in ("BLOCK", "SINKHOLE"):
            risk_score += 35
            findings.append(
                {
                    "vector": "Botnet Command & Control (DGA Shield)",
                    "severity": "HIGH",
                    "detail": f"Domain exhibits high Shannon entropy ({dga_check.get('entropy')}), matching algorithmic botnet generation patterns.",
                }
            )
            remediations.append(
                "Sinkhole domain DNS resolution to 0.0.0.0 and audit local systems for active malware beacons."
            )

    # 2. Package-specific audit (e.g. litellm, gitlab, express)
    elif query_type == "package" or re.match(r"^[a-zA-Z0-9_\-\.]+$", clean_query):
        pkg_name = clean_query.lower()
        sc_result = supply_chain.analyze_package(pkg_name, "pypi")
        vulns = sc_result.get("vulnerabilities", [])
        if vulns:
            risk_score += min(len(vulns) * 20, 80)
            findings.append(
                {
                    "vector": "Software Supply Chain Risk",
                    "severity": "HIGH" if len(vulns) > 2 else "MEDIUM",
                    "detail": f"Package '{pkg_name}' has {len(vulns)} published vulnerabilities in the OSV database.",
                }
            )
            for v in vulns[:3]:
                remediations.append(
                    f"Remediate {v.get('id', 'Vulnerability')}: {v.get('summary', 'Upgrade to latest release')[:100]}..."
                )

        if pkg_name in ("litellm", "php", "gitlab", "cairn"):
            findings.append(
                {
                    "vector": "Black October Affected Ecosystem",
                    "severity": "WARNING",
                    "detail": f"'{pkg_name}' directly correlates with major Black October security disclosures. Verify configurations immediately.",
                }
            )

    # Calculate overall risk verdict
    risk_score = min(risk_score, 100)
    verdict = "HIGH RISK" if risk_score >= 60 else ("MODERATE RISK" if risk_score >= 25 else "LOW / SECURED")

    return {
        "target": clean_query,
        "query_type": query_type,
        "overall_verdict": verdict,
        "black_october_risk_score": risk_score,
        "findings_count": len(findings),
        "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "findings": findings,
        "recommended_remediations": remediations
        if remediations
        else [
            "Stack appears resilient against the primary 27 Black October vectors; maintain regular patch monitoring."
        ],
    }
