(() => {
  const API_KEY = () => document.getElementById('global-api-key').value.trim();
  const HEADERS = () => ({ 'Content-Type': 'application/json', 'X-API-Key': API_KEY() });

  // ── API KEY TOGGLE ──
  const keyInput = document.getElementById('global-api-key');
  document.getElementById('toggle-key-btn').addEventListener('click', () => {
    keyInput.type = keyInput.type === 'password' ? 'text' : 'password';
  });

  // ── TAB ROUTING ──
  const tabMeta = {
    overview:  'Identity Threat Intelligence',
    sandbox:   'Interactive Evaluation Sandbox',
    logs:      'Audit Log Inspector',
    tutorials: 'Developer Integration Guide & Tutorials',
    apikeys:   'Tenant API Keys Portal',
  };

  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-page').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${tab}`).classList.add('active');
      if (tab === 'overview') { loadStats(); loadAnomalies('overview-table-body'); }
      if (tab === 'logs')     { loadAnomalies('audit-table-body'); }
    });
  });

  // ── STATS ──
  async function loadStats() {
    try {
      const res = await fetch('/v1/stats', { headers: HEADERS() });
      if (!res.ok) return;
      const d = await res.json();
      document.getElementById('stat-users').textContent     = d.active_monitored_users   ?? 0;
      document.getElementById('stat-anomalies').textContent = d.total_anomalies_detected ?? 0;
      document.getElementById('stat-critical').textContent  = d.critical_threats          ?? 0;
    } catch (e) { console.warn('Stats fetch failed', e); }
  }

  document.getElementById('refresh-overview-btn')?.addEventListener('click', () => {
    loadStats();
    loadAnomalies('overview-table-body');
  });

  // ── ANOMALY ROWS ──
  async function loadAnomalies(tableId) {
    const body = document.getElementById(tableId);
    if (!body) return;
    try {
      const res = await fetch('/v1/anomalies?limit=50', { headers: HEADERS() });
      if (!res.ok) { body.innerHTML = `<tr><td colspan="7" class="text-muted text-center">Auth error — check API key.</td></tr>`; return; }
      const rows = await res.json();
      if (!rows.length) {
        body.innerHTML = '<tr><td colspan="7" class="text-muted text-center">No anomalies recorded yet. Use the Interactive Sandbox to fire test events.</td></tr>';
        return;
      }
      body.innerHTML = rows.map(a => `
        <tr>
          <td>${new Date(a.timestamp).toLocaleString()}</td>
          <td>${a.user_id}</td>
          <td>${a.risk_score}/100</td>
          <td><span class="risk-badge ${a.risk_tier.toLowerCase()}">${a.risk_tier}</span></td>
          <td>${a.velocity_kmph.toLocaleString()} km/h</td>
          <td>${a.distance_km.toLocaleString()} km</td>
          <td>${(a.reasons||[]).join(' · ')}</td>
        </tr>`).join('');
    } catch (e) { body.innerHTML = `<tr><td colspan="7" class="text-muted text-center">Failed to fetch logs.</td></tr>`; }
  }

  document.getElementById('refresh-logs-btn')?.addEventListener('click', () => loadAnomalies('audit-table-body'));

  // ── SANDBOX FORM ──
  let lastPayload = null;
  let lastResponse = null;

  const sbForm = document.getElementById('sandbox-form');
  sbForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const [lat, lon, city, country] = document.getElementById('sb-preset').value.split(',');
    const mins = parseInt(document.getElementById('sb-time').value);
    const login_ts = new Date(Date.now() + mins * 60000).toISOString();

    lastPayload = {
      user_id:    document.getElementById('sb-user').value.trim(),
      login_ts,
      lat:        parseFloat(lat),
      lon:        parseFloat(lon),
      city,
      country,
      device_id:  document.getElementById('sb-device').value.trim(),
      ip:         document.getElementById('sb-ip').value.trim(),
    };

    try {
      const res = await fetch('/v1/auth/evaluate', {
        method: 'POST',
        headers: HEADERS(),
        body: JSON.stringify(lastPayload),
      });
      lastResponse = await res.json();
      // Default: show JSON response view
      setActiveCodeTab('json');
      loadStats();
    } catch (err) {
      document.getElementById('code-output').textContent = `// ERROR: ${err.message}`;
    }
  });

  // ── CODE SNIPPET GENERATOR ──
  function renderCodeTab(lang) {
    const out = document.getElementById('code-output');
    if (!lastPayload) {
      out.textContent = '// Submit an event first using the configurator above.';
      return;
    }
    const p = lastPayload;
    const r = lastResponse;
    const key = API_KEY();
    const url = `https://<your-deployment>.vercel.app/v1/auth/evaluate`;

    const snippets = {
      json: JSON.stringify(r || p, null, 2),

      curl: `curl -X POST "${url}" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${key}" \\
  -d '${JSON.stringify(p)}'`,

      python: `import httpx

VIGILGUARD_API_KEY = "${key}"
VIGILGUARD_URL = "${url}"

payload = ${JSON.stringify(p, null, 4)}

resp = httpx.post(
    VIGILGUARD_URL,
    headers={"X-API-Key": VIGILGUARD_API_KEY},
    json=payload,
    timeout=5,
)
result = resp.json()

if result["risk_tier"] == "CRITICAL":
    # Block login — immediate threat
    raise Exception("Authentication blocked: impossible travel detected")
elif result["risk_tier"] == "HIGH":
    # Trigger step-up MFA
    prompt_mfa(user_id=result["user_id"])
else:
    # Allow login
    grant_session()

print(f"Risk Score: {result['risk_score']}/100 | Tier: {result['risk_tier']}")`,

      node: `const axios = require('axios');

const VIGILGUARD_API_KEY = "${key}";
const VIGILGUARD_URL = "${url}";

async function evaluateLogin(payload) {
  const { data } = await axios.post(VIGILGUARD_URL, payload, {
    headers: { 'X-API-Key': VIGILGUARD_API_KEY },
    timeout: 5000,
  });

  if (data.risk_tier === 'CRITICAL') {
    throw new Error('Login blocked: impossible travel detected');
  } else if (data.risk_tier === 'HIGH') {
    return { allowed: false, requireMFA: true, ...data };
  }
  return { allowed: true, ...data };
}

evaluateLogin(${JSON.stringify(p, null, 2)}).then(console.log);`,
    };

    out.textContent = snippets[lang] || snippets.json;
  }

  function setActiveCodeTab(lang) {
    document.querySelectorAll('.code-tab-btn').forEach(b => {
      b.classList.toggle('active', b.dataset.lang === lang);
    });
    renderCodeTab(lang);
  }

  document.querySelectorAll('.code-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => setActiveCodeTab(btn.dataset.lang));
  });

  // ── TUTORIAL NAVIGATION ──
  document.querySelectorAll('.tut-step').forEach(step => {
    step.addEventListener('click', () => {
      const n = step.dataset.step;
      document.querySelectorAll('.tut-step').forEach(s => s.classList.remove('active'));
      document.querySelectorAll('.tut-panel').forEach(p => p.classList.remove('active'));
      step.classList.add('active');
      document.getElementById(`tut-step-${n}`)?.classList.add('active');
    });
  });

  // ── API KEY GENERATION ──
  document.getElementById('key-gen-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('key-label').value.trim();
    try {
      const res = await fetch('/v1/keys/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
      const d = await res.json();
      document.getElementById('new-key-code').textContent = d.api_key;
      document.getElementById('key-output-banner').classList.remove('hidden');
      keyInput.value = d.api_key;
    } catch (err) { alert('Error generating key: ' + err.message); }
  });

  document.getElementById('copy-key-btn')?.addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('new-key-code').textContent);
  });

  // ── INITIAL LOAD ──
  loadStats();
  loadAnomalies('overview-table-body');
})();
