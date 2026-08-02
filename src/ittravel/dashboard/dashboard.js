document.addEventListener('DOMContentLoaded', () => {
  const globalApiKeyInput = document.getElementById('global-api-key');
  const toggleKeyBtn = document.getElementById('toggle-key-visibility');

  // Toggle API Key visibility
  toggleKeyBtn.addEventListener('click', () => {
    if (globalApiKeyInput.type === 'password') {
      globalApiKeyInput.type = 'text';
    } else {
      globalApiKeyInput.type = 'password';
    }
  });

  const getHeaders = () => ({
    'Content-Type': 'application/json',
    'X-API-Key': globalApiKeyInput.value.trim(),
  });

  // Tab Navigation
  const navItems = document.querySelectorAll('.nav-item');
  const tabContents = document.querySelectorAll('.tab-content');
  const pageTitle = document.getElementById('page-title');
  const pageSubtitle = document.getElementById('page-subtitle');

  const tabMeta = {
    overview: { title: 'Overview Telemetry', subtitle: 'Real-time authentication risk monitoring and impossible travel detection' },
    simulator: { title: 'Live Threat Simulator', subtitle: 'Simulate authentication events and test real-time AI risk evaluation' },
    anomalies: { title: 'Anomaly Logs', subtitle: 'Audit log of historical high-risk security triggers' },
    apikeys: { title: 'API Keys Portal', subtitle: 'Manage tenant keys for system integration' },
  };

  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const tab = item.getAttribute('data-tab');
      navItems.forEach(i => i.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      item.classList.add('active');
      document.getElementById(`tab-${tab}`).classList.add('active');

      if (tabMeta[tab]) {
        pageTitle.textContent = tabMeta[tab].title;
        pageSubtitle.textContent = tabMeta[tab].subtitle;
      }

      if (tab === 'overview' || tab === 'anomalies') {
        loadTelemetry();
        loadAnomalies();
      }
    });
  });

  // Fetch SaaS Telemetry Stats
  async function loadTelemetry() {
    try {
      const res = await fetch('/v1/stats', { headers: getHeaders() });
      if (!res.ok) return;
      const data = await res.json();
      document.getElementById('stat-users').textContent = data.active_monitored_users || 0;
      document.getElementById('stat-anomalies').textContent = data.total_anomalies_detected || 0;
      document.getElementById('stat-critical').textContent = data.critical_threats || 0;
    } catch (e) {
      console.error('Failed to load telemetry stats', e);
    }
  }

  // Fetch Anomaly Logs
  async function loadAnomalies() {
    try {
      const res = await fetch('/v1/anomalies?limit=50', { headers: getHeaders() });
      if (!res.ok) return;
      const logs = await res.json();

      const overviewTable = document.getElementById('overview-anomaly-table');
      const logsTable = document.getElementById('logs-table-body');

      if (!logs || logs.length === 0) {
        const emptyRow = '<tr><td colspan="7" class="text-center">No anomaly events logged yet. Use the Live Threat Simulator to trigger one!</td></tr>';
        if (overviewTable) overviewTable.innerHTML = emptyRow;
        if (logsTable) logsTable.innerHTML = emptyRow;
        return;
      }

      const renderRows = logs.map(a => `
        <tr>
          <td>${new Date(a.timestamp).toLocaleTimeString()}</td>
          <td><strong>${a.user_id}</strong></td>
          <td>${a.risk_score} / 100</td>
          <td><span class="badge ${a.risk_tier.toLowerCase()}">${a.risk_tier}</span></td>
          <td>${a.velocity_kmph} km/h</td>
          <td>${a.distance_km} km</td>
          <td>${(a.reasons || []).join(', ')}</td>
        </tr>
      `).join('');

      if (overviewTable) overviewTable.innerHTML = renderRows;
      if (logsTable) logsTable.innerHTML = renderRows;
    } catch (e) {
      console.error('Failed to load anomaly logs', e);
    }
  }

  document.getElementById('refresh-telemetry-btn')?.addEventListener('click', () => { loadTelemetry(); loadAnomalies(); });
  document.getElementById('refresh-logs-btn')?.addEventListener('click', loadAnomalies);

  // Live Threat Simulator Form Submit
  const simForm = document.getElementById('simulator-form');
  simForm?.addEventListener('submit', async (e) => {
    e.preventDefault();

    const userId = document.getElementById('sim-user-id').value;
    const locVal = document.getElementById('sim-location').value;
    const [latStr, lonStr, city, country] = locVal.split(',');
    const minutesOffset = parseInt(document.getElementById('sim-time-offset').value);
    const deviceId = document.getElementById('sim-device').value;
    const ip = document.getElementById('sim-ip').value;

    const loginTs = new Date(Date.now() + minutesOffset * 60 * 1000).toISOString();

    const payload = {
      user_id: userId,
      login_ts: loginTs,
      lat: parseFloat(latStr),
      lon: parseFloat(lonStr),
      city: city,
      country: country,
      device_id: deviceId,
      ip: ip,
    };

    try {
      const res = await fetch('/v1/auth/evaluate', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      document.getElementById('sim-response-placeholder').classList.add('hidden');
      document.getElementById('sim-response-content').classList.remove('hidden');

      const scoreEl = document.getElementById('res-risk-score');
      scoreEl.textContent = data.risk_score;

      const tierEl = document.getElementById('res-risk-tier');
      tierEl.textContent = data.risk_tier;
      tierEl.className = `badge ${data.risk_tier.toLowerCase()}`;

      const flagEl = document.getElementById('res-anomaly-flag');
      flagEl.textContent = data.is_anomaly ? '🚨 ANOMALY FLAGGED' : '✅ NORMAL AUTH';

      document.getElementById('res-speed').textContent = `${data.velocity_kmph} km/h`;
      document.getElementById('res-distance').textContent = `${data.distance_km} km`;
      document.getElementById('res-time-delta').textContent = `${data.time_delta_hours} hrs`;

      const reasonsList = document.getElementById('res-reasons-list');
      reasonsList.innerHTML = (data.reasons || []).map(r => `<li>${r}</li>`).join('');

      document.getElementById('res-raw-json').textContent = JSON.stringify(data, null, 2);

      loadTelemetry();
    } catch (e) {
      alert('Error evaluating event: ' + e.message);
    }
  });

  // API Key Generation Form
  const keyForm = document.getElementById('create-key-form');
  keyForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('key-name-input').value;

    try {
      const res = await fetch('/v1/keys/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name }),
      });
      const data = await res.json();

      const alertBox = document.getElementById('new-key-alert');
      const valBox = document.getElementById('new-key-value');
      valBox.textContent = data.api_key;
      alertBox.classList.remove('hidden');

      // Auto-set generated key into global active key input
      globalApiKeyInput.value = data.api_key;
    } catch (err) {
      alert('Error generating key: ' + err.message);
    }
  });

  document.getElementById('copy-key-btn')?.addEventListener('click', () => {
    const keyVal = document.getElementById('new-key-value').textContent;
    navigator.clipboard.writeText(keyVal);
    alert('API Key copied to clipboard!');
  });

  // Initial load
  loadTelemetry();
  loadAnomalies();
});
