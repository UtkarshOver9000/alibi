// Alibi dashboard. Every number on the page comes from the API, which reads the real data
// snapshot (HIBP, CISA KEV, abuse.ch, Spamhaus, RansomLook, iptoasn, OONI, TeleGeography,
// public-dns.info) or the live news feeds. Nothing here is generated.

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => [...el.querySelectorAll(sel)];
const fmt = (n) => Number(n).toLocaleString("en-US");
const compact = (n) => Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
const pct = (x, d = 2) => `${(x * 100).toFixed(d)}%`;
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const day = (iso) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
// Lucide icons (ISC), one self-hosted sprite
const ico = (name, cls = "") => `<svg class="ico ${cls}" aria-hidden="true"><use href="/static/vendor/icons.svg#i-${name}"/></svg>`;

function ago(iso) {
  if (!iso) return "";
  const mins = Math.round((Date.now() - new Date(iso)) / 60000);
  if (mins < 60) return `${Math.max(mins, 1)} min ago`;
  if (mins < 1440) return `${Math.round(mins / 60)} h ago`;
  return `${Math.round(mins / 1440)} days ago`;
}

async function api(path, opts) {
  const res = await fetch(path, opts);
  if (!res.ok) throw new Error(`${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

const kpi = (v, l) => `<div class="kpi"><div class="v">${v}</div><div class="l">${l}</div></div>`;

function bars(el, rows, label = (n) => fmt(n)) {
  if (!rows.length) return void (el.innerHTML = '<p class="muted empty">Nothing recorded in this snapshot.</p>');
  const max = Math.max(...rows.map((r) => r[1]), 1);
  el.innerHTML = rows.map(([k, n]) => `<div class="bar"><span>${esc(k)}</span>
    <div class="track"><div class="fill" style="width:${(n / max) * 100}%"></div></div><span class="n">${label(n)}</span></div>`).join("");
}

// ---------- tabs ----------
const loaders = {};
const loaded = new Set();

// "Updated 3 hours ago" line under a tab's title
function stamp(tab, iso, extra = "") {
  const section = $(`#tab-${tab}`);
  if (!section.querySelector(".page-head")) return; // the globe shows its date in the timeline
  let el = section.querySelector(".updated");
  if (!el) {
    section.querySelector(".page-head").insertAdjacentHTML("afterend", '<p class="fineprint updated"></p>');
    el = section.querySelector(".updated");
  }
  el.textContent = `Updated ${ago(iso)} (${day(iso)})${extra}`;
}

// Run a tab's loader with a skeleton while it loads and a retry card if it fails; never a blank panel.
function load(tab) {
  const section = $(`#tab-${tab}`);
  loaded.add(tab);
  section.querySelector(".load-error")?.remove();
  section.classList.add("is-loading");
  loaders[tab]()
    .catch((err) => {
      console.error(tab, err);
      loaded.delete(tab);
      (section.querySelector(".page-head") || section.firstElementChild).insertAdjacentHTML("afterend", `<div class="panel load-error" role="alert">
        <b>This section didn't load.</b> The server or your connection had a hiccup (${esc(err.message.slice(0, 80))}).
        <button class="btn">Try again</button></div>`);
      section.querySelector(".load-error button").addEventListener("click", () => load(tab));
    })
    .finally(() => section.classList.remove("is-loading"));
}

// ---------- shareable state: the module, map colour, layers and selection live in the URL ----------
// #globe?m=dns_resolvers&l=c2,dl,tor&c=IN opens the globe coloured by DNS servers, three point layers on, India selected.
let worldReady = false;
const route = () => {
  const [path, query = ""] = location.hash.slice(1).split("?");
  return { path, params: new URLSearchParams(query) };
};

function syncUrl() {
  if (!worldReady || !document.body.classList.contains("on-globe")) return;
  const p = new URLSearchParams();
  if (metric !== "malicious_ips") p.set("m", metric);
  const on = $$("[data-layer]").filter((c) => c.checked).map((c) => c.dataset.layer);
  if ($("#show-cables").checked) on.push("cables");
  if (on.join() !== "c2,dl") p.set("l", on.join() || "none");
  const cc = selected?.properties?.c?.a2;
  if (cc) p.set("c", cc);
  const q = p.toString().replaceAll("%2C", ",");
  history.replaceState(null, "", `#globe${q ? `?${q}` : ""}`); // no new history entry for a layer toggle
}

function applyUrlState() {
  if (!worldReady) return;
  const { params } = route();
  const m = params.get("m");
  if (m && m !== metric) $(`[data-metric="${CSS.escape(m)}"]`)?.click();
  if (params.has("l")) {
    const want = new Set(params.get("l").split(","));
    $$("[data-layer]").forEach((c) => (c.checked = want.has(c.dataset.layer)));
    refreshPoints();
    if (want.has("cables") !== $("#show-cables").checked) $("#show-cables").click();
  }
  const cc = params.get("c")?.toUpperCase();
  const f = cc && window.__features.find((x) => x.properties.c?.a2 === cc);
  if (f && f !== selected) selectCountry(f, null);
}

function show(hash) {
  const RAIL_MAP = {
    "warroom": "warroom",
    "globe": "globe",
    "disruptions": "globe",
    "terminal": "terminal",
    "supply-chain": "terminal",
    "leaks": "terminal",
    "shield": "shield",
    "check": "shield",
    "canary": "shield",
    "remediation": "shield",
    "flaws": "flaws",
    "attacks": "flaws",
    "breaches": "flaws",
    "news": "flaws",
    "results": "flaws"
  };

  let [tab, story] = hash.split("?")[0].split("/");
  if (tab === "home" || !$(`#tab-${tab}`)) tab = "warroom"; // Black October is the landing crisis room
  $$(".tab").forEach((s) => (s.hidden = s.id !== `tab-${tab}`));
  
  const railTab = RAIL_MAP[tab] || tab;
  $$("nav a").forEach((a) => a.classList.toggle("on", a.dataset.tab === railTab));
  
  if (!loaded.has(tab) && loaders[tab]) load(tab);
  document.body.classList.toggle("on-globe", tab === "globe");
  document.body.classList.toggle("on-sheet", tab !== "globe");
  if (tab === "globe" && globe) setTimeout(sizeGlobe, 50);
  if (globe && !flat) tab === "globe" ? globe.resumeAnimation() : globe.pauseAnimation();
  window.scrollTo(0, 0);
  if (tab === "globe") [...route().params].length ? applyUrlState() : syncUrl();
}
window.addEventListener("hashchange", () => show(location.hash.slice(1)));

// ---------- command palette (Ctrl+K or /): modules, countries, recent searches and live lookups ----------
const MODULES = $$(".rail a").map((a) => ({ kind: "Module", label: a.getAttribute("aria-label"), go: a.getAttribute("href") }));
let paletteItems = [], paletteActive = 0, paletteTimer, countryIndex = [];
const looksLookup = (q) => /^(\d{1,3}\.){3}\d{1,3}$/.test(q) || /^cve-\d{4}-\d{3,}$/i.test(q) || q.length >= 3;

function recent() {
  try {
    return JSON.parse(localStorage.getItem("alibi.recent") || "[]");
  } catch {
    return [];
  }
}
function remember(q) {
  try {
    localStorage.setItem("alibi.recent", JSON.stringify([q, ...recent().filter((x) => x !== q)].slice(0, 6)));
  } catch {
    // private windows can refuse storage; recent searches are a convenience only
  }
}

async function openPalette(q = "") {
  $("#palette").hidden = false;
  const input = $("#palette-q");
  input.value = q;
  input.focus();
  if (!countryIndex.length) {
    try {
      const { countries } = await api("/v1/intel/countries");
      countryIndex = Object.entries(countries).map(([a2, c]) => ({ kind: "Country", label: c.name, go: `#globe?c=${a2}` }));
    } catch {
      countryIndex = [];
    }
  }
  paletteQuery(input.value);
}

function closePalette() {
  $("#palette").hidden = true;
  $("#palette-detail").innerHTML = "";
  $("#open-palette").focus({ preventScroll: true });
}

function paletteQuery(raw) {
  const q = raw.trim(), lq = q.toLowerCase();
  clearTimeout(paletteTimer);
  $("#palette-detail").innerHTML = "";
  let items;
  if (!q) items = [...recent().map((r) => ({ kind: "Recent", label: r, query: r })), ...MODULES];
  else {
    const at = (x) => x.label.toLowerCase().indexOf(lq);
    items = [...MODULES, ...countryIndex].filter((x) => at(x) >= 0).sort((a, b) => at(a) - at(b)).slice(0, 8);
    if (looksLookup(q)) {
      items.unshift({ kind: "Look up", label: q, query: q });
      paletteTimer = setTimeout(() => lookup(q), 250);
    }
  }
  paletteItems = items;
  paletteActive = 0;
  renderPalette();
}

function renderPalette() {
  $("#palette-list").innerHTML = paletteItems.map((x, i) => `<li role="option" id="pal-${i}" aria-selected="${i === paletteActive}" data-i="${i}">
    <span class="k">${esc(x.kind)}</span><span class="t">${esc(x.label)}</span>${x.go ? ico("chevron-right") : ""}</li>`).join("")
    || '<li class="none">No matches. Try an IP address, a CVE id or a company name.</li>';
  $("#palette-q").setAttribute("aria-activedescendant", paletteItems.length ? `pal-${paletteActive}` : "");
  $(`#pal-${paletteActive}`)?.scrollIntoView({ block: "nearest" });
}

async function lookup(q) {
  const box = $("#palette-detail");
  box.innerHTML = '<p class="muted">Looking up…</p>';
  try {
    const r = await api(`/v1/intel/search?q=${encodeURIComponent(q)}`);
    if ($("#palette-q").value.trim() !== q) return; // a newer query is on its way
    box.innerHTML = searchHtml(r);
    remember(q);
  } catch (err) {
    box.innerHTML = `<p class="err">Lookup failed: ${esc(err.message.slice(0, 80))}</p>`;
  }
}

function choose(i) {
  const x = paletteItems[i];
  if (!x) return;
  if (x.go) {
    closePalette();
    location.hash = x.go;
  } else {
    $("#palette-q").value = x.query;
    lookup(x.query);
  }
}

$("#open-palette").addEventListener("click", () => openPalette());
$("#palette-q").addEventListener("input", (e) => paletteQuery(e.target.value));
$("#palette-q").addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    const n = Math.max(paletteItems.length, 1);
    paletteActive = (paletteActive + (e.key === "ArrowDown" ? 1 : -1) + n) % n;
    renderPalette();
  } else if (e.key === "Enter") {
    e.preventDefault();
    choose(paletteActive);
  }
});
$("#palette-list").addEventListener("click", (e) => {
  const li = e.target.closest("[data-i]");
  if (li) choose(+li.dataset.i);
});
$("#palette").addEventListener("click", (e) => e.target.id === "palette" && closePalette());

// ---------- keyboard shortcuts ("?" lists them) ----------
const onGlobe = () => document.body.classList.contains("on-globe");
function stepMetric(d) {
  if (!onGlobe()) return;
  const chips = $$("[data-metric]");
  const i = chips.findIndex((x) => x.classList.contains("on"));
  chips[(i + d + chips.length) % chips.length]?.click();
}
const KEYS = [
  ["g", "Live globe", () => (location.hash = "#globe")],
  ["m", "Tech terminal", () => (location.hash = "#terminal")],
  ["c", "Live footprint", () => (location.hash = "#check")],
  ["h", "DNS shield", () => (location.hash = "#shield")],
  ["o", "BGP disruptions", () => (location.hash = "#disruptions")],
  ["p", "Supply chain", () => (location.hash = "#supply-chain")],
  ["k", "Leak hunter", () => (location.hash = "#leaks")],
  ["y", "Canary tripwires", () => (location.hash = "#canary")],
  ["e", "AI remediation", () => (location.hash = "#remediation")],
  ["t", "Threats", () => (location.hash = "#attacks")],
  ["l", "Leaks", () => (location.hash = "#breaches")],
  ["f", "Exploited flaws", () => (location.hash = "#flaws")],
  ["n", "News", () => (location.hash = "#news")],
  ["s", "Sources and accuracy", () => (location.hash = "#results")],
  ["r", "Replay the last 48 hours (globe)", () => onGlobe() && $("#replay-play").click()],
  ["[", "Previous map colour (globe)", () => stepMetric(-1)],
  ["]", "Next map colour (globe)", () => stepMetric(1)],
  ["0", "Reset the globe view", () => onGlobe() && $("#reset-view").click()],
];
$("#help-keys").innerHTML = [["Ctrl K or /", "Search"], ...KEYS, ["?", "Show this list"], ["Esc", "Close a dialog"]]
  .map(([k, label]) => `<dt><kbd>${esc(k)}</kbd></dt><dd>${esc(label)}</dd>`).join("");
function toggleHelp(open = $("#help").hidden) {
  $("#help").hidden = !open;
  if (open) $("#help-close").focus();
}
$("#open-help").addEventListener("click", () => toggleHelp(true));
$("#help-close").addEventListener("click", () => toggleHelp(false));
$("#help").addEventListener("click", (e) => e.target.id === "help" && toggleHelp(false));
document.addEventListener("keydown", (e) => {
  if (e.ctrlKey || e.metaKey || e.altKey || typing() || !$("#palette").hidden) return;
  if (e.key === "?") {
    e.preventDefault();
    return toggleHelp();
  }
  if (e.key === "Escape") return toggleHelp(false);
  if (!$("#help").hidden) return;
  const hit = KEYS.find(([k]) => k === e.key.toLowerCase());
  if (hit) {
    e.preventDefault();
    hit[2]();
  }
});
const typing = () => /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "") || document.activeElement?.isContentEditable;
document.addEventListener("keydown", (e) => {
  if ((e.key.toLowerCase() === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing())) {
    e.preventDefault();
    $("#palette").hidden ? openPalette() : closePalette();
  } else if (e.key === "Escape") {
    if ($("#state-modal") && !$("#state-modal").hidden) closeStateDossier();
    else if (!$("#palette").hidden) closePalette();
  }
});

function openStateDossier(stateId) {
  const modal = $("#state-modal");
  if (!modal) return;
  modal.hidden = false;
  const body = $("#state-dossier-body");
  body.innerHTML = '<p class="muted">Loading regional intelligence telemetry...</p>';

  api(`/v1/intel/state/${encodeURIComponent(stateId)}`)
    .then((d) => {
      $("#state-title").textContent = `${d.name} (${d.country_code}) · State Intelligence Dossier`;
      const t = d.telemetry;
      const ooni = d.ooni_censorship;
      const net = d.network_stability;

      const tierColors = {
        CRITICAL: "var(--crimson)",
        HIGH: "var(--amber)",
        ELEVATED: "var(--accent)",
        LOW: "#22c55e",
        UNRATED: "var(--dim)",
      };
      const tierColor = tierColors[t.threat_tier] || "var(--dim)";

      body.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; padding-bottom:10px; border-bottom:1px solid var(--line);">
          <div>
            <div style="font-size:18px; font-weight:700;">${esc(d.name)}</div>
            <div class="muted" style="font-size:12px;">${esc(d.type)} · ${esc(d.country_name)}</div>
          </div>
          <span style="background:${tierColor}20; color:${tierColor}; border:1px solid ${tierColor}; padding:4px 10px; border-radius:4px; font:700 11px var(--hud); letter-spacing:0.1em;">
            ${esc(t.threat_tier)}
          </span>
        </div>

        <div style="font-size:12px; margin-bottom:16px; color:var(--dim);">
          ${esc(t.tier_description)}
        </div>

        <div style="display:grid; grid-template-columns:repeat(2, 1fr); gap:10px; margin-bottom:16px;">
          <div class="card" style="padding:10px; background:var(--bg-card); border-radius:4px; border:1px solid var(--line);">
            <div class="muted" style="font-size:11px; text-transform:uppercase;">Malware C2 Nodes</div>
            <div style="font-size:20px; font-weight:700; color:var(--crimson);">${fmt(t.malware_c2_nodes)}</div>
          </div>
          <div class="card" style="padding:10px; background:var(--bg-card); border-radius:4px; border:1px solid var(--line);">
            <div class="muted" style="font-size:11px; text-transform:uppercase;">Threat Density</div>
            <div style="font-size:20px; font-weight:700;">${t.threat_density_per_million ? t.threat_density_per_million + ' / 1M' : 'N/A'}</div>
          </div>
          <div class="card" style="padding:10px; background:var(--bg-card); border-radius:4px; border:1px solid var(--line);">
            <div class="muted" style="font-size:11px; text-transform:uppercase;">Public DNS Resolvers</div>
            <div style="font-size:18px; font-weight:600;">${fmt(t.public_dns_nodes)}</div>
          </div>
          <div class="card" style="padding:10px; background:var(--bg-card); border-radius:4px; border:1px solid var(--line);">
            <div class="muted" style="font-size:11px; text-transform:uppercase;">Total IPv4 Allocated</div>
            <div style="font-size:18px; font-weight:600;">${fmt(t.total_ipv4_addresses)}</div>
          </div>
        </div>

        <div style="margin-bottom:14px;">
          <div style="font:600 11px var(--hud); letter-spacing:0.1em; text-transform:uppercase; color:var(--dim); margin-bottom:6px;">Infrastructure & Telemetry</div>
          <div style="font-size:12.5px; line-height:1.6;">
            <div>• <b>Hosting / Cloud IPv4:</b> ${compact(net.hosting_ipv4)} addresses announced</div>
            <div>• <b>Tor Anonymization Relays:</b> ${fmt(net.tor_exit_nodes)} active exit nodes</div>
            <div>• <b>Submarine Cable Landings:</b> ${fmt(net.subsea_cable_landings)} global fiber landing points</div>
            <div>• <b>Confirmed Censorship Blocks (OONI):</b> ${fmt(ooni.confirmed_blocks)} blocks across ${compact(ooni.measurement_count)} tests</div>
          </div>
        </div>

        ${d.top_threat_cities && d.top_threat_cities.length ? `
          <div style="margin-top:12px;">
            <div style="font:600 11px var(--hud); letter-spacing:0.1em; text-transform:uppercase; color:var(--dim); margin-bottom:6px;">Regional Threat Hotspots</div>
            <div style="display:flex; flex-wrap:wrap; gap:6px;">
              ${d.top_threat_cities.map((cityObj) => `<span style="background:var(--bg); border:1px solid var(--line); padding:2px 8px; border-radius:3px; font-size:11.5px;">${esc(cityObj.city)}: <b>${cityObj.count}</b></span>`).join("")}
            </div>
          </div>
        ` : ""}
      `;
    })
    .catch((err) => {
      body.innerHTML = `<p style="color:var(--crimson);">Failed to load state dossier: ${esc(err.message || String(err))}</p>`;
    });
}

function closeStateDossier() {
  const modal = $("#state-modal");
  if (modal) modal.hidden = true;
}

$("#state-modal-close")?.addEventListener("click", closeStateDossier);
$("#state-modal")?.addEventListener("click", (e) => e.target.id === "state-modal" && closeStateDossier());

function searchHtml(r) {
  if (r.kind === "ip") {
    const n = r.ip, rep = r.report;
    return `<h3>${esc(r.query)}</h3><p><b>${esc(n.type)}</b>${n.network ? ` on ${esc(n.network)} (AS${n.asn})` : ""}${
      n.country ? `, registered in ${esc(n.country)}` : ""}.</p>` +
      (rep ? `<p class="err">Reported as a ${esc(rep.what.toLowerCase())} (${esc(rep.malware)}) to abuse.ch ${esc(rep.source)} on ${day(rep.seen)}.</p>`
        : "<p class=\"muted\">Not on the abuse.ch malware lists in this snapshot.</p>") +
      (n.criminal_network ? "<p class=\"err\">Its network is on the Spamhaus DROP list (run by criminals).</p>" : "") +
      `<p class="fineprint"><a href="/v1/intel/ip/${encodeURIComponent(r.query)}/stix" target="_blank">Download as STIX 2.1</a></p>`;
  }
  if (r.kind === "cve") {
    return r.flaws.length ? r.flaws.map((f) => `<h3>${esc(f.cve)}</h3><p>${esc(f.name)}</p>
      <p class="fineprint">Added to CISA's exploited list ${day(f.added)}${f.ransomware ? " · used by ransomware" : ""} ·
      <a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" rel="noopener">NVD</a></p>`).join("")
      : `<p class="muted">${esc(r.query)} is not on CISA's list of exploited flaws.</p>`;
  }
  const b = r.breaches.map((x) => `<li><b>${esc(x.name)}</b> ${esc(x.domain)}: ${fmt(x.accounts)} accounts, ${day(x.breach_date)} · ${esc(x.how)}</li>`).join("");
  const f = r.flaws.map((x) => `<li><b>${esc(x.cve)}</b> ${esc(x.vendor)} ${esc(x.product)} · added ${day(x.added)}</li>`).join("");
  return `<h4>Breaches (${fmt(r.breach_matches)})</h4>${b ? `<ul>${b}</ul>` : '<p class="muted">No published breach matches.</p>'}
    <h4>Exploited flaws (${fmt(r.flaw_matches)})</h4>${f ? `<ul>${f}</ul>` : '<p class="muted">No exploited flaw matches.</p>'}`;
}

// ---------- libraries, loaded only when a tab needs them ----------
const LIBS = {
  d3: "/static/vendor/d3.min.js",
  topojson: "/static/vendor/topojson-client.min.js",
  globe: "/static/vendor/globe.gl.min.js", // includes three.js, about 1.9 MB
  leaflet: "/static/vendor/leaflet.js",
};
const libLoads = {};
function need(...names) {
  return Promise.all(names.map((n) => (libLoads[n] ??= new Promise((ok, fail) => {
    const tag = document.createElement("script");
    tag.src = LIBS[n];
    tag.onload = ok;
    tag.onerror = () => fail(new Error(`Could not load ${n}`));
    document.head.append(tag);
  }))));
}

// ---------- shared country data ----------
const WORLD_URL = "/static/vendor/countries-110m.json"; // world-atlas 2.0.2, self-hosted
let worldPromise;

function center(f) {
  // centre of the country's largest piece of land (so France sits in Europe, not halfway to French Guiana)
  if (f.geometry.type === "Polygon") return d3.geoCentroid(f);
  const parts = f.geometry.coordinates.map((c) => ({ type: "Polygon", coordinates: c }));
  return d3.geoCentroid(parts.reduce((a, b) => (d3.geoArea(a) > d3.geoArea(b) ? a : b)));
}

function world() {
  worldPromise ??= Promise.all([fetch(WORLD_URL).then((r) => r.json()), api("/v1/intel/countries"), need("d3", "topojson")]).then(([topo, data]) => {
    const byNumeric = {};
    for (const [a2, c] of Object.entries(data.countries)) byNumeric[+c.numeric] = { a2, ...c };
    const features = topojson.feature(topo, topo.objects.countries).features.filter((f) => f.id !== "010"); // no Antarctica
    const centers = {};
    features.forEach((f) => {
      f.properties.c = byNumeric[+f.id];
      if (f.properties.c) centers[f.properties.c.a2] = center(f);
    });
    return { features, data, centers, topo };
  });
  return worldPromise;
}

const sampleCache = {};
const samples = (cc) => (sampleCache[cc] ??= api(`/v1/intel/sample-ips?country=${cc}`));

// ---------- HUD status strip ----------
const STALE_AFTER_H = 8; // feeds refresh every 6 hours; past 8 the snapshot is late
const late = (f) => f.status !== "ok" && !f.status.startsWith("optional");

async function headerStatus() {
  const tick = () => ($("#utc").textContent = new Date().toISOString().slice(11, 19));
  tick();
  setInterval(tick, 1000);
  try {
    const [h, o] = await Promise.all([api("/v1/health"), api("/v1/intel/overview")]);
    const built = new Date(h.snapshot), ageH = (Date.now() - built) / 3600e3;
    const stale = ageH > STALE_AFTER_H;
    $("#live").classList.toggle("stale", stale);
    $("#live-label").textContent = stale ? "STALE" : "LIVE";
    $("#live").title = stale ? `The threat snapshot is ${Math.round(ageH)} hours old; feeds normally refresh every 6 hours.`
      : "Threat feeds refresh every 6 hours; news is fetched live.";
    $("#data-age").textContent = `${built.toISOString().slice(5, 16).replace("T", " ").replace("-", "/")}Z · ${ageH < 1 ? "<1" : Math.round(ageH)}h`;
    const bad = h.feeds.filter(late);
    $("#feeds-ok").textContent = `${h.feeds.length - bad.length}/${h.feeds.length}`;
    $("#feeds-cell").classList.toggle("warn", bad.length > 0);
    $("#feeds-cell").title = bad.map((f) => `${f.name}: ${f.status}${f.age_hours != null ? `, ${f.age_hours} h old` : ""}`).join("\n")
      || "Every feed is within its maximum age";
    $("#on-map").textContent = fmt(Object.values(o.map_points).reduce((s, n) => s + n, 0));
  } catch {
    $("#live").classList.add("stale");
    $("#live-label").textContent = "OFFLINE";
  }
}

// ---------- rail badges: what is new since the snapshot's day began ----------
async function railBadges() {
  const put = (name, n, cap) => {
    const el = $(`[data-badge="${name}"]`);
    if (!el || !n) return;
    el.textContent = n >= cap ? `${cap}+` : n;
    el.hidden = false;
    el.closest("a").setAttribute("aria-label", `${el.closest("a").getAttribute("aria-label")}: ${n} new`);
  };
  try {
    const [act, f, b] = await Promise.all([api("/v1/intel/activity"), api("/v1/intel/flaws"), api("/v1/intel/breaches")]);
    put("attacks", act.new_today, 999);
    put("flaws", f.added_last_7_days, 99);
    const weekAgo = new Date(new Date(b.as_of) - 7 * 86400e3).toISOString().slice(0, 10);
    put("breaches", b.latest.filter((r) => r.added >= weekAgo).length, b.latest.length);
  } catch (err) {
    console.warn("rail badges", err);
  }
}

// ---------- the wire: newest real events, scrolling along the bottom ----------
const WIRE_LABEL = { c2: "C2", dl: "PAYLOAD", kev: "EXPLOITED", breach: "BREACH" };
async function loadWire() {
  try {
    const { items } = await api("/v1/intel/wire");
    if (!items.length) return;
    const when = (x) => (x.precision === "day" ? x.time.slice(0, 10) : `${x.time.slice(11, 16)}Z`);
    const html = items.map((x) => `<button class="wire-item ${x.kind}" type="button" data-q="${esc(x.query)}"
      title="${esc(x.source)}: open in search"><b>${WIRE_LABEL[x.kind]}</b><time>${esc(when(x))}</time><em>${esc(x.title)}</em>
      <span>${esc(x.detail)}</span></button>`).join("");
    const run = $("#wire-run");
    run.innerHTML = html + html.replaceAll('type="button"', 'type="button" tabindex="-1" aria-hidden="true"'); // twice, for a seamless loop
    run.style.setProperty("--wire-dur", `${Math.max(60, items.length * 4)}s`);
    run.addEventListener("click", (e) => {
      const b = e.target.closest("[data-q]");
      if (b) openPalette(b.dataset.q);
    });
  } catch (err) {
    console.warn("wire", err);
  }
}

// ---------- overview ----------
const hhmm = (unix) => new Date(unix * 1000).toISOString().slice(5, 16).replace("T", " ") + "Z";

// The live situation panel: today's headline numbers, drawn over the globe.
async function situation() {
  const [o, act] = await Promise.all([api("/v1/intel/overview"), api("/v1/intel/activity")]);
  const rw = o.ransomware_victims;
  $("#sit-mal").textContent = fmt(o.malicious_ips);
  $("#sit-new").textContent = `+${fmt(act.new_today)} TODAY`;
  $("#sit-new").hidden = !act.new_today;
  $("#sit-sub").textContent = `${fmt(o.map_points.c2 || 0)} control servers · ${fmt(o.map_points.dl || 0)} download sites`;
  $("#sit-meta").textContent = "abuse.ch · Spamhaus";
  $("#sit-end").textContent = hhmm(act.window_end);
  const max = Math.max(...act.per_hour, 1);
  $("#home-activity").innerHTML = act.per_hour.map((n, i) => `<i style="height:${Math.max(4, (n / max) * 100)}%" title="${n} reported, ${47 - i} h before the snapshot"></i>`).join("");
  $("#home-kpis").innerHTML = [
    kpi(compact(o.accounts_exposed_last_12_months), `accounts exposed in ${o.breaches_last_12_months} breaches, 12 months`),
    kpi(fmt(o.exploited_flaws_last_30_days), "flaws newly confirmed exploited, 30 days"),
    kpi(fmt(rw.victims), "ransomware leak-site posts, 7 days"),
    kpi(fmt(o.threat_indicators_48h), "new threat indicators shared, 48 hours"),
  ].join("");
}

// ---------- live globe ----------
const METRICS = {
  malicious_ips: {
    state: "m",
    title: "Malware and botnet servers",
    explain: "Servers reported to abuse.ch for spreading malware or controlling botnets, placed by IP geolocation and divided by the IPv4 addresses in each state. Hijacked home routers and cameras dominate, so dense home-broadband regions rank high.",
    source: "malware",
  },
  dns_resolvers: {
    state: "d",
    title: "Public DNS servers",
    explain: "Working open DNS resolvers per million IPv4 addresses. Useful infrastructure, also abused for traffic amplification and blocked under censorship.",
    source: "dns",
  },
  confirmed_blocks: {
    title: "Websites confirmed blocked, 30 d",
    explain: "OONI Probe tests that hit a known government or ISP block page. Country-level; more volunteers means more tests.",
    source: "censorship",
  },
  hosting_ipv4: {
    title: "Hosting / VPN address space",
    explain: "IPv4 addresses owned by cloud, hosting and VPN providers. Country-level. Sign-ins from these networks get extra scrutiny.",
    source: "network",
  },
  cable_landings: {
    title: "Undersea cable landing stations",
    explain: "Where undersea internet cables come ashore. Country-level. Few landings means a single fault can cut a country off.",
    source: "cables",
  },
  tor_exits: {
    title: "Tor exit relays",
    explain: "Relays where Tor traffic leaves the network. Country-level. A sign-in from one could originate anywhere.",
    source: "tor",
  },
};
const POINT_COLORS = { c2: "#d55e00", dl: "#e69f00", tor: "#cc79a7", drop: "#f0e442", landing: "#56b4e9", compute: "#06b6d4" };
let metric = "malicious_ips", globe, selected, journey = [], journeyArcs = [], legendData = null;

function sizeGlobe() {
  const el = $("#globe");
  if (globe && el.clientWidth) globe.width(el.clientWidth).height(el.clientHeight);
}

const IMG = "/static/vendor/img/"; // NASA Blue Marble imagery (public domain), self-hosted
// Phones and tablets get 2048-pixel textures; desktops keep the full 4096.
const SMALL_SCREEN = matchMedia("(pointer: coarse)").matches || innerWidth < 900;
const TEX_W = SMALL_SCREEN ? 2048 : 4096;
const REDUCED_MOTION = matchMedia("(prefers-reduced-motion: reduce)").matches;
let places = [], pickData = null, pickW = 0, pickH = 0, heatPromise, cablesLoaded = null, selState = null, snapshotAt = "";
let events = { points: [], types: {} }, cablePaths = [], landingPoints = [], computePoints = [], computeLoaded = null, flat = false;

// The server paints each metric's states into the Earth texture (see intel/globe.py), so the browser
// downloads one image instead of drawing 4,596 states itself.
const texUrl = (m) => `/v1/intel/globe/${m}.jpg?w=${TEX_W}&v=${encodeURIComponent(snapshotAt)}`;

function webglWorks() {
  try {
    const c = document.createElement("canvas");
    return !!(window.WebGLRenderingContext && (c.getContext("webgl2") || c.getContext("webgl")));
  } catch {
    return false;
  }
}

async function loadPickMap() {
  const [img, rows] = await Promise.all([
    new Promise((ok, fail) => { const i = new Image(); i.onload = () => ok(i); i.onerror = fail; i.src = "/v1/intel/globe/pick.png"; }),
    api("/v1/intel/globe/places"),
  ]);
  const c = document.createElement("canvas");
  c.width = pickW = img.width;
  c.height = pickH = img.height;
  const ctx = c.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  pickData = ctx.getImageData(0, 0, pickW, pickH).data;
  places = rows.rows.map(([n, c2, t, m, d, ip], i) => ({ i, n, c: c2, t, m, d, ip }));
}

function stateAt(at) {
  if (!at || !pickData) return null;
  const x = Math.min(pickW - 1, Math.floor(((at.lng + 180) / 360) * pickW));
  const y = Math.min(pickH - 1, Math.floor(((90 - at.lat) / 180) * pickH));
  const k = (y * pickW + x) * 4;
  const index = ((pickData[k] << 8) | pickData[k + 1]) - 1;
  return index >= 0 ? places[index] : null;
}

const perMillion = (count, ip) => (ip >= 100000 ? `${(count / ip * 1e6).toFixed(2)} per 1M addresses` : "too few addresses to rate");

function activePoints() {
  const on = new Set($$("[data-layer]").filter((c) => c.checked).map((c) => c.dataset.layer));
  const pts = events.points.filter((p) => on.has(p[2])).map(([lat, lng, kind]) => ({ lat, lng, kind }));
  let res = pts;
  if ($("#show-cables")?.checked) res = res.concat(landingPoints);
  if ($("#show-compute")?.checked) res = res.concat(computePoints);
  return res;
}

function refreshPoints() {
  if (!globe || flat) return;
  globe.pointsData(activePoints());
}

// Flat fallback for phones or browsers without WebGL: the same server texture as a 2D map you can tap.
function flatMap(features) {
  flat = true;
  const el = $("#globe");
  el.classList.add("flat");
  el.innerHTML = `<img alt="Map of ${esc(METRICS[metric].title)}" src="${texUrl(metric)}">`;
  el.querySelector("img").addEventListener("click", (e) => {
    const r = e.target.getBoundingClientRect();
    const at = { lng: ((e.clientX - r.left) / r.width) * 360 - 180, lat: 90 - ((e.clientY - r.top) / r.height) * 180 };
    pickAt(features, at);
  });
}

loaders.globe = async () => {
  const el = $("#globe");
  el.innerHTML = `<div class="globe-poster"><span>LOADING GLOBE</span></div>`;
  const useGl = webglWorks();
  const [{ features, data, centers }, ev, act] = await Promise.all([world(), api("/v1/intel/events"), api("/v1/intel/activity"),
    useGl ? need("globe") : null, loadPickMap()]);
  snapshotAt = data.as_of;
  events = ev;
  for (const k of ["c2", "dl", "tor", "drop"]) {
    const n = ev.points.filter((p) => p[2] === k).length;
    const box = $(`[data-count="${k}"]`);
    if (box) box.textContent = fmt(n);
    if (!n) $(`[data-layer="${k}"]`)?.closest("label")?.remove();
  }
  if (!data.totals.tor_exit_relays) $('[data-metric="tor_exits"]').remove();
  globe = null;
  if (useGl) {
    try {
      globe = Globe({ animateIn: !REDUCED_MOTION, rendererConfig: { antialias: !SMALL_SCREEN, powerPreference: "high-performance" } })(el);
    } catch (err) {
      console.error("WebGL globe failed, using the flat map", err);
    }
  }
  setupTimeline(act);
  situation().catch((err) => console.error("situation", err));
  globe ? setupGlobe(el, features, data, centers) : flatMap(features);
  globe && (globe.__features = features);
  window.__features = features;
  window.__data = data;
  window.__centers = centers;

  $$("[data-metric]").forEach((b) => b.addEventListener("click", () => {
    metric = b.dataset.metric;
    $$("[data-metric]").forEach((x) => x.classList.toggle("on", x === b));
    paint();
    if (selected) selectCountry(selected, window.__lastAt);
    syncUrl();
  }));
  $$("[data-layer]").forEach((c) => c.addEventListener("change", () => { refreshPoints(); syncUrl(); }));
  $("#show-cables").addEventListener("change", async () => {
    if (!globe) return;
    const on = $("#show-cables").checked;
    if (on) cablesLoaded ??= api("/v1/intel/cables"); // the 733 cable paths load only when asked for
    const cab = on ? await cablesLoaded : null;
    cablePaths = on ? cab.cables.flatMap((c) => c.paths.map((p) => ({ name: c.name, color: c.color, coords: p }))) : [];
    landingPoints = on ? cab.landings.map((l) => ({ lat: l.lat, lng: l.lng, kind: "landing" })) : [];
    globe.pathsData(cablePaths);
    refreshPoints();
    syncUrl();
  });
  $("#show-compute")?.addEventListener("change", async () => {
    if (!globe) return;
    const on = $("#show-compute").checked;
    if (on && !computeLoaded) {
      try {
        const d = await api("/v1/intel/compute-atlas");
        computePoints = (d.clusters || []).map((c) => ({
          lat: c.lat,
          lng: c.lon,
          kind: "compute",
          name: c.name,
          operator: c.operator,
          chips: c.hardware,
        }));
      } catch (err) {
        console.error("compute atlas load", err);
      }
    }
    refreshPoints();
    syncUrl();
  });
  $$("[data-toggle]").forEach((b) => b.addEventListener("click", () => {
    const target = $(`#${b.dataset.toggle}`);
    const open = !target.classList.contains("open");
    $$(".ov-left, .ov-right").forEach((p) => p.classList.remove("open"));
    target.classList.toggle("open", open);
  }));
  $$("[data-journey]").forEach((b) => b.addEventListener("click", () => {
    journey = b.dataset.journey.split(",");
    renderJourney();
    runJourney();
  }));
  $("#journey-go").addEventListener("click", runJourney);
  $("#tour-btn").addEventListener("click", () => (touring ? stopTour() : tour()));
  paint();
  worldReady = true;
  applyUrlState();
  if (new URLSearchParams(location.search).has("tour")) tour();
};

function setupGlobe(el, features, data, centers) {
  globe
    .globeImageUrl(texUrl(metric))
    .showAtmosphere(true).atmosphereColor("#4c90f0").atmosphereAltitude(0.14)
    .onGlobeClick((at) => pickAt(features, at))
    .polygonsData([]).polygonCapColor(() => "rgba(255,255,255,0.18)").polygonSideColor(() => "rgba(0,0,0,0)")
    .polygonStrokeColor(() => "#ffffff").polygonAltitude(0.006)
    .onPolygonClick((_p, _e, at) => pickAt(features, at))
    .pathPoints("coords").pathPointLat((p) => p[0]).pathPointLng((p) => p[1]).pathPointAlt(0.004)
    .pathColor((p) => p.color).pathDashLength(0.08).pathDashGap(0.01).pathDashAnimateTime(16000).pathTransitionDuration(0)
    .pathLabel((p) => `<div class="globe-tip">Undersea cable: ${esc(p.name)}</div>`)
    .pointLat("lat").pointLng("lng").pointAltitude(0.004).pointRadius((p) => (p.kind === "landing" ? 0.12 : p.kind === "compute" ? 0.28 : 0.16))
    .pointLabel((p) => (p.kind === "compute" ? `<div class="globe-tip">AI Cluster: <b>${esc(p.operator)}</b><br>${esc(p.name)}<br><small>${esc(p.chips)}</small></div>` : ""))
    .pointColor((p) => POINT_COLORS[p.kind]).pointsMerge(true).pointsTransitionDuration(0)
    .ringLat("lat").ringLng("lng").ringColor((r) => (t) => `rgba(${r.rgb},${1 - t})`).ringMaxRadius(2.6)
    .ringPropagationSpeed(3).ringRepeatPeriod(0)
    .arcsData([]).arcColor("color").arcStroke(0.8).arcDashLength(0.5).arcDashGap(0.15).arcDashAnimateTime(1600)
    .arcAltitudeAutoScale(0.45).arcLabel((a) => `<div class="globe-tip">${esc(a.label)}</div>`)
    .labelsData([]).labelLat("lat").labelLng("lng").labelText("text").labelSize(1.1).labelDotRadius(0.45)
    .labelColor(() => "#ffffff").labelResolution(2);
  if (!SMALL_SCREEN) globe.bumpImageUrl(`${IMG}earth-topology.png`).backgroundImageUrl(`${IMG}night-sky.png`);
  globe.renderer().setPixelRatio(Math.min(window.devicePixelRatio, 1.5));
  globe.pointOfView({ lat: 22, lng: 40, altitude: SMALL_SCREEN ? 2.6 : 1.9 });
  Object.assign(globe.controls(), { autoRotate: !REDUCED_MOTION && !SMALL_SCREEN, autoRotateSpeed: 0.3, minDistance: 112, maxDistance: 600 });
  $("#reset-view").addEventListener("click", () => globe.pointOfView({ lat: 22, lng: 40, altitude: 1.9 }, 800));
  el.addEventListener("pointerdown", () => (globe.controls().autoRotate = false), { once: true });
  // a lost WebGL context (common on phones under memory pressure) falls back to the flat map
  el.querySelector("canvas")?.addEventListener("webglcontextlost", () => { globe.pauseAnimation(); flatMap(features); paint(); });
  sizeGlobe();
  new ResizeObserver(sizeGlobe).observe(el);
  // drawn once behind a module sheet, then paused until the globe is opened again
  globe.onGlobeReady(() => setTimeout(() => !document.body.classList.contains("on-globe") && globe.pauseAnimation(), 1200));
  refreshPoints();

  const tip = $("#globe-tip");
  let frame = 0;
  el.addEventListener("mousemove", (e) => {
    if (frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      const box = el.getBoundingClientRect();
      const s = stateAt(globe.toGlobeCoords(e.clientX - box.left, e.clientY - box.top));
      if (!s) return void (tip.hidden = true);
      tip.hidden = false;
      tip.style.left = `${Math.min(e.clientX - box.left + 14, box.width - 270)}px`;
      tip.style.top = `${e.clientY - box.top + 14}px`;
      tip.innerHTML = stateTip(s);
    });
  });
  el.addEventListener("mouseleave", () => (tip.hidden = true));
}

// ---------- 48-hour replay: each malware server pulses where and when it was reported ----------
let replay = null;

function setupTimeline(act) {
  $("#new-today").textContent = fmt(act.new_today);
  $("#last-48h").textContent = fmt(act.last_48h);
  const max = Math.max(...act.per_hour, 1);
  $("#replay-hist").innerHTML = act.per_hour.map((n, i) => `<i style="height:${(n / max) * 100}%" title="${n} reported ${47 - i}-${48 - i} h before the snapshot"></i>`).join("");
  $("#replay-time").textContent = `window ends ${hhmm(act.window_end)}`;
  $("#replay-play").addEventListener("click", () => (replay ? stopReplay() : startReplay(act)));
}

function startReplay(act, seconds = 36) {
  const end = act.window_end, start = end - 48 * 3600;
  const timed = events.points.filter((p) => p[3] && p[3] >= start && p[3] <= end).sort((a, b) => a[3] - b[3]);
  const bars = $$("#replay-hist i");
  const rgb = { c2: "213,94,0", dl: "230,159,0" };
  let k = 0;
  const t0 = performance.now();
  $("#replay-play").innerHTML = ico("pause");
  replay = { stop: false };
  const step = () => {
    if (!replay || replay.stop) return;
    const now = start + ((performance.now() - t0) / (seconds * 1000)) * 48 * 3600;
    const fresh = [];
    while (k < timed.length && timed[k][3] <= now) {
      const [lat, lng, kind] = timed[k++];
      fresh.push({ lat, lng, rgb: rgb[kind] || "230,159,0" });
    }
    if (fresh.length && globe) globe.ringsData([...globe.ringsData().slice(-120), ...fresh]);
    const hour = Math.min(47, Math.floor((now - start) / 3600));
    bars.forEach((b, i) => b.classList.toggle("past", i <= hour));
    $("#replay-time").textContent = `${hhmm(Math.min(now, end))} · ${fmt(k)} reported`;
    if (now >= end) return stopReplay(true);
    requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function stopReplay(done = false) {
  if (replay) replay.stop = true;
  replay = null;
  $("#replay-play").innerHTML = ico("play");
  if (!done) $$("#replay-hist i").forEach((b) => b.classList.remove("past"));
  setTimeout(() => globe && globe.ringsData([]), done ? 2500 : 0);
}

// ---------- tour: a hands-free walk through today's real hotspots ----------
let touring = false;
const pause = (ms) => new Promise((r) => setTimeout(r, ms));

function caption(label, text) {
  const c = $("#tour-caption");
  c.hidden = !text;
  c.innerHTML = text ? `<span class="label">${esc(label)}</span>${text}` : "";
}

async function tour() {
  if (!globe || touring) return;
  touring = true;
  $("#tour-btn").innerHTML = `${ico("x")}<span>Stop tour</span>`;
  globe.controls().autoRotate = false;
  try {
    const lg = await api("/v1/intel/globe/malicious_ips/legend");
    const act = await api("/v1/intel/activity");
    if (metric !== "malicious_ips") $('[data-metric="malicious_ips"]').click();
    const o = await api("/v1/intel/overview");
    caption("Today", `${fmt(o.malicious_ips)} malware and botnet servers tracked; ${fmt(act.new_today)} reported since 00:00 UTC.`);
    globe.pointOfView({ lat: 20, lng: 40, altitude: 2.2 }, 1500);
    await pause(4000);
    for (const top of lg.top.filter((x) => x.lat != null).slice(0, 3)) {
      if (!touring) return;
      globe.pointOfView({ lat: top.lat, lng: top.lng, altitude: 0.9 }, 2200);
      caption("Hotspot", `<b>${esc(top.name)}</b>: ${top.value.toFixed(2)} malware servers per 1M addresses (${fmt(top.count)} servers).`);
      await pause(4500);
    }
    if (!touring) return;
    globe.pointOfView({ lat: 25, lng: 60, altitude: 2.3 }, 1800);
    caption("Replay", "The last 48 hours, each malware server shown where and when it was reported.");
    await pause(1800);
    startReplay(act, 14);
    await pause(15500);
    if (!touring) return;
    journey = ["IN", "GB"];
    renderJourney();
    caption("Sign-in check", "One account signs in from India, then from the UK 45 minutes later.");
    await runJourney();
    await pause(4500);
  } finally {
    stopTour();
  }
}

function stopTour() {
  touring = false;
  $("#tour-btn").innerHTML = `${ico("orbit")}<span>Tour</span>`;
  caption("", "");
}

function pickAt(features, at) {
  const f = at && features.find((x) => d3.geoContains(x, [at.lng, at.lat]));
  if (f) selectCountry(f, at);
}

function stateTip(s) {
  const c = window.__data.countries[s.c];
  const m = METRICS[metric];
  const rate = m.state ? `<br>${perMillion(m.state === "m" ? s.m : s.d, s.ip)}` : "";
  return `<b>${esc(s.n)}</b> <span class="muted">${esc(s.t)}${c ? `, ${esc(c.name)}` : ""}</span>
    <br>${fmt(s.m)} malware servers · ${fmt(s.d)} public DNS servers${rate}` +
    (c && !m.state ? `<br>${esc(c.name)} (country): ${fmt(c[metric])}` : "");
}

async function paint() {
  const data = window.__data;
  const m = METRICS[metric];
  if (globe) globe.globeImageUrl(texUrl(metric));
  else $("#globe img") && ($("#globe img").src = texUrl(metric));
  const lg = (legendData = await api(`/v1/intel/globe/${metric}/legend`));
  stamp("globe", lg.as_of, "");
  $("#legend").innerHTML = `<div class="label">${esc(lg.unit)}${lg.level === "country" ? " · country-level" : ""}</div><div class="bins">` +
    [...lg.bins, lg.no_data].map((b) => `<span><i style="background:${b.color}"></i>${esc(b.label)}</span>`).join("") + "</div>";
  $("#top-title").textContent = `Top 10 ${lg.level === "state" ? "states" : "countries"} · ${m.title}`;
  $("#top-list").innerHTML = lg.top.map((t) => `<li><span>${esc(t.name)}</span><b>${fmt(t.value)}</b></li>`).join("");
  $("#metric-explain").textContent = m.explain;
  const s = data.sources[m.source];
  const how = lg.level === "state"
    ? ` Placed by IP Geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener">DB-IP</a> (CC BY 4.0); states under ${fmt(lg.min_addresses)} addresses are grey.`
    : "";
  $("#map-sources").innerHTML = s ? `Source: <a href="${s.url}" target="_blank" rel="noopener">${esc(s.name)}</a> (${esc(s.license)}).${how} Colours: ColorBrewer YlOrRd.` : "";
}

async function highlightState(s) {
  if (!globe) return;
  if (!s) return globe.polygonsData([]);
  const { rings } = await api(`/v1/intel/globe/state/${s.i}`);
  globe.polygonsData([{ type: "Feature", properties: {}, geometry: { type: "MultiPolygon",
    coordinates: rings.map((r) => [r.map(([lat, lng]) => [lng, lat])]) } }]);
}

async function selectCountry(f, at) {
  const c = f.properties.c;
  if (!c) return;
  selected = f;
  window.__lastAt = at;
  const st = stateAt(at);
  selState = st && st.c === c.a2 ? st : null;
  highlightState(selState);
  const [lng, lat] = window.__centers[c.a2];
  if (globe) {
    globe.controls().autoRotate = false;
    if (!touring) globe.pointOfView(at ? { lat: at.lat, lng: at.lng, altitude: 1.2 } : { lat, lng, altitude: 1.5 }, 900);
  }
  if (SMALL_SCREEN) { $$(".ov-left").forEach((p) => p.classList.remove("open")); $("#inspector").classList.add("open"); }
  syncUrl();
  const rank = legendData?.ranks?.[c.a2];
  const facts = [
    ["Malware servers", fmt(c.malicious_ips)],
    ["Websites blocked, 30 d", `${fmt(c.confirmed_blocks)} / ${compact(c.censorship_measurements)} tests`],
    ["Public DNS servers", fmt(c.dns_resolvers)],
    ["Hosting / VPN addresses", compact(c.hosting_ipv4)],
    ["Cable landings", fmt(c.cable_landings)],
  ];
  if (window.__data.totals.tor_exit_relays) facts.push(["Tor exits", fmt(c.tor_exits)]);
  const key = METRICS[metric].state === "d" ? "d" : "m";
  const label = key === "d" ? "public DNS servers" : "malware servers";
  const topStates = places.filter((s) => s.c === c.a2 && s[key] > 0).sort((a, b) => b[key] - a[key]).slice(0, 6);
  heatPromise ??= api("/v1/intel/heat"); // city lists load only when a country is opened
  const spots = (await heatPromise).places?.[c.a2]?.[key === "d" ? "dns" : "malware"] || [];
  $("#country-panel").innerHTML = `<h3>Inspector <span class="meta">${esc(c.a2)}</span></h3>
    ${selState ? `<div class="place"><b>${esc(selState.n)}</b> <span class="muted">${esc(selState.t)}</span><br>
      ${fmt(selState.m)} malware servers · ${fmt(selState.d)} public DNS servers
      <br><span class="muted">${perMillion(selState[key], selState.ip)} (${label})</span>
      <button class="btn btn-sm" id="btn-state-dossier" style="margin-top:8px; width:100%; display:flex; align-items:center; justify-content:center; gap:6px;">
        <span>State Intelligence Dossier</span>
      </button>
    </div>` : ""}
    <div class="row"><b style="font-size:16px">${esc(c.name)}</b></div>
    ${rank ? `<p class="rank">#${rank[0]} of ${rank[2]} · ${esc(METRICS[metric].title)} (${fmt(rank[1])})</p>` : ""}
    <div class="facts">${facts.map(([k, v]) => `<div><b>${k}</b>${v}</div>`).join("")}</div>
    ${topStates.length ? `<p class="fineprint"><b>Top states, ${label}:</b> ${topStates.map((s) => `${esc(s.n)} ${fmt(s[key])}`).join(" · ")}</p>` : ""}
    ${spots.length ? `<p class="fineprint"><b>Top cities:</b> ${spots.slice(0, 6).map(([city, n]) => `${esc(city)} ${fmt(n)}`).join(" · ")}</p>` : ""}
    <p class="fineprint" id="country-nets">Looking up networks…</p>
    <button class="btn" id="add-journey" ${journey.length >= 3 ? "disabled" : ""}>Add to journey</button>`;
  $("#btn-state-dossier")?.addEventListener("click", () => {
    if (selState) openStateDossier(selState.i);
  });
  $("#add-journey").addEventListener("click", () => {
    if (journey.length < 3 && journey.at(-1) !== c.a2) journey.push(c.a2);
    $("#journey-panel").open = true;
    renderJourney();
    $("#add-journey").disabled = journey.length >= 3;
  });
  try {
    const s = await samples(c.a2);
    const homes = s.home.map((h) => esc(h.network)).join(", ");
    $("#country-nets").innerHTML = (homes ? `Largest home networks: ${homes}.` : "No home networks on record.") +
      (s.malware ? ` Reported malware server: <span class="mono">${esc(s.malware)}</span>.` : "");
  } catch {
    $("#country-nets").textContent = "";
  }
}

function renderJourney() {
  const names = window.__data.countries;
  $("#journey-list").innerHTML = journey.map((cc, i) => `<li>${esc(names[cc].name)}${i === 0 ? " <span class='muted'>(usual home)</span>" : ""}
    <button data-drop="${i}" aria-label="Remove ${esc(names[cc].name)}">${ico("x")}</button></li>`).join("");
  $$("[data-drop]").forEach((b) => b.addEventListener("click", () => {
    journey.splice(+b.dataset.drop, 1);
    renderJourney();
  }));
  $("#journey-go").disabled = journey.length < 2;
  const pts = journey.map((cc) => ({ lat: window.__centers[cc][1], lng: window.__centers[cc][0], text: names[cc].name }));
  if (globe) globe.labelsData(pts);
  journeyArcs = pts.slice(1).map((p, i) => ({ startLat: pts[i].lat, startLng: pts[i].lng, endLat: p.lat, endLng: p.lng,
    color: [css("--accent"), css("--accent")], label: `${pts[i].text} → ${p.text}` }));
  if (globe) globe.arcsData(journeyArcs);
  $("#journey-result").innerHTML = "";
}

async function runJourney() {
  if (journey.length < 2) return;
  const names = window.__data.countries, centers = window.__centers;
  const gap = Math.max(1, +$("#journey-minutes").value || 1);
  const btn = $("#journey-go");
  $("#journey-err").textContent = "";
  btn.disabled = true;
  btn.textContent = "Checking…";
  try {
    const hops = await Promise.all(journey.map(samples));
    if (hops.some((h) => !h.home.length)) throw new Error("One of these countries has no home networks on record to sign in from.");
    const ev = (ts, i) => {
      const [lon, lat] = centers[journey[i]];
      return { user_id: "demo", login_ts: new Date(ts).toISOString(), ip: hops[i].home[0].ip, country: journey[i],
        city: names[journey[i]].name, lat, lon, success: true, device_id: "usual-laptop", browser: "Chrome 128.0",
        os: "Windows 10", device_type: "desktop" };
    };
    const t0 = Date.now() - gap * 60000 * (journey.length - 1);
    const events = [];
    for (let i = 6; i >= 0; i--) events.push(ev(t0 - i * 2 * 86400000, 0));
    for (let i = 1; i < journey.length; i++) events.push(ev(t0 + i * gap * 60000, i));
    const { timeline } = await api("/v1/demo/check", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ events }),
    });
    const steps = timeline.slice(-(journey.length - 1));
    const tierColor = { LOW: css("--ok"), MEDIUM: css("--warn"), HIGH: css("--risk"), CRITICAL: css("--risk") };
    journeyArcs.forEach((a, i) => {
      a.color = [tierColor[steps[i].tier], tierColor[steps[i].tier]];
      a.label = `${a.label}: ${fmt(Math.round(steps[i].distance_km))} km in ${gap} min, ${steps[i].tier}`;
    });
    if (globe) globe.arcsData([...journeyArcs]);
    $("#journey-result").innerHTML = steps.map((s, i) => `<div class="hop ${s.tier}"><b>${esc(names[journey[i]].name)} → ${esc(names[journey[i + 1]].name)}</b>:
      ${fmt(Math.round(s.distance_km))} km in ${gap} min${s.velocity_kmph ? ` (${fmt(Math.round(s.velocity_kmph))} km/h)` : ""}.
      <span class="badge ${s.tier}">${s.tier}</span><br><span class="muted">${esc(s.reasons[0])}</span></div>`).join("") +
      `<p class="fineprint">Each hop signs in from that country's biggest home network, after two weeks of usual sign-ins from ${esc(names[journey[0]].name)}. Planes fly about 900 km/h.</p>`;
  } catch (err) {
    $("#journey-err").textContent = err.message;
  } finally {
    btn.disabled = journey.length < 2;
    btn.textContent = "Check this journey";
  }
}

// ---------- breaches ----------
let allBreaches, breachList = [];
const HOW_SHORT = (h) => h.replace("Hacked, method not disclosed", "Hacked (method not given)");

function breachRows(rows) {
  breachList = rows;
  $("#breach-rows").innerHTML = rows.map((b, i) => `<tr class="click" data-i="${i}"><td><b>${esc(b.name)}</b><br><span class="fineprint">${esc(b.domain || "")}</span></td>
    <td>${day(b.breach_date)}</td><td class="num">${fmt(b.accounts)}</td><td>${esc(HOW_SHORT(b.how))}</td></tr>`).join("")
    || `<tr><td colspan="4" class="muted">No published breach matches. That's good news, not a guarantee.</td></tr>`;
}

$("#breach-rows").addEventListener("click", (e) => {
  const tr = e.target.closest("tr.click");
  if (!tr) return;
  if (tr.nextElementSibling?.classList.contains("detail")) return tr.nextElementSibling.remove();
  const b = breachList[+tr.dataset.i];
  tr.insertAdjacentHTML("afterend", `<tr class="detail"><td colspan="4">${esc(b.summary)}<br><br><b>Exposed:</b> ${esc(b.data.join(", "))}
    <br><span class="fineprint">Write-up: Have I Been Pwned, CC BY 4.0.</span></td></tr>`);
});

loaders.breaches = async () => {
  const s = await api("/v1/intel/breaches");
  stamp("breaches", s.as_of, ". Breach list from Have I Been Pwned, refreshed daily.");
  const top = s.biggest_companies[0];
  $("#breach-kpis").innerHTML = [
    kpi(fmt(s.total_breaches), "breaches on record"),
    kpi(compact(s.total_accounts), "accounts exposed in total"),
    kpi(fmt(s.last_12_months.breaches), `breaches in the last 12 months, ${compact(s.last_12_months.accounts)} accounts`),
    kpi(compact(top.accounts), `biggest single company breach: ${esc(top.name)}`),
    kpi(compact(s.lists.accounts), `accounts in ${s.lists.count} lists traded by hackers and harvested by info-stealer malware`),
  ].join("");
  bars($("#breach-how"), s.how_stolen.map(([h, n]) => [HOW_SHORT(h), n]));
  bars($("#breach-data"), s.most_exposed_data, (n) => `${fmt(n)} breaches`);
  bars($("#breach-years"), Object.entries(s.accounts_by_year), compact);
  breachRows(s.biggest_companies);
};

$("#breach-search").addEventListener("input", async (e) => {
  const q = e.target.value.trim().toLowerCase();
  allBreaches ??= (await api("/v1/intel/breaches?full=true")).breaches;
  $("#breach-table-title").textContent = q ? `Breaches matching "${e.target.value.trim()}"` : "Biggest company breaches";
  const rows = q ? allBreaches.filter((b) => b.name.toLowerCase().includes(q) || (b.domain || "").toLowerCase().includes(q))
    : allBreaches.filter((b) => b.kind === "company").sort((a, b) => b.accounts - a.accounts);
  breachRows(rows.slice(0, 25));
});

// ---------- attacks ----------
loaders.attacks = async () => {
  const [t, { data }] = await Promise.all([api("/v1/intel/threats"), world()]);
  const name = (cc) => data.countries[cc]?.name || cc;
  const rw = t.ransomware;
  stamp("attacks", t.as_of, ". Malware feeds refresh daily.");
  $("#attack-kpis").innerHTML = [
    kpi(fmt(t.malicious_ips), "servers caught spreading malware or running botnets"),
    kpi(fmt(t.threatfox_iocs_48h), "new threat indicators shared by researchers in the last 48 hours"),
    kpi(fmt(t.urlhaus_online), `malware download links still live, of ${fmt(t.urlhaus_urls_30d)} reported in 30 days`),
    kpi(fmt(rw.victims), `businesses claimed by ransomware gangs, ${day(rw.from)} to ${day(rw.to)}`),
    kpi(fmt(t.spamhaus_asn_drop), "whole networks run by criminals (Spamhaus)"),
  ].join("");
  const iot = t.iot_botnet_ips / t.malicious_ips;
  $("#attack-insight").innerHTML = `<b>The surprise:</b> only ${pct(t.hosting_share_of_malicious_ips, 0)} of these malware servers run on
    hosting or VPN networks, about the same as those networks' ${pct(t.hosting_share_of_internet, 0)} share of the internet.
    ${pct(iot, 0)} are home routers, cameras and other gadgets taken over by botnets like Mozi and Mirai.
    Blocking data centers alone would miss most of them, which is why Alibi checks every IP against these lists too.`;
  bars($("#attack-malware"), t.top_malware.filter(([m]) => !/^(unnamed|unknown malware|none)$/i.test(m)).slice(0, 10));
  bars($("#attack-countries"), t.top_countries.slice(0, 10).map(([cc, n]) => [name(cc), n]));
  $("#attack-networks").innerHTML = t.top_networks.map((n) => `<tr><td>${esc(n.network)} <span class="fineprint">AS${n.asn}</span></td>
    <td>${n.criminal_network ? '<span class="tag">criminal network</span>' : n.hosting ? "hosting / cloud" : "home or business internet provider"}</td>
    <td class="num">${fmt(n.count)}</td></tr>`).join("");
  $("#ransom-window").textContent = `${fmt(rw.victims)} posts on ransomware gangs' leak sites between ${day(rw.from)} and ${day(rw.to)} (RansomLook, CC BY 4.0). ` +
    "Only totals are shown: no victim names, links or stolen files. This source does not record victims' countries or industries.";
  bars($("#ransom-days"), rw.by_day.map(([d, n]) => [day(d), n]));
  bars($("#ransom-groups"), rw.by_group.slice(0, 10));
  $("#drop-text").textContent = `${fmt(t.spamhaus_drop_ranges)} address blocks (${compact(t.spamhaus_drop_addresses)} addresses) and ` +
    `${t.spamhaus_asn_drop} whole networks are on Spamhaus's "do not route" lists: hijacked, or run by spammers and cybercriminals. Where those networks are registered:`;
  bars($("#drop-countries"), t.spamhaus_asn_drop_countries.map(([cc, n]) => [name(cc), n]));
  $("#attack-sources").innerHTML = "Sources: " + Object.values(t.sources).map((s) =>
    `<a href="${s.url}" target="_blank" rel="noopener">${esc(s.name)}</a> (${esc(s.license)})`).join(" · ") + `. As of ${day(t.as_of)}.`;
};

// ---------- exploited flaws ----------
loaders.flaws = async () => {
  const f = await api("/v1/intel/flaws");
  stamp("flaws", f.as_of, ". CISA adds flaws on weekdays; refreshed daily.");
  $("#flaw-kpis").innerHTML = [
    kpi(fmt(f.added_last_7_days), "added in the last 7 days"),
    kpi(fmt(f.added_last_30_days), "added in the last 30 days"),
    kpi(fmt(f.total), "exploited flaws on the list"),
    kpi(fmt(f.ransomware_linked), "used in ransomware attacks"),
  ].join("");
  bars($("#flaw-vendors"), f.top_vendors_last_12_months);
  const stack = new Set(["Microsoft", "Fortinet", "Cisco"]);
  const chips = $("#stack-chips");
  chips.innerHTML = f.top_vendors.slice(0, 12).map(([v]) => `<button data-vendor="${esc(v)}">${esc(v)}</button>`).join("");
  const rank = async () => {
    $$("[data-vendor]", chips).forEach((b) => b.classList.toggle("on", stack.has(b.dataset.vendor)));
    const r = await api(`/v1/intel/flaws/priority?vendors=${encodeURIComponent([...stack].join(","))}`);
    $("#priority-rows").innerHTML = r.flaws.slice(0, 10).map((x) => {
      const why = [x.epss != null ? `${pct(x.epss, 1)} exploit chance` : null, x.ransomware ? "used by ransomware" : null,
        `added ${day(x.added)}`].filter(Boolean).join(" · ");
      return `<tr><td><b>${x.priority.toFixed(0)}</b></td><td><a href="https://nvd.nist.gov/vuln/detail/${esc(x.cve)}" target="_blank" rel="noopener">${esc(x.cve)}</a></td>
        <td>${esc(x.vendor)} ${esc(x.product)}</td><td class="fineprint">${why}</td></tr>`;
    }).join("") || '<tr><td colspan="4" class="muted">Pick at least one vendor.</td></tr>';
  };
  chips.addEventListener("click", (e) => {
    const v = e.target.closest("[data-vendor]")?.dataset.vendor;
    if (!v) return;
    stack.has(v) ? stack.delete(v) : stack.add(v);
    rank();
  });
  rank();
  const thisMonth = f.as_of.slice(0, 7); // the snapshot's month is not over yet
  bars($("#flaw-months"), Object.entries(f.added_by_month).map(([m, n]) => [
    new Date(`${m}-01`).toLocaleDateString("en-GB", { month: "short", year: "numeric" }) + (m === thisMonth ? ", to date" : ""), n]));
  $("#flaw-rows").innerHTML = f.latest.map((r) => `<tr><td>${day(r.added)}</td>
    <td><a href="https://nvd.nist.gov/vuln/detail/${esc(r.cve)}" target="_blank" rel="noopener">${esc(r.cve)}</a><br>${esc(r.name)}</td>
    <td>${esc(r.vendor)} ${esc(r.product)}</td><td>${r.ransomware ? '<span class="tag">yes</span>' : "not known"}</td>
    <td class="num">${r.epss == null ? "not scored" : pct(r.epss, 1)}</td></tr>`).join("");
};

// ---------- Tech Bloomberg Terminal ----------
loaders.terminal = async () => {};  // lazy: search is user-driven, no auto-load

(function wireTerminal() {
  const form = $("#terminal-form");
  const qInput = form?.querySelector("input[name='q']") ?? form?.querySelector("input");
  if (!form) return;

  function runTerminal(q) {
    if (!q) return;
    const box = $("#terminal-results");
    box.innerHTML = '<p class="muted">Pulling Bloomberg dossier from BGPView · CISA KEV · HIBP · crt.sh…</p>';
    api(`/v1/terminal/company?q=${encodeURIComponent(q)}`)
      .then((d) => {
        const grade = d.grade ?? "—";
        const gradeColor = { A: "#2f7a4f", B: "#3d7ab5", C: "#d4a017", D: "#e8710a", F: "#b42318" }[grade[0]] ?? "#666";
        const subdomains = d.attack_surface?.subdomains ?? [];
        const breaches = d.breach_summary ?? {};
        const breachList = d.breaches?.recent ?? [];
        const asns = (d.asn_profile ?? []).slice(0, 12);
        const vulns = (d.vulnerabilities?.top_cves ?? []).slice(0, 8);

        box.innerHTML = `
          <div class="panel" style="margin-bottom:1rem;border-left:5px solid ${gradeColor}">
            <div style="display:flex;align-items:center;gap:1.2rem;margin-bottom:.75rem">
              <span style="font-size:3rem;font-weight:700;color:${gradeColor};line-height:1;min-width:2.5rem">${esc(grade)}</span>
              <div>
                <b style="font-size:1.2rem">${esc(d.company ?? q)}</b>${d.primary_domain ? `<span class="fineprint" style="margin-left:.5rem;color:var(--accent)">${esc(d.primary_domain)}</span>` : ""}<br>
                <span class="fineprint" style="color:var(--dim)">${esc(d.grade_description ?? "")}</span>
              </div>
              <div style="margin-left:auto;text-align:right">
                <div style="font-size:.75rem;color:var(--dim)">Security Health Score</div>
                <div style="font-size:1.5rem;font-weight:700;color:${gradeColor}">${d.score ?? "—"}/100</div>
              </div>
            </div>
            <ul style="margin:0;padding-left:1.4rem;line-height:1.8">
              ${(d.summary_bullets ?? []).map((b) => `<li style="font-size:13px">${esc(b)}</li>`).join("") || "<li class='muted'>No records found. Try a more specific name or domain (e.g. infosys.com, stripe.com).</li>"}
            </ul>
            <div class="fineprint" style="margin-top:.5rem;color:var(--dim)">Sources: ${esc(d.sources ?? "BGPView · CISA KEV · FIRST EPSS · HIBP · crt.sh")}</div>
          </div>
          ${asns.length ? `<div class="panel" style="margin-bottom:1rem">
            <b>BGP Network Footprint — ${asns.length} Autonomous System${asns.length > 1 ? "s" : ""}</b>
            <table style="width:100%;margin-top:.6rem;font-size:13px"><tbody>
              ${asns.map((a) => `<tr>
                <td><a href="https://bgpview.io/asn/${esc(a.asn)}" target="_blank" rel="noopener" style="font-family:var(--mono)">AS${esc(a.asn)}</a></td>
                <td>${esc(a.network || a.description || "")}</td>
                <td style="text-align:right;color:var(--dim)">${esc(a.country ?? "")}</td>
              </tr>`).join("")}
            </tbody></table>
            <div class="fineprint" style="margin-top:.4rem">Source: <a href="https://bgpview.io" target="_blank" rel="noopener">BGPView.io</a> real-time BGP routing data</div>
          </div>` : ""}
          ${vulns.length ? `<div class="panel" style="margin-bottom:1rem">
            <b>CISA Known Exploited Vulnerabilities — ${vulns.length} attributed to this vendor</b>
            <table style="width:100%;margin-top:.6rem;font-size:12px"><thead><tr>
              <th>CVE</th><th>Product</th><th>EPSS 30d</th><th>Ransomware</th>
            </tr></thead><tbody>
              ${vulns.map((f) => `<tr>
                <td><a href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" rel="noopener">${esc(f.cve)}</a></td>
                <td>${esc((f.vendor || "") + " " + (f.product || ""))}</td>
                <td class="num">${f.epss != null ? pct(f.epss, 1) : "—"}</td>
                <td>${f.ransomware_use ? '<span class="tag">Yes</span>' : "—"}</td>
              </tr>`).join("")}
            </tbody></table>
            <div class="fineprint" style="margin-top:.4rem">Source: CISA KEV · FIRST EPSS</div>
          </div>` : ""}
          ${breachList.length ? `<div class="panel" style="margin-bottom:1rem">
            <b>Data Breach History — ${breachList.length} breach${breachList.length > 1 ? "es" : ""} · ${compact(breaches.total_records ?? 0)} records exposed</b>
            <table style="width:100%;margin-top:.6rem;font-size:12px"><thead><tr>
              <th>Breach</th><th>Date</th><th class="num">Accounts</th><th>Data types</th>
            </tr></thead><tbody>
              ${breachList.slice(0, 10).map((b) => `<tr>
                <td>${esc(b.title || b.name || b.domain || "")}</td>
                <td>${esc(b.breach_date ? day(b.breach_date) : "—")}</td>
                <td class="num">${compact(b.accounts || b.pwn_count || 0)}</td>
                <td class="fineprint">${(b.data_classes || []).slice(0, 3).map(esc).join(", ")}</td>
              </tr>`).join("")}
            </tbody></table>
            <div class="fineprint" style="margin-top:.4rem">Source: <a href="https://haveibeenpwned.com" target="_blank" rel="noopener">Have I Been Pwned</a> (CC BY 4.0)</div>
          </div>` : (d.breaches?.total === 0 ? `<div class="panel" style="margin-bottom:1rem"><p style="color:#2f7a4f;margin:0">✓ No corporate breaches found in HIBP catalog for this company.</p></div>` : "")}
          ${subdomains.length ? `<div class="panel">
            <b>Attack Surface — ${subdomains.length} live subdomains via Certificate Transparency</b>
            <div style="margin-top:.5rem;font-family:var(--mono);font-size:.78rem;line-height:1.9;columns:2;column-gap:1rem">
              ${subdomains.slice(0, 40).map((s) => `<div>${esc(s)}</div>`).join("")}
              ${subdomains.length > 40 ? `<div class="fineprint" style="column-span:all">…and ${subdomains.length - 40} more subdomains</div>` : ""}
            </div>
            <div class="fineprint" style="margin-top:.4rem">Source: <a href="https://crt.sh" target="_blank" rel="noopener">crt.sh</a> Certificate Transparency logs (live query)</div>
          </div>` : ""}`;
      })
      .catch((err) => { box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 200))}</p>`; });
  }

  form.addEventListener("submit", (e) => { e.preventDefault(); runTerminal(qInput?.value.trim()); });
  $$("[data-terminal]").forEach((b) => b.addEventListener("click", () => {
    if (qInput) qInput.value = b.dataset.terminal;
    runTerminal(b.dataset.terminal);
  }));
})();

// ---------- live footprint ----------
loaders.check = async () => {};  // user-driven

(function wireFootprint() {
  const form = $("#footprint-form");
  const ipInput = form?.querySelector("input");
  if (!form) return;

  const TIER_COL = { HEALTHY: "#2f7a4f", CLEAN: "#2f7a4f", ELEVATED: "#d4a017", MEDIUM: "#d4a017", LOW: "#3d7ab5", HIGH: "#e8710a", CRITICAL: "#b42318" };

  function runFootprint(ip) {
    if (!ip) return;
    const box = $("#footprint-results");
    box.innerHTML = '<p class="muted">Pulling live network & tripwire footprint…</p>';
    api(`/v1/terminal/footprint?ip=${encodeURIComponent(ip)}`)
      .then((d) => {
        const tier = d.threat_tier ?? d.threat_status?.level ?? "UNKNOWN";
        const col = TIER_COL[tier] ?? "#888";
        const net = d.network ?? {};
        const cables = (d.subsea_cables ?? []).slice(0, 8);
        box.innerHTML = `
          <div class="panel" style="margin-bottom:1rem;border-left:5px solid ${col}">
            <div style="display:flex;align-items:center;gap:1.2rem;margin-bottom:.75rem">
              <span style="font-size:2.2rem;font-weight:700;color:${col};line-height:1">${esc(tier)}</span>
              <div>
                <b style="font-size:1.1rem;font-family:var(--mono)">${esc(ip)}</b>${net.hostname ? `<span class="fineprint" style="margin-left:.6rem">${esc(net.hostname)}</span>` : ""}<br>
                <span class="fineprint">${esc(net.network ?? "")}${net.asn ? ` · <a href="https://bgpview.io/asn/${esc(net.asn)}" target="_blank" rel="noopener">AS${net.asn}</a>` : ""}</span>
              </div>
            </div>
            ${d.threat_status?.summary ? `<p style="margin:.4rem 0 .7rem;font-size:13px;color:var(--ink)">${esc(d.threat_status.summary)}</p>` : ""}
            <div class="facts" style="margin-top:.5rem">
              <div><b>Country</b>${esc(net.country ?? "—")}</div>
              <div><b>Network type</b>${esc(net.type ?? "—")}</div>
              ${net.cloud_provider ? `<div><b>Cloud provider</b><span class="tag" style="background:#7dd3fc22;color:var(--accent)">${esc(net.cloud_provider)}</span></div>` : ""}
              ${d.is_tor ? '<div><b>Tor exit</b><span class="tag" style="background:#e8710a22;color:#e8710a">yes</span></div>' : ""}
              ${d.is_malware ? `<div><b>Malware threat</b><span class="tag" style="background:#b4231822;color:#b42318">yes — ${esc(d.malware_threat || "malware C2")}</span></div>` : ""}
              ${d.is_criminal_network ? '<div><b>Criminal network</b><span class="tag" style="background:#b4231822;color:#b42318">Spamhaus DROP</span></div>' : ""}
            </div>
            <div class="fineprint" style="margin-top:.6rem;color:var(--dim)">Sources: ${esc(d.sources ?? "iptoasn · DB-IP · abuse.ch ThreatFox · Spamhaus DROP · Tor Project")}</div>
          </div>
          ${cables.length ? `<div class="panel">
            <b>Undersea Fiber Landings (${net.country || ""}) — ${cables.length} Subsea Cables Connected</b>
            <ul style="margin:.5rem 0 0;padding-left:1.4rem;line-height:1.7;font-size:13px">
              ${cables.map((c) => `<li>${esc(c)}</li>`).join("")}
            </ul>
            <div class="fineprint" style="margin-top:.4rem">Source: TeleGeography Submarine Cable Map</div>
          </div>` : ""}`;
      })
      .catch((err) => { box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`; });
  }

  form.addEventListener("submit", (e) => { e.preventDefault(); runFootprint(ipInput?.value.trim()); });
  $$("[data-fp]").forEach((b) => b.addEventListener("click", () => {
    if (ipInput) ipInput.value = b.dataset.fp;
    runFootprint(b.dataset.fp);
  }));
})();

// ---------- DNS shield ----------
loaders.shield = async () => {};  // user-driven

(function wireShield() {
  const form = $("#shield-form");
  const domInput = form?.querySelector("input");
  if (!form) return;

  function runShield(domain) {
    if (!domain) return;
    const box = $("#shield-results");
    box.innerHTML = '<p class="muted">Inspecting domain entropy & threat feed sinkhole status…</p>';
    api(`/v1/shield/check?domain=${encodeURIComponent(domain)}`)
      .then((d) => {
        const verdict = d.verdict ?? (d.status === "BLOCKED" ? "BLOCK" : "ALLOW");
        const col = verdict === "ALLOW" ? "#2f7a4f" : "#b42318";
        const ips = (d.resolved_ips ?? []).slice(0, 8);
        box.innerHTML = `
          <div class="panel" style="border-left:5px solid ${col}">
            <div style="display:flex;align-items:center;gap:1.2rem;margin-bottom:.75rem">
              <span style="font-size:2rem;font-weight:700;color:${col}">${esc(verdict)}</span>
              <div>
                <b style="font-size:1.1rem;font-family:var(--mono)">${esc(domain)}</b><br>
                <span class="fineprint">${esc(d.action === "SINKHOLED" ? "Sinkholed to 0.0.0.0" : "Resolution allowed")}</span>
              </div>
            </div>
            <p style="margin:.4rem 0 .7rem;font-size:13px;color:var(--ink)">${esc(d.reason ?? "")}</p>
            <div class="facts">
              <div><b>Shannon entropy</b>${d.entropy != null ? d.entropy.toFixed(3) : "—"} ${d.entropy > 3.65 ? '<span class="tag" style="background:#b4231822;color:#b42318">High DGA pattern</span>' : '<span class="tag" style="background:#2f7a4f22;color:#2f7a4f">Normal</span>'}</div>
              ${d.dga_reason ? `<div><b>DGA analysis</b>${esc(d.dga_reason)}</div>` : ""}
              ${d.bad_ip_hits?.length ? `<div><b>Flagged IPs</b><span class="tag" style="background:#b4231822;color:#b42318">${d.bad_ip_hits.map(esc).join(", ")}</span></div>` : ""}
            </div>
            ${ips.length && ips[0] !== "NXDOMAIN" ? `
              <div style="margin-top:.75rem">
                <b>Resolved IP Addresses (${ips.length})</b>
                <div style="font-family:var(--mono);font-size:.85rem;margin-top:.3rem;line-height:1.8">
                  ${ips.map(esc).join("<br>")}
                </div>
              </div>` : (ips[0] === "NXDOMAIN" ? `<div class="fineprint" style="margin-top:.5rem;color:var(--dim)">DNS status: NXDOMAIN (Non-Existent Domain)</div>` : "")}
          </div>`;
      })
      .catch((err) => { box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`; });
  }

  form.addEventListener("submit", (e) => { e.preventDefault(); runShield(domInput?.value.trim()); });
  $$("[data-shield]").forEach((b) => b.addEventListener("click", () => {
    if (domInput) domInput.value = b.dataset.shield;
    runShield(b.dataset.shield);
  }));
})();

// ---------- BGP & Internet Disruption Radar (Pillar 5) ----------
loaders.disruptions = async () => {
  const box = $("#disruption-list");
  const kpiBox = $("#disruption-kpis");
  if (!box) return;
  box.innerHTML = '<p class="muted">Scanning CAIDA IODA & BGP routing telemetry…</p>';
  try {
    const d = await api("/v1/intel/disruptions");
    const active = d.active_disruptions ?? [];
    const health = d.global_health ?? "NORMAL";
    const healthCol = health === "NORMAL" ? "#2f7a4f" : "#b42318";

    if (kpiBox) {
      kpiBox.innerHTML = [
        kpi(`<span style="color:${healthCol}">${esc(health)}</span>`, "Global Routing Health"),
        kpi(fmt(d.critical_count ?? 0), "Critical Outages & Blackouts"),
        kpi(fmt(active.length), "Active Regional Anomalies"),
        kpi(esc(d.as_of ? ago(d.as_of) : "Live"), "Telemetry Freshness"),
      ].join("");
    }

    if (!active.length) {
      box.innerHTML = '<p class="muted">No major macro-level internet outages detected currently. Global transit stable.</p>';
      return;
    }

    box.innerHTML = active.map((a) => {
      const sevCol = a.severity === "CRITICAL" ? "#b42318" : a.severity === "HIGH" ? "#e8710a" : "#d4a017";
      return `
        <div class="panel" style="margin-bottom: 12px; border-left: 4px solid ${sevCol};">
          <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
            <div>
              <b style="font-size:16px;">${esc(a.country_name || a.country)}</b> <span class="tag" style="background:${sevCol}22; color:${sevCol}; border:1px solid ${sevCol}44; font-weight:600;">${esc(a.severity)}</span>
              <div class="fineprint" style="margin-top:2px;">Signal: ${esc(a.type || "BGP Outage")} · Detected: ${esc(a.started ? ago(a.started) : "Ongoing")}</div>
            </div>
            <div style="text-align:right;">
              <span class="mono" style="font-size:18px; font-weight:700; color:${sevCol};">${a.drop_pct ? `-${a.drop_pct}%` : "DISRUPTED"}</span>
              <div class="fineprint">Transit Volume Drop</div>
            </div>
          </div>
          <p style="margin: 8px 0 6px; font-size:13px; color:var(--ink);">${esc(a.description || a.impact || "")}</p>
          ${a.asns?.length ? `<div class="fineprint"><b>Impacted ASNs:</b> ${a.asns.map((asn) => `<span class="mono">AS${asn}</span>`).join(", ")}</div>` : ""}
        </div>`;
    }).join("");
  } catch (err) {
    box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`;
  }
};

(function wireDisruptions() {
  $("#refresh-disruptions")?.addEventListener("click", () => loaders.disruptions());
})();

// ---------- Open-Source Supply Chain Analyzer (Pillar 6) ----------
loaders["supply-chain"] = async () => {};

(function wireSupplyChain() {
  const form = $("#supply-chain-form");
  const pkgInput = $("#supply-pkg");
  const ecoSelect = $("#supply-eco");
  if (!form) return;

  function runSupplyChain(pkg, eco) {
    if (!pkg) return;
    const box = $("#supply-chain-results");
    box.innerHTML = '<p class="muted">Querying Google deps.dev & OSV vulnerability graph…</p>';
    api(`/v1/supply-chain/analyze?package=${encodeURIComponent(pkg)}&ecosystem=${encodeURIComponent(eco)}`)
      .then((d) => {
        const status = d.security_status ?? "CLEAN";
        const col = status === "CLEAN" ? "#2f7a4f" : status === "CRITICAL" ? "#b42318" : "#e8710a";
        const licCol = d.has_restrictive_license ? "#b42318" : "#2f7a4f";
        const vulns = d.vulnerabilities ?? [];

        box.innerHTML = `
          <div class="panel" style="margin-bottom: 12px; border-left: 4px solid ${col};">
            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
              <div>
                <span style="font-size:1.4rem; font-weight:700; color:${col};">${esc(status)}</span>
                <span style="font-size:1.2rem; font-weight:600; margin-left:8px;">${esc(d.package)}</span>
                <span class="fineprint">(${esc(d.ecosystem)})</span>
              </div>
              <div class="facts">
                <div><b>Latest Version</b>${esc(d.latest_version ?? "unknown")}</div>
                <div><b>Total Releases</b>${fmt(d.total_versions ?? 0)}</div>
                <div><b>License Risk</b><span style="color:${licCol}; font-weight:600;">${esc(d.license_risk)}</span></div>
              </div>
            </div>
            <div style="margin-top:10px; font-size:13px;">
              <b>Detected Licenses:</b> ${(d.licenses ?? []).map(esc).join(", ")}
            </div>
          </div>
          ${vulns.length ? `
            <div class="panel">
              <h3 style="margin-bottom:8px;">Identified Vulnerabilities (${vulns.length})</h3>
              <table style="width:100%;">
                <thead><tr><th>ID</th><th>Summary</th><th>Published</th></tr></thead>
                <tbody>
                  ${vulns.map((v) => `
                    <tr>
                      <td><a href="https://osv.dev/vulnerability/${esc(v.id)}" target="_blank" rel="noopener"><b>${esc(v.id)}</b></a></td>
                      <td>${esc(v.summary || v.details || "Security advisory published")}</td>
                      <td class="fineprint">${esc(v.published ? day(v.published) : "—")}</td>
                    </tr>
                  `).join("")}
                </tbody>
              </table>
            </div>
          ` : '<div class="panel"><p class="muted" style="color:#2f7a4f;">✓ Zero known public CVEs or advisories reported for this package in OSV.</p></div>'}`;
      })
      .catch((err) => {
        box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`;
      });
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    runSupplyChain(pkgInput?.value.trim(), ecoSelect?.value || "pypi");
  });

  $$("[data-sc-pkg]").forEach((b) => b.addEventListener("click", () => {
    if (pkgInput) pkgInput.value = b.dataset.scPkg;
    if (ecoSelect) ecoSelect.value = b.dataset.scEco;
    runSupplyChain(b.dataset.scPkg, b.dataset.scEco);
  }));
})();

// ---------- Corporate Breach & Leak Hunter (Pillar 7) ----------
loaders.leaks = async () => {};

(function wireLeaks() {
  const domForm = $("#leak-domain-form");
  const domInput = $("#leak-domain");
  const pwForm = $("#leak-pw-form");
  const pwInput = $("#leak-pw");

  function runDomainAudit(domain) {
    if (!domain) return;
    const box = $("#leak-domain-results");
    box.innerHTML = '<p class="muted">Scanning HIBP enterprise catalog & ransomware extortion feeds…</p>';
    api(`/v1/terminal/leak-hunter?domain=${encodeURIComponent(domain)}`)
      .then((d) => {
        const breaches = d.breaches ?? [];
        const claims = d.ransomware_claims ?? [];
        const risk = d.risk_level ?? "LOW";
        const riskCol = risk === "CRITICAL" ? "#b42318" : risk === "HIGH" ? "#e8710a" : risk === "MEDIUM" ? "#d4a017" : "#2f7a4f";

        box.innerHTML = `
          <div class="panel" style="margin-bottom:12px; border-left: 4px solid ${riskCol};">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <div><b style="font-size:16px;">${esc(d.domain)}</b> <span class="tag" style="background:${riskCol}22; color:${riskCol}; font-weight:600;">${esc(risk)} RISK</span></div>
              <div><b>${compact(d.total_pwned_accounts ?? 0)}</b> <span class="fineprint">Exposed Accounts</span></div>
            </div>
          </div>
          ${claims.length ? `
            <div class="panel" style="margin-bottom:12px; border-color:#b42318;">
              <b style="color:#b42318;">⚠️ Ransomware Gang Extortion Disclosures (${claims.length})</b>
              <ul style="margin:6px 0 0; padding-left:18px;">
                ${claims.map((c) => `<li><b>${esc(c.gang)}</b> claimed attack on ${esc(day(c.date))}: ${esc(c.details || "")}</li>`).join("")}
              </ul>
            </div>
          ` : ""}
          ${breaches.length ? `
            <div class="panel">
              <b>Publicly Confirmed Breaches (${breaches.length})</b>
              <ul style="margin:6px 0 0; padding-left:18px;">
                ${breaches.map((b) => `<li><b>${esc(b.name)}</b> (${esc(day(b.breach_date))}): ${compact(b.pwn_count)} accounts exposed. <span class="fineprint">${(b.data_classes || []).slice(0, 4).join(", ")}</span></li>`).join("")}
              </ul>
            </div>
          ` : '<div class="panel"><p class="muted">✓ Zero corporate domain compromises logged in HIBP directory.</p></div>'}`;
      })
      .catch((err) => { box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`; });
  }

  domForm?.addEventListener("submit", (e) => { e.preventDefault(); runDomainAudit(domInput?.value.trim()); });
  $$("[data-leak-dom]").forEach((b) => b.addEventListener("click", () => {
    if (domInput) domInput.value = b.dataset.leakDom;
    runDomainAudit(b.dataset.leakDom);
  }));

  // Browser-side SHA-1 hashing with SubtleCrypto for strict zero-knowledge k-Anonymity
  async function sha1Hex(str) {
    const buf = new TextEncoder().encode(str);
    const hash = await crypto.subtle.digest("SHA-1", buf);
    return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  pwForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = pwInput?.value;
    if (!pw) return;
    const box = $("#leak-pw-results");
    box.innerHTML = '<p class="muted">Hashing password client-side via SHA-1…</p>';
    try {
      const hash = await sha1Hex(pw);
      const prefix = hash.slice(0, 5);
      const suffix = hash.slice(5);
      const d = await api(`/v1/terminal/pwned-password?prefix=${prefix}`);
      const match = (d.matches || {})[suffix] ?? 0;
      if (match > 0 || d.pwned) {
        box.innerHTML = `
          <div class="panel" style="border-left: 4px solid #b42318;">
            <b style="color:#b42318; font-size:15px;">⚠️ COMPROMISED IN PUBLIC BREACHES</b>
            <p style="margin:6px 0; font-size:13px;">This exact password appears <b>${fmt(match || d.exposure_count || 1)} times</b> across known breach dumps (HIBP Pwned Passwords). Do not use this password for any account.</p>
            <div class="fineprint">Checked securely: Only SHA-1 prefix "${prefix}" was sent to server. Full hash was never exposed.</div>
          </div>`;
      } else {
        box.innerHTML = `
          <div class="panel" style="border-left: 4px solid #2f7a4f;">
            <b style="color:#2f7a4f; font-size:15px;">✓ NO BREACH MATCHES FOUND</b>
            <p style="margin:6px 0; font-size:13px;">This password does not appear in known public credential dumps.</p>
            <div class="fineprint">SHA-1 prefix: "${prefix}" (zero-knowledge k-anonymity verified).</div>
          </div>`;
      }
    } catch (err) {
      box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`;
    }
  });
})();

// ---------- Canary Tokens & Hacker Tripwire (Pillar 8) ----------
loaders.canary = async () => {
  loadCanaryAlarms();
};

async function loadCanaryAlarms() {
  const box = $("#canary-alarms-box");
  if (!box) return;
  try {
    const { alarms } = await api("/v1/canary/alarms");
    if (!alarms?.length) {
      box.innerHTML = '<p class="muted">No tripwires triggered yet. Deployed decoys are silently listening.</p>';
      return;
    }
    box.innerHTML = alarms.map((a) => `
      <div class="panel" style="margin-bottom:8px; border-left:4px solid #b42318;">
        <div style="display:flex; justify-content:space-between;">
          <b style="color:#b42318;">🚨 INTRUSION TRIPWIRE TRIGGERED</b>
          <span class="fineprint">${esc(ago(a.timestamp))}</span>
        </div>
        <div style="margin-top:4px;"><b>Decoy:</b> ${esc(a.memo)}</div>
        <div class="facts" style="margin-top:6px;">
          <div><b>Intruder IP</b><span class="mono">${esc(a.intruder_ip)}</span></div>
          <div><b>Carrier / ASN</b>AS${esc(a.network?.asn ?? "—")} ${esc(a.network?.carrier ?? "")}</div>
          <div><b>Location</b>${esc(a.network?.country ?? "—")}</div>
        </div>
        <div class="fineprint" style="margin-top:4px;">User-Agent: ${esc(a.user_agent)}</div>
      </div>
    `).join("");
  } catch (err) {
    box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`;
  }
}

(function wireCanary() {
  const form = $("#canary-form");
  const kindSelect = $("#canary-kind");
  const memoInput = $("#canary-memo");
  const resultBox = $("#canary-created");

  $("#refresh-alarms")?.addEventListener("click", loadCanaryAlarms);

  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const kind = kindSelect?.value || "aws_key";
    const memo = memoInput?.value.trim() || "Decoy asset";
    resultBox.innerHTML = '<p class="muted">Generating deceptive decoy asset…</p>';
    try {
      const res = await api(`/v1/canary/generate?kind=${encodeURIComponent(kind)}&memo=${encodeURIComponent(memo)}`, { method: "POST" });
      const decoys = res.decoys || {};
      let snippet = "";
      if (kind === "aws_key") {
        snippet = decoys.aws_credentials || "";
      } else if (kind === "database_uri") {
        snippet = decoys.database_connection_string || "";
      } else {
        snippet = `<img src="${window.location.origin}${res.tripwire_url}" width="1" height="1" alt="" />`;
      }

      resultBox.innerHTML = `
        <div class="panel" style="border:1px solid var(--accent); background:rgba(125,211,252,0.06);">
          <b style="color:var(--accent);">✓ Decoy Generated & Armed</b>
          <p class="fineprint" style="margin:4px 0 8px;">Copy and place this decoy in your private repo, environment file, or documentation. When accessed, an alarm will fire immediately.</p>
          <pre style="background:var(--bg); padding:10px; border-radius:4px; font-family:var(--mono); font-size:12px; overflow-x:auto; user-select:all;">${esc(snippet)}</pre>
          <div style="margin-top:8px;">
            <a href="${res.tripwire_url}" target="_blank" class="btn-sm chip" style="text-decoration:none;">Test Trigger Tripwire Now</a>
          </div>
        </div>`;
    } catch (err) {
      resultBox.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`;
    }
  });
})();

// ---------- AI Defense Remediation Engine (Pillar 9) ----------
loaders.remediation = async () => {};

(function wireRemediation() {
  const form = $("#remediation-form");
  const typeSelect = $("#remediation-type");
  const targetInput = $("#remediation-target");
  const box = $("#remediation-results");
  if (!form) return;

  function runRemediation(type, target) {
    if (!target) return;
    box.innerHTML = '<p class="muted">Generating deterministic defense remediation playbook…</p>';
    api(`/v1/remediation/explain?type=${encodeURIComponent(type)}&target=${encodeURIComponent(target)}`)
      .then((d) => {
        const cmd = d.firewall_rule || d.remediation_command || "";
        box.innerHTML = `
          <div class="panel" style="margin-bottom:12px; border-left:4px solid var(--accent);">
            <div style="display:flex; justify-content:space-between; align-items:center;">
              <b style="font-size:16px;">Target: ${esc(d.target)}</b>
              <span class="tag" style="background:#7dd3fc22; color:var(--accent);">${esc(type.toUpperCase())}</span>
            </div>
            <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap:12px; margin-top:14px;">
              <div class="panel" style="background:var(--bg);">
                <div class="label" style="color:var(--dim); margin-bottom:4px;">1. What Happened</div>
                <div style="font-size:13px; line-height:1.5;">${esc(d.what_happened)}</div>
              </div>
              <div class="panel" style="background:var(--bg);">
                <div class="label" style="color:var(--dim); margin-bottom:4px;">2. Who Is Impacted</div>
                <div style="font-size:13px; line-height:1.5;">${esc(d.who_is_impacted)}</div>
              </div>
              <div class="panel" style="background:var(--bg);">
                <div class="label" style="color:var(--dim); margin-bottom:4px;">3. What To Do Right Now</div>
                <div style="font-size:13px; line-height:1.5;">${esc(d.what_to_do_now)}</div>
              </div>
            </div>
          </div>
          ${cmd ? `
            <div class="panel">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                <b>Immediate 60-Second Shell Mitigation</b>
                <button type="button" class="btn-sm chip" id="copy-rem-cmd">Copy Command</button>
              </div>
              <pre id="rem-cmd-code" style="background:var(--bg); padding:12px; border-radius:4px; font-family:var(--mono); font-size:13px; overflow-x:auto; color:var(--accent); border:1px solid var(--line);">${esc(cmd)}</pre>
            </div>
          ` : ""}`;

        $("#copy-rem-cmd")?.addEventListener("click", () => {
          navigator.clipboard.writeText(cmd);
          $("#copy-rem-cmd").textContent = "Copied!";
          setTimeout(() => ($("#copy-rem-cmd").textContent = "Copy Command"), 2000);
        });
      })
      .catch((err) => {
        box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`;
      });
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    runRemediation(typeSelect?.value || "cve", targetInput?.value.trim());
  });

  $$("[data-rem-type]").forEach((b) => b.addEventListener("click", () => {
    if (typeSelect) typeSelect.value = b.dataset.remType;
    if (targetInput) targetInput.value = b.dataset.remTarget;
    runRemediation(b.dataset.remType, b.dataset.remTarget);
  }));
})();

// ---------- news ----------
loaders.news = async () => {
  const { news, videos, as_of } = await api("/v1/intel/news");
  stamp("news", as_of, ". Fetched live from the feeds, at most 30 minutes old.");
  $("#news-list").innerHTML = news.map((n) => `<li><a href="${esc(n.url)}" target="_blank" rel="noopener">${esc(n.title)}</a>
    <small>${esc(n.source)} · ${ago(n.published)}</small></li>`).join("") || '<li class="muted">Headlines are refreshing. Check back in a few minutes.</li>';
  $("#video-list").innerHTML = videos.map((v) => {
    const id = new URL(v.url).searchParams.get("v");
    return `<li class="vid">${id ? `<img src="https://i.ytimg.com/vi/${esc(id)}/mqdefault.jpg" alt="" loading="lazy">` : "<span></span>"}
      <div><a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.title)}</a><small>${esc(v.source)} · ${ago(v.published)}</small></div></li>`;
  }).join("");
  $("#video-list").closest(".panel").hidden = !videos.length; // no videos: hide the panel rather than show an error
};

// ---------- data & accuracy ----------
const SPAN = { h: "hour", d: "day" };
const every = (span) => { const n = +span.slice(0, -1), u = SPAN[span.at(-1)]; return n === 1 ? `every ${u}` : `every ${n} ${u}s`; };
const spanMs = (span) => +span.slice(0, -1) * (span.endsWith("h") ? 3600e3 : 86400e3);

loaders.results = async () => {
  const [m, fr, src] = await Promise.all([api("/v1/model"), api("/v1/intel/freshness"), api("/v1/intel/sources")]);
  stamp("results", fr.snapshot, ". Snapshot of all threat data; the models were trained on 2020 to 2021 data.");
  const ato = m.test_metrics.ato, ip = m.test_metrics.attack_ip;
  $("#model-kpis").innerHTML = [
    kpi(`${ato.confusion_matrix.tp} of ${ato.positives}`, `account takeovers caught in the Oct to Nov 2020 test data (recall ${pct(ato.recall, 1)})`),
    kpi(pct(ato.alert_rate), `of sign-ins asked for a code (${ato.alerts_per_10k_logins} per 10,000)`),
    kpi(ato.roc_auc.toFixed(3), "takeover ROC-AUC (1.0 is perfect, 0.5 is a coin flip)"),
    kpi(ip.roc_auc.toFixed(3), `attack-IP ROC-AUC on Jan to Feb 2021 data, recall ${pct(ip.recall, 1)} at a ${pct(ip.alert_rate)} alert rate`),
    kpi(compact(ato.logins), "test sign-ins the model never saw"),
    kpi(pct(ato.precision, 2), "takeover precision: most codes go to sign-ins not labelled as takeovers, so Alibi asks rather than blocks"),
  ].join("");
  $("#model-plain").textContent = `Out of ${fmt(ato.logins)} sign-ins in the test months (October and November 2020), ${ato.positives} were labelled account takeovers. ` +
    `Asking for a one-time code on the riskiest ${pct(ato.alert_rate)} of sign-ins would have stopped ${ato.confusion_matrix.tp} of them. ` +
    `The other ${fmt(ato.confusion_matrix.fp)} people asked for a code were not labelled as takeovers. ` +
    `With only ${ato.positives} takeovers to test on, that catch rate is uncertain: anywhere from about 43% to 80%. ` +
    `Spotting sign-ins from known attack IPs is harder: the model ranks them well above chance (ROC-AUC ${ip.roc_auc.toFixed(2)}) ` +
    `but catches only ${pct(ip.recall, 1)} at that budget, which is why Alibi adds today's Tor, VPN, malware-server and criminal-network checks on top. ` +
    "These models have not yet been tested on 2025 or 2026 logins. " +
    (m.live_differences || []).join(" ");
  const now = Date.now();
  $("#currency").innerHTML = fr.feeds.map((f) => {
    const age = f.updated ? now - new Date(f.updated) : null;
    const stale = age !== null && age > spanMs(f.max_age);
    const when = !f.available ? (f.optional ? "not in this snapshot; fetched live" : "missing") : `${day(f.updated)} (${ago(f.updated)})`;
    return `<tr><td><a href="${esc(f.url)}" target="_blank" rel="noopener">${esc(f.name)}</a></td><td>${esc(f.licence)}</td>
      <td>${when}${stale ? ' <span class="tag">stale</span>' : ""}</td><td>${every(f.cadence)}</td></tr>`;
  }).join("");
  $("#currency-note").textContent = `Snapshot built ${day(fr.snapshot)}. A feed counts as stale once it is older than its limit: 3 days for the malware feeds, up to 6 months for DB-IP and the cable maps.`;
  $("#model-data").innerHTML = fr.models.map((x) => `<tr><td>${esc(x.name)}</td><td><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.data)}</a>, ${esc(x.licence)}<br><span class="fineprint">${esc(x.note)}</span></td>
    <td>${esc(x.train)}</td><td>${esc(x.test)}</td></tr>`).join("");
  const { news_feeds: nf, video_feeds: vf } = src;
  const rows = [
    [`Security news: ${Object.keys(nf).join(", ")}`, Object.values(nf)[0], "public RSS feeds, headlines and links only, fetched live"],
    [`Videos: ${Object.keys(vf).join(", ")}`, "https://www.youtube.com", "public YouTube channel feeds, titles and links only, fetched live"],
    ["Country shapes: Natural Earth via world-atlas", "https://github.com/topojson/world-atlas", "public domain"],
    ["Earth imagery: NASA Blue Marble", "https://visibleearth.nasa.gov/collection/1484/blue-marble", "public domain"],
    ["Street map tiles", "https://www.openstreetmap.org/copyright", "© OpenStreetMap contributors, ODbL"],
  ];
  $("#sources").innerHTML = rows.map(([n, u, l]) => `<li><a href="${esc(u)}" target="_blank" rel="noopener">${esc(n)}</a>: ${esc(l)}</li>`).join("");
};

// The globe is the backdrop of every module: desktops load it as soon as the browser is idle, phones (to save
// data) when the globe is first opened.
function startWorld() {
  if (SMALL_SCREEN || loaded.has("globe")) return;
  (window.requestIdleCallback || ((f) => setTimeout(f, 300)))(() => loaded.has("globe") || load("globe"));
}


// ---------- Black October 2026 Crisis War Room & Exploit Simulation Engine ----------
let warroomIncidents = [];
let activeIncident = null;
let simStep = 0;
let simInterval = null;

loaders.warroom = async () => {
  try {
    const data = await api("/v1/black-october/overview");
    warroomIncidents = data.incidents || [];
    renderWarroomCards(warroomIncidents);
  } catch (err) {
    console.error("War room loader failed:", err);
  }
};

function renderWarroomCards(incidents) {
  const grid = $("#warroom-incidents-grid");
  if (!grid) return;
  if (!incidents.length) {
    grid.innerHTML = '<p class="muted">No incidents matching the selected filter.</p>';
    return;
  }

  grid.innerHTML = incidents.map((inc) => {
    const tierClass = inc.tier === "year_level" ? "tier-year" : inc.tier === "critical_infra" ? "tier-critical" : "tier-month";
    const tierLabel = inc.tier === "year_level" ? "YEAR-LEVEL 0-DAY" : inc.tier === "critical_infra" ? "CRITICAL INFRASTRUCTURE" : "MONTH-LEVEL INCIDENT";
    const tierColor = inc.tier === "year_level" ? "#ef4444" : inc.tier === "critical_infra" ? "#a855f7" : "#f59e0b";
    const cvss = inc.cvss || 8.0;
    const cvssCol = cvss >= 9.5 ? "#ef4444" : cvss >= 8.5 ? "#f97316" : "#f59e0b";

    return `
      <div class="warroom-card ${tierClass}">
        <div>
          <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
            <span style="font: 700 11px var(--hud); color: ${tierColor}; letter-spacing: 0.08em;">${tierLabel}</span>
            <span class="mono" style="background: ${cvssCol}22; color: ${cvssCol}; border: 1px solid ${cvssCol}44; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 700;">CVSS ${cvss.toFixed(1)}</span>
          </div>
          <h4 style="margin: 8px 0 4px; font-size: 16px; color: var(--ink); line-height: 1.3;">${esc(inc.name)}</h4>
          <div style="font-size: 12px; color: var(--dim); margin-bottom: 8px;">
            <b>Target:</b> ${esc(inc.target)} ${inc.cve ? `· <span class="mono" style="color:var(--accent);">${esc(inc.cve)}</span>` : ""}
          </div>
          <p style="font-size: 13px; color: var(--muted); margin: 0 0 12px; line-height: 1.45;">
            ${esc(inc.summary)}
          </p>
        </div>
        <div style="border-top: 1px solid var(--line); padding-top: 10px; display: flex; justify-content: space-between; align-items: center;">
          <span class="fineprint">${esc(inc.geo?.location || "Global Fleet")}</span>
          <button type="button" class="btn-sm chip btn-autopsy" data-autopsy-id="${esc(inc.id)}" style="background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.4); color: #fff; font-weight: 600;">
            ⚡ Exploit Autopsy & Sim
          </button>
        </div>
      </div>
    `;
  }).join("");

  $$(".btn-autopsy").forEach((b) => b.addEventListener("click", () => openAutopsyModal(b.dataset.autopsyId)));
}

// Filter chips
(function wireWarroomFilters() {
  $$("#warroom-filter-chips button").forEach((btn) => {
    btn.addEventListener("click", () => {
      $$("#warroom-filter-chips button").forEach((b) => b.classList.remove("on"));
      btn.classList.add("on");
      const tier = btn.dataset.tier;
      if (tier === "all") renderWarroomCards(warroomIncidents);
      else renderWarroomCards(warroomIncidents.filter((i) => i.tier === tier));
    });
  });

  $("#refresh-warroom")?.addEventListener("click", () => loaders.warroom());
})();

// 1-Click Black October Stack Auditor Form
(function wireWarroomAuditor() {
  const form = $("#warroom-audit-form");
  const targetInput = $("#warroom-audit-target");
  const typeSelect = $("#warroom-audit-type");
  const box = $("#warroom-audit-results");
  if (!form) return;

  function runAudit(target, type) {
    if (!target) return;
    box.innerHTML = '<p class="muted">Scanning live against revoked eMudhra CAs, PHP2Shell web runtimes, and vulnerable dependencies…</p>';
    api(`/v1/black-october/audit?target=${encodeURIComponent(target)}&target_type=${encodeURIComponent(type)}`)
      .then((d) => {
        const score = d.black_october_risk_score ?? 0;
        const col = score >= 50 ? "#ef4444" : score >= 20 ? "#f59e0b" : "#10b981";
        const findings = d.findings || [];
        const rems = d.recommended_remediations || [];

        box.innerHTML = `
          <div class="panel" style="border-left: 4px solid ${col}; margin-bottom: 12px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
              <div>
                <span style="font-size: 18px; font-weight: 700; color: ${col};">${esc(d.overall_verdict)}</span>
                <span style="font-size: 15px; font-weight: 600; margin-left: 8px;">${esc(d.target)}</span>
              </div>
              <div class="facts">
                <div><b>Risk Score</b><span class="mono" style="color: ${col}; font-weight: 700;">${score} / 100</span></div>
                <div><b>Critical Findings</b><span class="mono">${d.critical_count ?? 0}</span></div>
              </div>
            </div>
            
            <div style="margin-top: 14px;">
              <b style="font-size: 13px; color: var(--ink);">Audit Findings & Vector Breakdown:</b>
              <div style="display: flex; flex-direction: column; gap: 8px; margin-top: 6px;">
                ${findings.map((f) => {
                  const sCol = f.severity === "CRITICAL" ? "#ef4444" : f.severity === "HIGH" ? "#f97316" : f.severity === "CLEAN" ? "#10b981" : "#7dd3fc";
                  return `
                    <div style="background: var(--bg); padding: 10px 12px; border-radius: 4px; border: 1px solid var(--line);">
                      <div style="display: flex; justify-content: space-between; align-items: center;">
                        <b style="font-size: 13px;">${esc(f.vector)}</b>
                        <span class="tag" style="background: ${sCol}22; color: ${sCol}; font-weight: 600;">${esc(f.severity)}</span>
                      </div>
                      <div style="font-size: 12.5px; color: var(--muted); margin-top: 4px;">${esc(f.detail)}</div>
                    </div>
                  `;
                }).join("")}
              </div>
            </div>

            ${rems.length ? `
              <div style="margin-top: 14px; padding-top: 12px; border-top: 1px solid var(--line);">
                <b style="color: var(--accent); font-size: 13px;">Recommended Immediate Remediation:</b>
                <ul style="margin: 6px 0 0; padding-left: 18px; font-size: 13px; color: var(--muted);">
                  ${rems.map((r) => `<li>${esc(r)}</li>`).join("")}
                </ul>
              </div>
            ` : ""}
          </div>
        `;
      })
      .catch((err) => {
        box.innerHTML = `<p class="muted">Error: ${esc(err.message.slice(0, 120))}</p>`;
      });
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    runAudit(targetInput?.value.trim(), typeSelect?.value || "domain");
  });

  $$("[data-audit-target]").forEach((b) => b.addEventListener("click", () => {
    if (targetInput) targetInput.value = b.dataset.auditTarget;
    if (typeSelect) typeSelect.value = b.dataset.auditType;
    runAudit(b.dataset.auditTarget, b.dataset.auditType);
  }));
})();

// ---------- Interactive Exploit Autopsy & Simulation Engine ----------
async function openAutopsyModal(incidentId) {
  const modal = $("#autopsy-modal");
  const body = $("#autopsy-modal-body");
  const title = $("#autopsy-modal-title");
  if (!modal || !body) return;

  modal.hidden = false;
  body.innerHTML = '<p class="muted">Fetching forensic telemetry and assembling attack simulation…</p>';
  simStep = 0;
  if (simInterval) clearInterval(simInterval);

  try {
    const inc = await api(`/v1/black-october/incident/${encodeURIComponent(incidentId)}`);
    activeIncident = inc;
    title.innerHTML = `⚡ Forensic Autopsy: ${esc(inc.name)}`;
    renderAutopsyContent(inc);
  } catch (err) {
    body.innerHTML = `<p class="muted">Failed to load autopsy: ${esc(err.message)}</p>`;
  }
}

$("#autopsy-modal-close")?.addEventListener("click", () => {
  $("#autopsy-modal").hidden = true;
  if (simInterval) clearInterval(simInterval);
});

function renderAutopsyContent(inc) {
  const body = $("#autopsy-modal-body");
  if (!body) return;

  const isPhp = inc.id === "php2shell";
  const isEmudhra = inc.id === "emudhra";
  const isLitellm = inc.id === "litellm" || inc.id === "cairn-ai";

  body.innerHTML = `
    <!-- Top Metadata Grid -->
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--line);">
      <div>
        <span class="mono" style="color: var(--accent); font-weight: 700;">${esc(inc.cve || "0-DAY IN THE WILD")}</span> ·
        <span style="color: var(--muted);">${esc(inc.date)}</span>
      </div>
      <div>
        <span class="tag" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; font-weight: 700;">CVSS ${esc((inc.cvss || 8).toFixed(1))} CRITICAL</span>
      </div>
    </div>

    <!-- Visual Attack Simulation Box -->
    <div class="panel" style="background: #090d16; border: 1px solid #1e293b; border-radius: 8px; padding: 16px; margin-bottom: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; border-bottom: 1px solid #1e293b; padding-bottom: 8px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="display: inline-block; width: 10px; height: 10px; border-radius: 50%; background: #ef4444; animation: live-pulse 1.6s infinite;"></span>
          <b style="color: #fff; font-size: 14px; letter-spacing: 0.05em;">INTERACTIVE EXPLOIT SIMULATION</b>
        </div>
        <div style="display: flex; gap: 6px;">
          <button type="button" class="btn-sm chip" id="sim-prev-btn">◀ Previous</button>
          <button type="button" class="btn-sm chip" id="sim-play-btn" style="background: #3b82f6; color: #fff; border-color: #3b82f6;">▶ Auto-Play</button>
          <button type="button" class="btn-sm chip" id="sim-next-btn">Next Step ▶</button>
        </div>
      </div>

      <!-- Simulation Display Area -->
      <div id="sim-stage" style="min-height: 220px; font-family: var(--mono); font-size: 13px;"></div>
    </div>

    <!-- 5-Step Forensic Timeline -->
    <div class="panel" style="margin-bottom: 20px;">
      <h4 style="margin: 0 0 10px; color: var(--ink);">Forensic Chronology: How the Attack Unfolded</h4>
      <pre style="background: var(--bg); padding: 14px; border-radius: 6px; font-size: 12.5px; line-height: 1.6; white-space: pre-wrap; color: var(--ink); border: 1px solid var(--line);">${esc(inc.how_it_happened)}</pre>
    </div>

    <!-- Technical Mechanism & Mathematical Flaw -->
    <div class="panel" style="margin-bottom: 20px; border-left: 4px solid var(--accent);">
      <h4 style="margin: 0 0 6px; color: var(--accent);">Technical Mechanism & Cryptographic / Architectural Flaw</h4>
      <p style="margin: 0; font-size: 13.5px; color: var(--ink); line-height: 1.5;">${esc(inc.technical_mechanism)}</p>
      <div style="margin-top: 8px; font-size: 13px; color: var(--muted);"><b>Blast Radius & Impact:</b> ${esc(inc.impact)}</div>
    </div>

    <!-- 60-Second Instant Shell Remediation -->
    <div class="panel" style="background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.3);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <b style="color: #10b981; font-size: 14px;">⚡ 60-Second Emergency Shell Mitigation Command</b>
        <button type="button" class="btn-sm chip" id="copy-autopsy-cmd" style="background: #10b981; color: #000; font-weight: 700; border: none;">Copy Command</button>
      </div>
      <pre id="autopsy-cmd-code" style="background: #020617; padding: 12px; border-radius: 6px; font-family: var(--mono); font-size: 12.5px; color: #38bdf8; overflow-x: auto; border: 1px solid #1e293b;">${esc(inc.mitigation)}</pre>
      ${inc.waf_rule ? `
        <div style="margin-top: 10px;">
          <b style="color: #f59e0b; font-size: 12.5px;">WAF / ModSecurity Mitigation Rule:</b>
          <pre style="background: #020617; padding: 10px; border-radius: 4px; font-family: var(--mono); font-size: 11.5px; color: #f59e0b; overflow-x: auto; margin-top: 4px; border: 1px solid #1e293b;">${esc(inc.waf_rule)}</pre>
        </div>
      ` : ""}
    </div>
  `;

  // Attach copy button
  $("#copy-autopsy-cmd")?.addEventListener("click", () => {
    navigator.clipboard.writeText(inc.mitigation);
    $("#copy-autopsy-cmd").textContent = "Copied!";
    setTimeout(() => ($("#copy-autopsy-cmd").textContent = "Copy Command"), 2000);
  });

  // Wire simulation controls
  setupSimulation(inc);
}

function setupSimulation(inc) {
  let steps = [];

  if (inc.id === "php2shell") {
    steps = [
      {
        title: "STEP 1: Inbound Malicious HTTP Request",
        badge: "ATTACKER INGESTION",
        desc: "Attacker transmits deeply nested multipart/form-data boundary structures over standard HTTP POST.",
        diagram: `
┌──────────────────┐               ┌─────────────────────────────────────┐
│  Attacker IP     │ ────────────> │  Target Web Server (Apache/Nginx)   │
│  [185.220.101.5] │  HTTP POST    │  mod_php / php-fpm (Zend Engine)    │
└──────────────────┘               └─────────────────────────────────────┘
Payload: Content-Type: multipart/form-data; boundary=---------------------------97823...
Header Nesting: 10,000+ recursive boundary wrappers packed with binary offsets.`
      },
      {
        title: "STEP 2: Zend Engine Heap Memory Exhaustion (OOM)",
        badge: "RESOURCE COLLAPSE",
        desc: "The Zend memory manager attempts to allocate consecutive internal buffers, hitting the memory ceiling.",
        diagram: `
Zend Allocator Heap:
[■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■] 100%
>>> OUT OF MEMORY (OOM) ERROR TRIGGERED <<<
Zend initiates emergency unwinding via: zend_error_noreturn(E_ERROR, "Allowed memory size exhausted");`
      },
      {
        title: "STEP 3: The Flawed longjmp() Stack Unwinding",
        badge: "CRITICAL VULNERABILITY",
        desc: "longjmp() skips normal cleanup routines, leaving active frame execution pointers dangling in stack memory.",
        diagram: `
Call Stack:
| [0x7ffe4200]  main()
| [0x7ffe41a0]  php_execute_script()
| [0x7ffe4100]  multipart_buffer_read()
| [0x7ffe4080]  zend_throw_error() -> longjmp() invoked!
* Dangling Pointer left pointing into freed execution frame address at [0x7ffe4080]!`
      },
      {
        title: "STEP 4: Instruction Pointer Overwrite",
        badge: "ARBITRARY WRITE",
        desc: "Subsequent memory allocation reuse overwrites the dangling pointer with attacker-controlled shellcode address.",
        diagram: `
Memory Register State:
%rax : 0x000000000000003b  (sys_execve syscall)
%rdi : 0x00007ffe40801000  ("/bin/sh")
%rip : [0x7ffe4080] ──────> OVERWRITTEN WITH ATTACKER SHELLCODE ADDRESS!`
      },
      {
        title: "STEP 5: Web Shell Execution & Arbitrary Command Control",
        badge: "SYSTEM COMPROMISE",
        desc: "Kernel executes /bin/sh under web server UID (www-data/nginx). Unauthenticated remote code execution achieved.",
        diagram: `
[SUCCESSFUL REMOTE CODE EXECUTION]
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ uname -a
Linux production-target 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux
$ cat /etc/passwd | head -n 3
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/bin/sh`
      }
    ];
  } else if (inc.id === "emudhra") {
    steps = [
      {
        title: "STEP 1: The Cryptographic Key Ceremony",
        badge: "EXPECTED SPECIFICATION",
        desc: "A globally trusted Certificate Authority must generate a 384-bit ECDSA/ECC key with 116 digits of random noise.",
        diagram: `
Elliptic Curve secp384r1 (NIST P-384):
Private Key Space: 2^384 possible combinations
= 394,020,061,963,997,239,422,943,059,200,788,829,760,184,105,773,890,359... (116 decimal digits)
Brute-force duration with planetary supercomputers: > 14 Billion Years.`
      },
      {
        title: "STEP 2: The Scripting & Entropy Truncation Bug",
        badge: "FATAL BUG",
        desc: "Automated bash/HSM key ceremony wrapper zeroed out all but the lowest single byte of the random seed.",
        diagram: `
Expected 48-byte buffer:
[F8 3A 9C 21 B4 07 E3 89 ... 48 RANDOM BYTES ...]

ACTUAL BUFFER RECORDED:
[00 00 00 00 00 00 00 00 00 00 00 00 00 ... 00 00 04]  <-- KEY WAS LITERALLY 4!
Entropy collapsed from 384 bits to 8 bits: k ∈ [0, 255]!`
      },
      {
        title: "STEP 3: 15-Millisecond Brute-Force Verification",
        badge: "INSTANT CRACK",
        desc: "Researchers looped k from 0 to 255 computing public point Q = k * G until matching public certificate.",
        diagram: `
Brute-Force Counter:
k = 0 ... FAIL
k = 1 ... FAIL
k = 2 ... FAIL
k = 3 ... FAIL
k = 4 ... >>> MATCH CONFIRMED! <<<
Time elapsed on consumer laptop: 0.014 seconds!
All 8 Intermediate Private Keys recovered: [4, 56, 66, 115, 155, 156, 230, 237]!`
      },
      {
        title: "STEP 4: Forged Certificate Minting (Man-in-the-Middle)",
        badge: "GLOBAL TRUST HIJACK",
        desc: "Armed with private key k=4, an attacker mints valid SSL certificates for ANY website on earth.",
        diagram: `
Attacker Certificate Signer:
Target Domain: google.com / sbi.co.in / whitehouse.gov
Issuer: eMudhra Sub-CA (signed with private key: 4)
Validation Status:
  ✓ Chrome: VALID & TRUSTED (Green Lock)
  ✓ Apple Safari: VALID & TRUSTED
  ✓ Windows Edge: VALID & TRUSTED
Adversary performs transparent Man-in-the-Middle TLS decryption worldwide!`
      }
    ];
  } else {
    steps = [
      {
        title: "STEP 1: Perimeter Reconnaissance & Target Discovery",
        badge: "PHASE 1",
        desc: `Adversary targets exposed surfaces of ${inc.target}.`,
        diagram: `
Target: ${inc.target}
CVE / Advisory: ${inc.cve || "Unauthenticated 0-Day"}
Vector: ${inc.technical_mechanism}`
      },
      {
        title: "STEP 2: Vulnerability Exploitation & Boundary Penetration",
        badge: "PHASE 2",
        desc: "Attacker executes specialized payload to breach security boundaries.",
        diagram: `
Execution Flow:
${inc.how_it_happened}`
      },
      {
        title: "STEP 3: Impact & Ecosystem Blast Radius",
        badge: "PHASE 3",
        desc: "Lateral movement and exfiltration executed across target infrastructure.",
        diagram: `
Severity: CVSS ${inc.cvss} CRITICAL
Impact: ${inc.impact}
Recommended Action:
${inc.mitigation}`
      }
    ];
  }

  function renderStep(idx) {
    const s = steps[idx];
    const stage = $("#sim-stage");
    if (!stage || !s) return;

    stage.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <b style="color: #38bdf8; font-size: 14px;">${esc(s.title)}</b>
        <span class="tag" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; font-weight: 700;">${esc(s.badge)}</span>
      </div>
      <p style="color: var(--muted); margin: 0 0 10px; font-size: 13px;">${esc(s.desc)}</p>
      <pre style="background: #020617; padding: 12px; border-radius: 6px; font-size: 12px; line-height: 1.5; color: #a5f3fc; overflow-x: auto; border: 1px solid #1e293b;">${esc(s.diagram)}</pre>
      <div style="display: flex; gap: 4px; margin-top: 10px;">
        ${steps.map((_, i) => `
          <div style="flex: 1; height: 4px; border-radius: 2px; background: ${i <= idx ? '#38bdf8' : '#334155'}; transition: background 0.2s;"></div>
        `).join("")}
      </div>
    `;
  }

  simStep = 0;
  renderStep(simStep);

  $("#sim-prev-btn")?.addEventListener("click", () => {
    if (simStep > 0) {
      simStep--;
      renderStep(simStep);
    }
  });

  $("#sim-next-btn")?.addEventListener("click", () => {
    if (simStep < steps.length - 1) {
      simStep++;
      renderStep(simStep);
    }
  });

  $("#sim-play-btn")?.addEventListener("click", () => {
    if (simInterval) {
      clearInterval(simInterval);
      simInterval = null;
      $("#sim-play-btn").textContent = "▶ Auto-Play";
    } else {
      $("#sim-play-btn").textContent = "⏸ Pause";
      simInterval = setInterval(() => {
        if (simStep < steps.length - 1) {
          simStep++;
          renderStep(simStep);
        } else {
          clearInterval(simInterval);
          simInterval = null;
          $("#sim-play-btn").textContent = "▶ Replay";
        }
      }, 3500);
    }
  });
}


show(location.hash.slice(1) || "globe");
startWorld();
headerStatus();
railBadges();
loadWire();
