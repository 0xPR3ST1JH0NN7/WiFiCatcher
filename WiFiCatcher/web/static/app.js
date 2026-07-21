/* WiFiCatcher frontend: Cytoscape graph and interaction. */
"use strict";

const API = {
  async import(file) {
    const fd = new FormData();
    fd.append("file", file);
    return fetchJSON("/api/import", { method: "POST", body: fd });
  },
  node: (id) => fetchJSON(`/api/node/${encodeURIComponent(id)}`),
  search: (q) => fetchJSON(`/api/search?q=${encodeURIComponent(q)}`),
  config: () => fetchJSON("/api/config"),
  clear: () => fetchJSON("/api/clear", { method: "POST" }),
  liveStatus: () => fetchJSON("/api/live/status"),
  deauth: (payload) =>
    fetchJSON("/api/operations/deauth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  liveStart: (payload) =>
    fetchJSON("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  liveStop: () => fetchJSON("/api/live/stop", { method: "POST" }),
  interfaces: () => fetchJSON("/api/live/interfaces"),
  chooseSave: () => fetchJSON("/api/live/choose-save", { method: "POST" }),
  enterpriseCert: (payload) =>
    fetchJSON("/api/operations/enterprise/cert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  enterpriseEap: (payload) =>
    fetchJSON("/api/operations/enterprise/eap-methods", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  enterpriseCertUpload: (file, bssid) => {
    const fd = new FormData();
    fd.append("file", file);
    if (bssid) fd.append("ap_bssid", bssid);
    return fetchJSON("/api/operations/enterprise/cert/upload", { method: "POST", body: fd });
  },
};

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `${res.status} ${res.statusText}`);
  return data;
}

/* --------------------------------------------------------------- Cytoscape */
const cy = cytoscape({
  container: document.getElementById("cy"),
  wheelSensitivity: 0.25,
  minZoom: 0.1,
  maxZoom: 4,
  style: [
    {
      selector: "node",
      style: {
        label: "data(label)",
        color: "#dbeaf0",
        "font-size": 10,
        "text-valign": "bottom",
        "text-margin-y": 6,
        "text-wrap": "ellipsis",
        "text-max-width": 130,
        "text-outline-color": "#0a1016",
        "text-outline-width": 2.5,
        "min-zoomed-font-size": 6,
        // Nodes are SVG glyphs floating on the canvas: no fill, render the icon
        // unclipped, and keep the border invisible until a status class turns
        // it into a coloured frame (selected / fresh / handshake / enterprise).
        shape: "round-rectangle",
        "background-opacity": 0,
        "background-fit": "contain",
        "background-clip": "none",
        "border-width": 0,
        "border-color": "#0a1016",
        width: 36,
        height: 36,
      },
    },
    {
      selector: 'node[kind = "ap"]',
      style: {
        "background-image": "/static/img/node-ap.svg?v=1",
        width: "mapData(degree, 0, 12, 48, 80)",
        height: "mapData(degree, 0, 12, 48, 80)",
        "font-size": 12,
        "font-weight": "bold",
      },
    },
    {
      selector: 'node[kind = "client"]',
      style: { "background-image": "/static/img/node-client.svg?v=1",
               width: 42, height: 42 },
    },
    {
      selector: 'node[kind = "client"][?unassociated]',
      style: { "background-image-opacity": 0.4 },
    },
    {
      selector: 'node[kind = "ap"][?enterprise]',
      style: { "background-image": "/static/img/node-ap-enterprise.svg?v=1",
               "border-color": "#a78bfa", "border-width": 4 },
    },
    {
      selector: "edge",
      style: {
        width: 2,
        "line-color": "#2d4654",
        "curve-style": "bezier",
        "target-arrow-shape": "none",
      },
    },
    {
      selector: ".faded",
      style: { opacity: 0.12, "text-opacity": 0.05, events: "no" },
    },
    {
      selector: ".highlight",
      style: { "border-color": "#34d399", "border-width": 4, "line-color": "#34d399" },
    },
    {
      selector: "node.fresh",
      style: { "border-color": "#fbbf24", "border-width": 5,
               "border-opacity": 1, "background-blacken": -0.1 },
    },
    {
      selector: "node.has-handshake",
      style: { "border-color": "#fbbf24", "border-width": 5,
               label: "data(hsLabel)", "font-weight": "bold" },
    },
    { selector: ".hidden-node", style: { display: "none" } },
    {
      selector: "node:selected",
      style: { "border-color": "#22d3ee", "border-width": 4 },
    },
    // Pulsing red circular halo while a deauth runs against this node / edge.
    {
      selector: "node.deauthing",
      style: { "overlay-color": "#ff3b3b", "overlay-shape": "ellipse",
               "overlay-opacity": 0.28, "overlay-padding": 8 },
    },
    {
      selector: "edge.deauthing",
      style: { "line-color": "#ff3b3b", width: 5 },
    },
  ],
});

let OFFENSIVE = false;
let currentLayout = "fcose";

// Cap how far `fit` may zoom in, so a small capture doesn't get blown up and
// nodes/labels stay readable. Fits to visible elements only.
const MAX_FIT_ZOOM = 1.1;
function fitGraph() {
  const visible = cy.elements(":visible");
  cy.fit(visible.nonempty() ? visible : undefined, 60);
  if (cy.zoom() > MAX_FIT_ZOOM) {
    cy.zoom(MAX_FIT_ZOOM);
    cy.center(visible.nonempty() ? visible : undefined);
  }
}

function runLayout(name) {
  currentLayout = name || currentLayout;
  const opts =
    currentLayout === "fcose"
      ? { name: "fcose", animate: true, animationDuration: 500, randomize: true,
          packComponents: false, nodeRepulsion: 16000, idealEdgeLength: 130,
          nodeSeparation: 150, gravity: 0.15, gravityRange: 3.8, fit: false,
          padding: 60 }
      : currentLayout === "concentric"
      ? { name: "concentric", concentric: (n) => n.degree(), levelWidth: () => 2,
          minNodeSpacing: 60, fit: false, padding: 60 }
      : currentLayout === "breadthfirst"
      ? { name: "breadthfirst", directed: false, spacingFactor: 1.6, fit: false, padding: 60 }
      : { name: currentLayout, fit: false, padding: 60 };
  const layout = cy.layout(opts);
  layout.one("layoutstop", fitGraph);
  layout.run();
}

/* ----------------------------------------------------------------- render */
// Show the "no capture" splash when empty; show the graph legend only when
// there are nodes to read it against.
function setEmptyState(empty) {
  document.getElementById("empty-state").classList.toggle("hidden", !empty);
  const toggle = document.getElementById("view-toggle");
  if (toggle) toggle.classList.toggle("hidden", empty);
  // No table without data — fall back to the graph so the empty splash shows.
  if (empty && currentView === "table") setView("graph");
  // The node search overlay is graph-only chrome, same visibility as the legend.
  const graphSearch = document.getElementById("graph-search");
  if (graphSearch) graphSearch.classList.toggle("hidden", empty || currentView === "table");
  const legend = document.getElementById("graph-legend");
  if (legend) {
    const wasHidden = legend.classList.contains("hidden");
    const hide = empty || currentView === "table";   // legend is graph-only chrome
    legend.classList.toggle("hidden", hide);
    // Only on the hidden->visible transition (a capture just appeared): show the
    // overlay fully, then let it fade again. Doing this on every setEmptyState
    // would re-arm the timer on each live/replay patch (~1.2s < 3s), so it could
    // never dim during an active capture — the very moment it should get away.
    if (!hide && wasHidden) { wakeLegend(); armLegendDim(); }
  }
}

function renderGraph(payload) {
  const nodes = payload.elements.nodes.map((n) => {
    if (n.data.kind === "client") {
      n.data.unassociated = !payload.elements.edges.some(
        (e) => e.data.source === n.data.id || e.data.target === n.data.id
      );
    }
    return n;
  });
  cy.elements().remove();
  cy.add(nodes);
  cy.add(payload.elements.edges);
  applyFilters();
  runLayout(); // fits (with zoom cap) once the layout settles
  setEmptyState(cy.nodes().length === 0);
  if (payload.summary) updateStats(payload.summary);
  populateFilterOptions();
}

function updateStats(s) {
  document.getElementById("stat-aps").textContent = s.access_points ?? 0;
  document.getElementById("stat-clients").textContent = s.clients ?? 0;
  document.getElementById("stat-assoc").textContent = s.associated_clients ?? 0;
  document.getElementById("stat-hidden").textContent = s.hidden_aps ?? 0;
}

function populateFilterOptions() {
  const encs = new Set();
  const chans = new Set();
  cy.nodes('[kind = "ap"]').forEach((n) => {
    if (n.data("privacy")) encs.add(n.data("privacy"));
    if (n.data("channel")) chans.add(n.data("channel"));
  });
  fillSelect("filter-enc", [...encs].sort());
  fillSelect(
    "filter-chan",
    [...chans].sort((a, b) => Number(a) - Number(b))
  );
}

function fillSelect(id, values) {
  const sel = document.getElementById(id);
  const current = sel.value;
  sel.innerHTML = '<option value="">all</option>';
  values.forEach((v) => {
    const o = document.createElement("option");
    o.value = v;
    o.textContent = v;
    sel.appendChild(o);
  });
  sel.value = current;
}

/* ----------------------------------------------------------------- filters */
// A legend row is "on" unless it carries the .off class (toggled by clicking it).
function filterActive(name) {
  const el = document.getElementById("lt-" + name);
  return !el || !el.classList.contains("off");
}

function applyFilters() {
  const showAps = filterActive("aps");
  const showClients = filterActive("clients");
  const showUnassoc = filterActive("unassoc");
  const enc = document.getElementById("filter-enc").value;
  const chan = document.getElementById("filter-chan").value;

  cy.batch(() => {
    cy.nodes().forEach((n) => {
      const kind = n.data("kind");
      let show = true;
      if (kind === "ap") {
        if (!showAps) show = false;
        if (enc && n.data("privacy") !== enc) show = false;
        if (chan && String(n.data("channel")) !== chan) show = false;
      } else {
        if (!showClients) show = false;
        if (!showUnassoc && n.data("unassociated")) show = false;
      }
      n.toggleClass("hidden-node", !show);
    });
  });
  renderTable();   // keep the table in sync (no-op unless the table view is open)
}

/* -------------------------------------------------------------- table view */
// A sortable, searchable table alternative to the node graph — much easier to
// scan once a capture has too many APs / clients for the graph to stay legible.
// Rows are read straight from the live Cytoscape model, so the table always
// matches the graph and follows its live updates. It honours the same legend
// filters: nodes hidden by a filter (.hidden-node) are omitted here too.
let currentView = "graph";
const tableSort = {
  ap: { key: "degree", dir: "desc" },     // busiest APs first by default
  client: { key: "power", dir: "desc" },  // strongest clients first
};

// The AP a client is associated to, taken from its graph edge (live-accurate).
function clientAssocAp(n) {
  const ap = n.neighborhood('node[kind = "ap"]').first();
  return ap.nonempty() ? ap : null;
}

// Sort helpers: missing numbers always sink to the bottom, either direction.
function numOr(v) { const n = Number(v); return Number.isFinite(n) ? n : NaN; }
function cellOr(v) {
  return v === null || v === undefined || v === "" ? "—" : escapeHtml(String(v));
}
function sigCell(p) {
  if (p === null || p === undefined || p === "") return '<span class="muted-cell">—</span>';
  const dbm = Number(p);
  const cls = dbm >= -60 ? "sig-strong" : dbm >= -75 ? "sig-mid" : "sig-weak";
  return `<span class="${cls}">${escapeHtml(String(dbm))} dBm</span>`;
}

const AP_COLUMNS = [
  { key: "label", label: "ESSID",
    val: (n) => (n.data("label") || "").toLowerCase(),
    render: (n) => {
      const hidden = !n.data("essid");
      return `<span class="${hidden ? "muted-cell" : ""}">${escapeHtml(n.data("label") || "—")}</span>`;
    } },
  { key: "id", label: "BSSID", cls: "mono",
    val: (n) => n.id(), render: (n) => escapeHtml(n.id()) },
  { key: "channel", label: "Ch", cls: "num",
    val: (n) => numOr(n.data("channel")), render: (n) => cellOr(n.data("channel")) },
  { key: "privacy", label: "Encryption",
    val: (n) => (n.data("privacy") || "").toLowerCase(),
    render: (n) => cellOr(n.data("privacy")) +
      (n.data("enterprise") ? ' <span class="tbl-badge ent">802.1X</span>' : "") },
  { key: "wps", label: "WPS",
    val: (n) => (n.data("wps") ? 0 : 1),   // WPS-on sorts to the top
    render: (n) => n.data("wps")
      ? `<span class="tbl-badge wps">WPS${n.data("wps_version") ? " v" + escapeHtml(String(n.data("wps_version"))) : ""}${n.data("wps_locked") ? " 🔒" : ""}</span>`
      : '<span class="muted-cell">—</span>' },
  { key: "power", label: "Signal", cls: "num",
    val: (n) => numOr(n.data("power")), render: (n) => sigCell(n.data("power")) },
  { key: "degree", label: "Clients", cls: "num",
    val: (n) => n.degree(false), render: (n) => String(n.degree(false)) },
  { key: "vendor", label: "Vendor", cls: "muted-cell",
    val: (n) => (n.data("vendor") || "").toLowerCase(),
    render: (n) => cellOr(n.data("vendor")) },
];

const CLIENT_COLUMNS = [
  { key: "id", label: "MAC", cls: "mono",
    val: (n) => n.id(), render: (n) => escapeHtml(n.id()) },
  { key: "assoc", label: "Associated AP",
    val: (n) => { const ap = clientAssocAp(n); return ap ? (ap.data("label") || ap.id()).toLowerCase() : "~"; },
    render: (n) => {
      const ap = clientAssocAp(n);
      return ap ? escapeHtml(ap.data("label") || ap.id())
                : '<span class="tbl-badge un">unassociated</span>';
    } },
  { key: "power", label: "Signal", cls: "num",
    val: (n) => numOr(n.data("power")), render: (n) => sigCell(n.data("power")) },
  { key: "vendor", label: "Vendor", cls: "muted-cell",
    val: (n) => (n.data("vendor") || "").toLowerCase(),
    render: (n) => cellOr(n.data("vendor")) },
];

function tableFilterText() {
  return (document.getElementById("table-search").value || "").trim().toLowerCase();
}

function nodeMatchesText(n, q) {
  if (!q) return true;
  const hay = [n.id(), n.data("label"), n.data("privacy"), n.data("vendor"), n.data("channel")];
  const ap = n.data("kind") === "client" ? clientAssocAp(n) : null;
  if (ap) hay.push(ap.data("label"), ap.id());
  return hay.some((h) => h && String(h).toLowerCase().includes(q));
}

function sortNodes(nodes, cols, state) {
  const col = cols.find((c) => c.key === state.key) || cols[0];
  const dir = state.dir === "asc" ? 1 : -1;
  return nodes.sort((a, b) => {
    const va = col.val(a), vb = col.val(b);
    if (typeof va === "number" && typeof vb === "number") {
      const aNan = Number.isNaN(va), bNan = Number.isNaN(vb);
      if (aNan && bNan) return 0;
      if (aNan) return 1;                 // missing values always last
      if (bNan) return -1;
      return (va - vb) * dir;
    }
    return String(va).localeCompare(String(vb), undefined, { numeric: true }) * dir;
  });
}

function renderOneTable(kind, cols, state, tableId, countId, emptyId) {
  const q = tableFilterText();
  const nodes = cy.nodes(`[kind = "${kind}"]`)
    .filter((n) => !n.hasClass("hidden-node") && nodeMatchesText(n, q))
    .toArray();
  sortNodes(nodes, cols, state);

  const table = document.getElementById(tableId);
  const thead = table.querySelector("thead");
  const tbody = table.querySelector("tbody");

  thead.innerHTML = "<tr>" + cols.map((c) => {
    const on = state.key === c.key;
    const caret = on ? (state.dir === "asc" ? "▲" : "▼") : "▾";
    const cls = [c.cls || "", on ? "sorted" : ""].join(" ").trim();
    return `<th data-key="${c.key}" class="${cls}">${escapeHtml(c.label)}` +
           `<span class="sort-caret">${caret}</span></th>`;
  }).join("") + "</tr>";

  tbody.innerHTML = nodes.map((n) => {
    const sel = n.selected() ? " selected" : "";
    return `<tr data-id="${escapeHtml(n.id())}" class="${sel.trim()}">` +
      cols.map((c) => `<td class="${c.cls || ""}">${c.render(n)}</td>`).join("") + "</tr>";
  }).join("");

  document.getElementById(countId).textContent = String(nodes.length);
  document.getElementById(emptyId).classList.toggle("hidden", nodes.length > 0);

  thead.querySelectorAll("th").forEach((th) => {
    th.onclick = () => {
      const key = th.getAttribute("data-key");
      if (state.key === key) state.dir = state.dir === "asc" ? "desc" : "asc";
      else { state.key = key; state.dir = "desc"; }
      renderTable();
    };
  });
  tbody.querySelectorAll("tr").forEach((tr) => {
    tr.onclick = () => {
      const id = tr.getAttribute("data-id");
      cy.$(":selected").unselect();
      const node = cy.getElementById(id);
      if (node.nonempty()) node.select();
      document.querySelectorAll("#table-view tr.selected").forEach((r) => r.classList.remove("selected"));
      tr.classList.add("selected");
      highlightAssociations(id);
      openNode(id);
    };
  });
}

// In table view, light up the rows associated with a clicked node: an AP lights
// its connected clients, a client lights its AP (association = a graph edge).
function highlightAssociations(nodeId) {
  document.querySelectorAll("#table-view tr.associated")
    .forEach((r) => r.classList.remove("associated"));
  if (!nodeId) return;
  const node = cy.getElementById(nodeId);
  if (node.empty()) return;
  const ids = new Set(node.neighborhood().nodes().map((n) => n.id()));
  document.querySelectorAll("#table-view tr[data-id]").forEach((tr) => {
    if (ids.has(tr.getAttribute("data-id"))) tr.classList.add("associated");
  });
}

function renderTable() {
  if (currentView !== "table") return;
  const scroll = document.querySelector(".table-scroll");
  const top = scroll ? scroll.scrollTop : 0;
  renderOneTable("ap", AP_COLUMNS, tableSort.ap, "ap-table", "tbl-ap-count", "ap-empty");
  renderOneTable("client", CLIENT_COLUMNS, tableSort.client, "client-table", "tbl-client-count", "client-empty");
  if (scroll) scroll.scrollTop = top;   // preserve scroll across live re-renders
  // Re-apply the association highlight after a re-render (e.g. a live patch).
  const sel = cy.nodes(":selected");
  if (sel.nonempty()) highlightAssociations(sel.first().id());
}

function setView(view) {
  currentView = view === "table" ? "table" : "graph";
  const isTable = currentView === "table";
  document.getElementById("table-view").classList.toggle("hidden", !isTable);
  document.querySelectorAll(".vt-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === currentView));
  // The node search overlay navigates the canvas (it focuses / zooms a node), so
  // it only makes sense in graph mode; the table has its own row filter. Hide it
  // in table view (and when empty) and close any open results dropdown.
  const empty = cy.nodes().length === 0;
  const graphSearch = document.getElementById("graph-search");
  if (graphSearch) graphSearch.classList.toggle("hidden", empty || isTable);
  if (isTable) hideSearch();
  // The legend is graph-only chrome; hide it while the table is up.
  const legend = document.getElementById("graph-legend");
  if (legend) {
    legend.classList.toggle("hidden", empty || isTable);
    // Returning to the graph re-lights the overlay, then lets it idle-dim again.
    if (!isTable && !empty) { wakeLegend(); armLegendDim(); }
  }
  if (isTable) renderTable();
  else requestAnimationFrame(() => cy.resize());
}

document.querySelectorAll(".vt-btn").forEach((b) =>
  b.addEventListener("click", () => setView(b.dataset.view)));
document.getElementById("table-search").addEventListener("input", renderTable);

// Easter egg: click the toolbar runner cat and it hops. Re-triggering mid-hop
// restarts the animation; the class is cleared when the jump finishes.
const catRun = document.querySelector(".cat-run");
const catKey = document.querySelector(".cat-key");
// Click the cat: a single hop of the cat alone.
function hopCat() {
  if (!catRun) return;
  catRun.classList.remove("hop");
  void catRun.offsetWidth;   // force reflow so a repeat trigger restarts the hop
  catRun.classList.add("hop");
}
// Celebrate a capture (handshake and similar): the cat and the key hop together
// 5 times (driven by the CSS iteration count), cleared on animationend.
function celebrateCat() {
  for (const el of [catRun, catKey]) {
    if (!el) continue;
    el.classList.remove("jump");
    void el.offsetWidth;
    el.classList.add("jump");
  }
}
if (catRun) catRun.addEventListener("click", hopCat);   // easter egg: click to hop once
for (const el of [catRun, catKey]) {
  if (el) el.addEventListener("animationend", (e) => {
    if (e.animationName === "cat-jump") el.classList.remove("jump", "hop");
  });
}

// Pause every CSS animation while the tab is in the background: a hidden window
// should cost no CPU (no per-frame repaints of the live pulse, spinners, etc.).
document.addEventListener("visibilitychange", () => {
  document.documentElement.classList.toggle("anim-paused", document.hidden);
});

/* ----------------------------------------------------------------- details */
// The node whose details panel is open, so its values can be refreshed live.
let detailNodeId = null;

// Build just the field rows (+ probed ESSIDs) for a node. Kept separate so the
// panel's values can be refreshed in place during a live capture without
// rebuilding the action buttons (whose state a running op may be driving).
function buildDetailFields(info) {
  const isAp = info.kind === "ap";
  const rows = [];
  const row = (k, v) =>
    v !== null && v !== undefined && v !== ""
      ? rows.push(`<div class="detail-row"><span class="k">${k}</span><span class="v">${escapeHtml(v)}</span></div>`)
      : null;
  // Same as row(), but the value is click-to-copy (ESSID / BSSID / MAC).
  const rowCopy = (k, v) =>
    v !== null && v !== undefined && v !== ""
      ? rows.push(`<div class="detail-row"><span class="k">${k}</span><span class="v copyable" title="Click to copy">${escapeHtml(v)}</span></div>`)
      : null;
  if (isAp) {
    rowCopy("ESSID", info.essid);
    rowCopy("BSSID", info.id);
    row("Channel", info.channel);
    row("Encryption", info.privacy);
    row("Cipher", info.cipher);
    row("Auth", info.authentication);
    if (info.wps) {
      row("WPS", info.wps_version ? `Yes (v${info.wps_version})` : "Yes");
      row("WPS locked", info.wps_locked ? "Yes" : "No");
    }
    row("Signal", info.power != null ? `${info.power} dBm` : null);
    row("Beacons", info.beacons);
    row("Data", info.data);
    row("Vendor", info.vendor);
    row("Clients", info.degree);
    row("First seen", info.first_seen);
    row("Last seen", info.last_seen);
  } else {
    rowCopy("MAC", info.id);
    row("Vendor", info.vendor);
    rowCopy("Associated to", info.associated_bssid);
    row("Signal", info.power != null ? `${info.power} dBm` : null);
    row("Packets", info.packets);
    row("First seen", info.first_seen);
    row("Last seen", info.last_seen);
  }
  let probes = "";
  if (info.probed_essids && info.probed_essids.length) {
    probes =
      `<h4>Probed ESSIDs</h4><ul class="probe-list">` +
      info.probed_essids.map((p) => `<li>${escapeHtml(p)}</li>`).join("") +
      `</ul>`;
  }
  return rows.join("") + probes;
}

// Wire click-to-copy on the values inside a container.
function attachCopyable(container) {
  container.querySelectorAll(".v.copyable").forEach((el) => {
    el.onclick = () => copyText(el.textContent);
  });
}

// Refresh only the open panel's field values (signal, last seen, clients…) in
// place, leaving the action buttons untouched so a running op's button state
// survives.
function refreshDetails(info) {
  if (!info || info.id !== detailNodeId) return;
  const fields = document.getElementById("detail-fields");
  if (!fields) return;
  fields.innerHTML = buildDetailFields(info);
  attachCopyable(fields);
}

// Attack advisor content, per WiFi security type. Each entry has a plain-language
// list (shown in the panel), short bar-toast blurbs (one per attack type), and an
// attack tree as flat nodes with parent pointers (rendered as a graph on demand).
const ATTACK_DATA = {
  "wpa-psk": {
    family: "WPA and WPA2 PSK",
    list: [
      "If WPS is enabled, attack the WPS PIN to recover the passphrase: brute force it online with Reaver or Bully, or use Pixie Dust offline when the access point is vulnerable.",
      "Capture the four way handshake (wait passively, send a deauth to force a reconnect, or lure clients with an evil twin or MANA rogue access point), then crack the PSK offline with a wordlist or brute force using aircrack ng or hashcat.",
      "Run a PMKID attack: request the PMKID from an access point that includes it and capture it with hcxdumptool, then crack it offline with hashcat. This works even when no client is connected.",
    ],
    toasts: ["WPS PIN brute force", "Pixie Dust on WPS", "Handshake capture then offline crack", "PMKID offline crack"],
    nodes: [
      {"id": "root", "parent": null, "label": "WPA and WPA2 PSK", "kind": "root"},
      {"id": "goal_recover", "parent": "root", "label": "Recover the passphrase", "kind": "goal"},
      {"id": "m_wps", "parent": "goal_recover", "label": "WPS PIN attack", "kind": "method"},
      {"id": "a_wps_online", "parent": "m_wps", "label": "Online brute force with Reaver or Bully", "kind": "action"},
      {"id": "a_wps_pixie", "parent": "m_wps", "label": "Offline Pixie Dust on a vulnerable AP", "kind": "action"},
      {"id": "m_hs", "parent": "goal_recover", "label": "Four way handshake", "kind": "method"},
      {"id": "a_hs_wait", "parent": "m_hs", "label": "Wait passively for a client to join", "kind": "action"},
      {"id": "a_hs_deauth", "parent": "m_hs", "label": "Send a deauth to force a reconnect", "kind": "action"},
      {"id": "a_hs_twin", "parent": "m_hs", "label": "Lure clients with an evil twin", "kind": "action"},
      {"id": "a_hs_mana", "parent": "m_hs", "label": "Lure clients with a MANA rogue AP", "kind": "action"},
      {"id": "a_hs_crack", "parent": "m_hs", "label": "Crack the PSK offline with aircrack ng or hashcat", "kind": "action"},
      {"id": "m_pmkid", "parent": "goal_recover", "label": "PMKID attack", "kind": "method"},
      {"id": "a_pmkid_get", "parent": "m_pmkid", "label": "Request and capture the PMKID with hcxdumptool", "kind": "action"},
      {"id": "a_pmkid_crack", "parent": "m_pmkid", "label": "Crack the PMKID offline with hashcat", "kind": "action"},
    ],
  },
  "wep": {
    family: "WEP (Wired Equivalent Privacy)",
    list: [
      "ARP request replay: captured ARP requests are reinjected so the access point answers them over and over, flooding the air with fresh initialization vectors and sharply cutting the time needed to recover the key.",
      "Fragmentation attack: a small amount of keystream is recovered from a single captured packet, then used to forge valid packets whose injection makes the access point emit large volumes of initialization vectors.",
      "KoreK ChopChop attack: an encrypted packet is peeled one byte at a time to reveal its plaintext and keystream without knowing the key, which then lets an attacker forge traffic to gather more initialization vectors.",
      "Caffe Latte attack: a lone client is targeted instead of the access point and coaxed into producing usable initialization vectors, so the key can be cracked far away from the real network.",
      "KoreK statistical cracking: once enough initialization vectors are collected, the key is derived statistically by exploiting known weaknesses in how RC4 turns the key into keystream.",
      "Brute force cracking: candidate keys are tried exhaustively, useful only as a fallback when the key space is small or part of the key is already known.",
    ],
    toasts: ["ARP replay IV flood", "Fragmentation keystream attack", "ChopChop packet decrypt", "Caffe Latte client attack", "KoreK statistical crack"],
    nodes: [
      {"id": "root", "parent": null, "label": "WEP", "kind": "root"},
      {"id": "g_key", "parent": "root", "label": "Recover the WEP key", "kind": "goal"},
      {"id": "m_ivs", "parent": "g_key", "label": "Collect initialization vectors", "kind": "method"},
      {"id": "a_capture", "parent": "m_ivs", "label": "Capture traffic with airodump ng", "kind": "action"},
      {"id": "a_arp", "parent": "m_ivs", "label": "ARP request replay", "kind": "action"},
      {"id": "a_frag", "parent": "m_ivs", "label": "Fragmentation attack for keystream", "kind": "action"},
      {"id": "a_chop", "parent": "m_ivs", "label": "ChopChop packet decryption", "kind": "action"},
      {"id": "m_crack", "parent": "g_key", "label": "Crack the collected data", "kind": "method"},
      {"id": "a_korek", "parent": "m_crack", "label": "KoreK statistical attack", "kind": "action"},
      {"id": "a_brute", "parent": "m_crack", "label": "Brute force key search", "kind": "action"},
      {"id": "g_client", "parent": "root", "label": "Attack an isolated client", "kind": "goal"},
      {"id": "m_caffe", "parent": "g_client", "label": "Caffe Latte attack", "kind": "method"},
      {"id": "a_lure", "parent": "m_caffe", "label": "Generate IVs from the client", "kind": "action"},
      {"id": "a_offline", "parent": "m_caffe", "label": "Crack key from client traffic", "kind": "action"},
    ],
  },
  "wpa-enterprise": {
    family: "WPA2 Enterprise (802.1X)",
    list: [
      "Password spray and brute force the 802.1X login, trying a few common passwords across many domain users or many passwords against a single account, to guess valid credentials against the RADIUS server.",
      "Stand up an evil twin access point backed by a rogue RADIUS server, using tools such as eaphammer or hostapd wpe, so clients authenticate to you and reveal their EAP identity along with their MSCHAPv2 challenge and response.",
      "Steer the client onto a weaker EAP method during authentication, for example downgrading it to EAP GTC so the password arrives in the clear instead of as an MSCHAPv2 hash, which makes it far easier to capture and reuse.",
      "Crack a captured MSCHAPv2 challenge and response offline with asleap or hashcat to recover the user password, or run a PEAP relay that forwards the victim inner authentication to the real RADIUS in real time to log in as them.",
      "Capture a legacy EAP MD5 challenge and response off the air and crack the password offline, since EAP MD5 offers no server authentication and no protective tunnel.",
      "Attack EAP TLS client certificate authentication by abusing a stolen or exported client certificate together with its private key to impersonate a legitimate user.",
    ],
    toasts: ["Password spray the login", "Rogue RADIUS evil twin", "EAP downgrade attack", "MSCHAPv2 offline crack", "EAP MD5 capture and crack"],
    nodes: [
      {"id": "root", "parent": null, "label": "WPA2 Enterprise (802.1X)", "kind": "root"},
      {"id": "g1", "parent": "root", "label": "Recover domain credentials", "kind": "goal"},
      {"id": "m1", "parent": "g1", "label": "Online login guessing", "kind": "method"},
      {"id": "a1", "parent": "m1", "label": "Password spray and brute force", "kind": "action"},
      {"id": "g2", "parent": "root", "label": "Capture EAP secrets", "kind": "goal"},
      {"id": "m2", "parent": "g2", "label": "Rogue RADIUS evil twin", "kind": "method"},
      {"id": "a2", "parent": "m2", "label": "Capture EAP identity and MSCHAPv2", "kind": "action"},
      {"id": "a3", "parent": "m2", "label": "Downgrade to a weaker EAP method", "kind": "action"},
      {"id": "a4", "parent": "m2", "label": "Crack MSCHAPv2 with asleap or hashcat", "kind": "action"},
      {"id": "m3", "parent": "g2", "label": "PEAP relay", "kind": "method"},
      {"id": "a5", "parent": "m3", "label": "Relay auth to the real RADIUS", "kind": "action"},
      {"id": "g3", "parent": "root", "label": "Defeat certificate and legacy EAP", "kind": "goal"},
      {"id": "m4", "parent": "g3", "label": "EAP TLS certificate attack", "kind": "method"},
      {"id": "a6", "parent": "m4", "label": "Abuse a stolen client certificate", "kind": "action"},
      {"id": "m5", "parent": "g3", "label": "EAP MD5 capture", "kind": "method"},
      {"id": "a7", "parent": "m5", "label": "Crack EAP MD5 offline", "kind": "action"},
    ],
  },
  "open": {
    family: "Open network",
    list: [
      "Passively capture traffic on the open network, reading unencrypted packets to recover sessions, cookies and browsing activity.",
      "Stand up an evil twin that clones the network name, then deauthenticate clients so they reconnect to the attacker access point.",
      "Run a rogue access point with a stronger signal to lure clients away from the legitimate network.",
      "Present a captive portal with a fake login page to harvest credentials from victims.",
      "Sit in the middle of client traffic with ARP spoofing, then use DNS spoofing or SSL stripping to redirect victims and read protected data.",
    ],
    toasts: ["Passive traffic capture", "Evil twin access point", "Rogue AP lure", "Captive portal phishing", "Man in the middle redirect"],
    nodes: [
      {"id": "root", "parent": null, "label": "Open network", "kind": "root"},
      {"id": "goal_capture", "parent": "root", "label": "Capture client traffic", "kind": "goal"},
      {"id": "method_sniff", "parent": "goal_capture", "label": "Passive sniffing", "kind": "method"},
      {"id": "action_read", "parent": "method_sniff", "label": "Read unencrypted packets", "kind": "action"},
      {"id": "action_sessions", "parent": "method_sniff", "label": "Rebuild sessions and cookies", "kind": "action"},
      {"id": "goal_impersonate", "parent": "root", "label": "Impersonate the network", "kind": "goal"},
      {"id": "method_eviltwin", "parent": "goal_impersonate", "label": "Evil twin access point", "kind": "method"},
      {"id": "action_clone", "parent": "method_eviltwin", "label": "Clone the SSID", "kind": "action"},
      {"id": "action_deauth", "parent": "method_eviltwin", "label": "Deauthenticate clients to force reconnect", "kind": "action"},
      {"id": "method_rogue", "parent": "goal_impersonate", "label": "Rogue access point", "kind": "method"},
      {"id": "action_lure", "parent": "method_rogue", "label": "Lure clients with a stronger signal", "kind": "action"},
      {"id": "goal_harvest", "parent": "root", "label": "Harvest credentials", "kind": "goal"},
      {"id": "method_portal", "parent": "goal_harvest", "label": "Captive portal", "kind": "method"},
      {"id": "action_fakelogin", "parent": "method_portal", "label": "Serve a fake login page", "kind": "action"},
      {"id": "method_mitm", "parent": "goal_harvest", "label": "Man in the middle", "kind": "method"},
      {"id": "action_arp", "parent": "method_mitm", "label": "ARP spoofing to intercept traffic", "kind": "action"},
      {"id": "action_redirect", "parent": "method_mitm", "label": "DNS spoofing and SSL stripping", "kind": "action"},
    ],
  },
};

// Classify a selected AP into an ATTACK_DATA key, or null when we don't advise.
function classifyTech(info) {
  const priv = (info.privacy || "").toUpperCase();
  if (info.enterprise || priv.includes("MGT")) return "wpa-enterprise";
  if (priv.includes("WEP")) return "wep";
  if (priv.includes("WPA")) return "wpa-psk";
  if (priv.includes("OPN") || priv.includes("OPEN")) return "open";
  return null;
}

// Advisor payload for an AP: {key, data} or null when nothing applies.
function suggestAttacks(info) {
  const key = info.kind === "ap" ? classifyTech(info) : null;
  return key ? { key, data: ATTACK_DATA[key] } : null;
}

// One line about this AP's own WPS state, shown for WPA/WPA2 PSK.
function wpsNote(info) {
  if (!info.wps) return "";
  return info.wps_locked
    ? "WPS is present but locked on this AP, so the PIN attack is likely blocked."
    : "WPS is enabled on this AP, so the PIN attack is worth trying first.";
}

// The "Suggested attacks" panel block for an AP, or "" when nothing applies. Open
// by default for visibility; the button opens the attack path graph.
function attackAdvisorHtml(info) {
  const s = suggestAttacks(info);
  if (!s) return "";
  const lis = s.data.list.map((t) => `<li>${escapeHtml(t)}</li>`).join("");
  const note = s.key === "wpa-psk" ? wpsNote(info) : "";
  const noteHtml = note ? `<p class="advisor-wps">${escapeHtml(note)}</p>` : "";
  return `<details class="subpanel attack-advisor" open>
    <summary>Suggested attacks</summary>
    <div class="panel-body">
      <p class="advisor-family">${escapeHtml(s.data.family)}</p>
      ${noteHtml}
      <ul class="advisor-list">${lis}</ul>
      <button class="btn" id="attack-tree-btn">View attack paths</button>
      <p class="advisor-note">Guidance only. Use exclusively on networks you are authorized to test.</p>
    </div>
  </details>`;
}

// Render the attack tree for a security type as an on-demand Cytoscape graph in a
// modal. A fresh instance is built on open and destroyed on close so it never
// competes with the live network graph.
let attackCy = null;
function _cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}
function openAttackModal(key) {
  const data = ATTACK_DATA[key];
  if (!data || typeof cytoscape === "undefined") return;
  document.getElementById("attack-modal-title").textContent = "Attack paths: " + data.family;
  // Left to right tidy tree: x is set by depth, y is packed by leaves and each
  // parent sits at the midpoint of its children. Rendered with a preset layout so
  // the shape is exactly this, not an auto layout that drifts.
  const root = data.nodes.find((n) => n.parent === null) || data.nodes[0];
  const kids = {};
  for (const n of data.nodes) if (n.parent) (kids[n.parent] = kids[n.parent] || []).push(n.id);
  const XS = 280, YS = 72, pos = {};
  let leaf = 0;
  (function place(id, depth) {
    const cs = kids[id] || [];
    if (!cs.length) { pos[id] = { x: depth * XS, y: leaf++ * YS }; return; }
    cs.forEach((c) => place(c, depth + 1));
    const ys = cs.map((c) => pos[c].y);
    pos[id] = { x: depth * XS, y: (Math.min(...ys) + Math.max(...ys)) / 2 };
  })(root.id, 0);

  const elements = [];
  for (const n of data.nodes) {
    elements.push({ data: { id: n.id, label: n.label, kind: n.kind }, position: pos[n.id] });
    if (n.parent) elements.push({ data: { id: n.parent + ">" + n.id, source: n.parent, target: n.id } });
  }
  document.getElementById("attack-modal").classList.remove("hidden");
  if (attackCy) { attackCy.destroy(); attackCy = null; }
  const accent = _cssVar("--accent"), client = _cssVar("--client"),
    panel2 = _cssVar("--panel-2"), border = _cssVar("--border"),
    text = _cssVar("--text"), muted = _cssVar("--muted"),
    onColor = _cssVar("--btn-primary-text") || "#0b0f12";
  attackCy = cytoscape({
    container: document.getElementById("attack-graph"),
    elements,
    style: [
      { selector: "node", style: {
          label: "data(label)", "text-wrap": "wrap", "text-max-width": "150px",
          "font-size": "11px", color: text, "text-valign": "center", "text-halign": "center",
          "background-color": panel2, "background-opacity": 1,
          "border-width": 1, "border-color": border,
          shape: "round-rectangle", width: "label", height: "label", padding: "10px" } },
      { selector: 'node[kind="root"]', style: {
          "background-color": accent, color: onColor, "font-weight": "bold", "border-width": 0 } },
      { selector: 'node[kind="goal"]', style: {
          "background-color": client, color: onColor, "font-weight": "bold", "border-width": 0 } },
      { selector: 'node[kind="method"]', style: {
          "background-color": panel2, "border-color": accent, "border-width": 2.5, color: text } },
      { selector: 'node[kind="action"]', style: {
          "background-color": panel2, "border-color": border, "border-width": 1, color: muted } },
      // Thicker orthogonal (taxi) connectors flowing rightward, matching the
      // structured feel of the app rather than thin diagonal lines.
      { selector: "edge", style: {
          width: 2.5, "line-color": muted, "line-opacity": 0.85,
          "target-arrow-color": muted, "target-arrow-shape": "triangle", "arrow-scale": 1.3,
          "curve-style": "taxi", "taxi-direction": "rightward",
          "taxi-turn": "40px", "taxi-turn-min-distance": "6px" } },
    ],
    layout: { name: "preset", padding: 30 },
    wheelSensitivity: 0.2, autoungrabify: true, minZoom: 0.2, maxZoom: 2.5,
  });
  attackCy.ready(() => attackCy.fit(undefined, 30));
}
function closeAttackModal() {
  document.getElementById("attack-modal").classList.add("hidden");
  if (attackCy) { attackCy.destroy(); attackCy = null; }
}

function showDetails(info) {
  const body = document.getElementById("details-body");
  const isAp = info.kind === "ap";
  const prevDetailId = detailNodeId;
  detailNodeId = info.id;
  const title = isAp ? info.essid || "&lt;Hidden&gt;" : info.id;
  const clientAssociated =
    !isAp && info.associated_bssid && info.associated_bssid !== "(not associated)";
  // Offensive / enterprise actions act on a *live* radio capture, so they are
  // pointless on a static import or replay — only offer them during a live
  // airodump session (deauth additionally needs a fixed channel).
  const liveActive = live.running && live.mode === "airodump";
  let offBtn = "";
  if (live.canDeauth && isAp) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth this AP</button>`;
  } else if (live.canDeauth && clientAssociated) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth from AP</button>`;
  }

  // Enterprise (802.1X) badge is informational; its actions need a live capture.
  const enterprise = isAp && info.enterprise;
  const entBadge = enterprise
    ? `<span class="kind-badge enterprise">802.1X Enterprise</span>` : "";
  // The RADIUS cert button appears only once the helper has actually captured
  // the certificate live for this AP (it rides along in the node details).
  const certReady = enterprise && info.radius_certs && info.radius_certs.length;
  let entBtns = "";
  if (enterprise && liveActive) {
    if (certReady)
      entBtns += `<button class="btn" id="op-cert-btn">Read RADIUS cert</button>`;
    entBtns += `<button class="btn" id="op-eap-btn">Enumerate EAP methods…</button>`;
  }

  // Attack advisor is informational and static per AP, so it lives outside
  // #detail-fields (which the live tick rebuilds) — otherwise opening it would
  // snap shut on the next refresh.
  const advisor = isAp ? attackAdvisorHtml(info) : "";

  body.innerHTML = `
    <span class="kind-badge ${info.kind}">${isAp ? "Access Point" : "Client"}</span>
    ${entBadge}
    <h3>${escapeHtml(title)}</h3>
    <div id="detail-fields">${buildDetailFields(info)}</div>
    <div class="actions">
      <button class="btn" id="neighbors-btn">Highlight neighbors</button>
      <button class="btn" id="isolate-btn">Isolate</button>
      ${offBtn}
      ${entBtns}
    </div>
    <div id="enterprise-result"></div>
    ${advisor}`;

  const panel = document.getElementById("details");
  const wasHidden = panel.classList.contains("hidden");
  panel.classList.remove("hidden");
  document.getElementById("resizer-right").classList.remove("hidden");
  document.getElementById("neighbors-btn").onclick = () => highlightNeighbors(info.id);
  document.getElementById("isolate-btn").onclick = () => isolate(info.id);
  attachCopyable(body);
  const deauthBtn = document.getElementById("op-deauth-btn");
  if (deauthBtn) deauthBtn.onclick = () => openDeauthModal(info);
  const certBtn = document.getElementById("op-cert-btn");
  if (certBtn) certBtn.onclick = () => inspectCert(info);
  const eapBtn = document.getElementById("op-eap-btn");
  if (eapBtn) eapBtn.onclick = () => openEapModal(info);
  const treeBtn = document.getElementById("attack-tree-btn");
  if (treeBtn) treeBtn.onclick = () => openAttackModal(classifyTech(info));

  // On a genuinely new AP selection, flash its suggested attacks across the bar
  // (one toast per attack type) so they are noticed, not just parked in the panel.
  if (isAp && info.id !== prevDetailId) {
    const s = suggestAttacks(info);
    if (s) toastSequence(s.data.toasts, "info");
  }

  // The panel docks on the right and shrinks the graph area; reflow Cytoscape
  // into the new size and, when it just opened, keep the node beside the panel.
  requestAnimationFrame(() => {
    cy.resize();
    if (wasHidden) {
      const node = cy.getElementById(info.id);
      if (node.nonempty()) cy.animate({ center: { eles: node } }, { duration: 250 });
    }
  });
}

function closeDetails() {
  detailNodeId = null;
  document.getElementById("details").classList.add("hidden");
  document.getElementById("resizer-right").classList.add("hidden");
  requestAnimationFrame(() => cy.resize());
}

/* -------------------------------------------------------------- highlight */
function highlightNeighbors(id) {
  const node = cy.getElementById(id);
  if (node.empty()) return;
  const hood = node.closedNeighborhood();
  cy.elements().addClass("faded");
  hood.removeClass("faded").addClass("highlight");
  setTimeout(() => cy.elements().removeClass("highlight"), 1500);
}

function focusNode(id) {
  const node = cy.getElementById(id);
  if (node.empty()) return;
  cy.animate({ center: { eles: node }, zoom: 1.6 }, { duration: 400 });
  node.select();
  node.addClass("highlight");
  setTimeout(() => node.removeClass("highlight"), 1200);
}

/* --------------------------------------------------- right click → details */
// Right-click (or long-press) opens the same details panel as a left click —
// all the info and actions live in that panel, no radial menu.
cy.on("cxttap", "node", (evt) => openNode(evt.target.id()));
document.getElementById("cy").addEventListener("contextmenu", (e) => e.preventDefault());

function isolate(id) {
  const node = cy.getElementById(id);
  const keep = node.closedNeighborhood();
  cy.batch(() => {
    cy.elements().addClass("faded");
    keep.removeClass("faded");
  });
}

/* ------------------------------------------------------------------ search */
const searchInput = document.getElementById("search-input");
const searchResults = document.getElementById("search-results");
let searchTimer = null;

searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  const q = searchInput.value.trim();
  if (!q) return hideSearch();
  searchTimer = setTimeout(async () => {
    try {
      const { results } = await API.search(q);
      renderSearch(results);
    } catch (e) {
      /* ignore transient search errors */
    }
  }, 180);
});

function renderSearch(results) {
  if (!results.length) return hideSearch();
  searchResults.innerHTML = results
    .slice(0, 30)
    .map(
      (r) =>
        `<li data-id="${escapeHtml(r.id)}"><span>${escapeHtml(r.label)}</span><span class="kind">${r.kind}</span></li>`
    )
    .join("");
  searchResults.classList.remove("hidden");
  searchResults.querySelectorAll("li").forEach((li) => {
    li.onclick = () => {
      const id = li.getAttribute("data-id");
      hideSearch();
      searchInput.value = "";
      focusNode(id);
      openNode(id);
    };
  });
}

function hideSearch() {
  searchResults.classList.add("hidden");
}
document.addEventListener("click", (e) => {
  if (!e.target.closest(".search")) hideSearch();
});

/* ------------------------------------------------------------- operations */
let pendingOp = null;
// True while a live EAP enumeration is running: it writes its result into the
// details panel asynchronously (minutes), so a background tap must not close
// the panel out from under it.
let eapRunning = false;

function openDeauthModal(info) {
  // Target an AP directly, or a client off its associated AP.
  const isAp = info.kind === "ap";
  const bssid = isAp ? info.id : info.associated_bssid;
  const client = isAp ? null : info.id;
  pendingOp = { type: "deauth", bssid, client };

  const target = isAp
    ? `AP <strong>${escapeHtml(info.essid || info.id)}</strong> (${escapeHtml(info.id)})`
    : `client <strong>${escapeHtml(info.id)}</strong> off AP <strong>${escapeHtml(bssid)}</strong>`;
  const capLine = live.canDeauth
    ? `Uses the live capture interface, locked on channel <strong>${escapeHtml(live.channel)}</strong>.`
    : `<span style="color:#ffb3ba">No fixed channel airodump capture is running. Start a
       live airodump capture on a channel to enable deauth.</span>`;

  document.getElementById("op-title").textContent = "Deauthentication";
  document.getElementById("op-body").innerHTML = `
    <p>Target ${target}</p>
    <p class="hint">${capLine}</p>
    <label>Deauth bursts (1 to 64, 0 = continuous not allowed)</label>
    <input id="op-count" type="number" min="1" max="64" value="5"/>`;
  const confirm = document.getElementById("op-confirm");
  confirm.textContent = "Confirm";
  confirm.classList.add("danger");
  confirm.disabled = !live.canDeauth;
  document.getElementById("op-modal").classList.remove("hidden");
}

// Enterprise: enumerate EAP methods for an AP's ESSID (active; root + ack).
function openEapModal(info) {
  pendingOp = { type: "eap", essid: info.essid || "" };
  document.getElementById("op-title").textContent = "Enumerate EAP methods";
  document.getElementById("op-body").innerHTML = `
    <p>Probe which EAP methods <strong>${escapeHtml(info.essid || info.id)}</strong> accepts.</p>
    <p class="hint">Active 802.1X authentication (several minutes). The live
      capture is stopped first so its interface can be switched to
      <strong>managed</strong> mode for the probe. Use a legitimate identity;
      anonymous ones give unreliable results.</p>
    <label>EAP identity</label>
    <input id="op-identity" placeholder="DOMAIN\\user"/>
    <label>Interface</label>
    <input id="op-iface" value="${escapeHtml(live.iface || "")}" placeholder="wlan0"/>
    <label><input type="checkbox" id="op-dry"/> Dry run (build command only)</label>`;
  const confirm = document.getElementById("op-confirm");
  confirm.textContent = "Run";
  confirm.classList.remove("danger");
  confirm.disabled = false;
  document.getElementById("op-modal").classList.remove("hidden");
}

document.getElementById("op-cancel").onclick = () => {
  document.getElementById("op-modal").classList.add("hidden");
  pendingOp = null;
};

document.getElementById("op-confirm").onclick = () => {
  if (!pendingOp) return;
  return pendingOp.type === "eap" ? confirmEap() : confirmDeauth();
};

// Pulse a red circular halo while a deauth runs server-side, so it is clear
// something is happening. A client deauth lights the client, its AP and the link
// between them (the deauth targets that association); an AP deauth lights the AP
// and its links. Returns a stop function that ends and clears the effect.
function startDeauthFx(op) {
  let targets = cy.collection();
  if (op.client) {
    const client = cy.getElementById(op.client);
    const ap = op.bssid ? cy.getElementById(op.bssid) : cy.collection();
    if (client.nonempty()) targets = targets.union(client);
    if (ap.nonempty()) targets = targets.union(ap);
    if (client.nonempty() && ap.nonempty())
      targets = targets.union(client.edgesWith(ap));
  } else if (op.bssid) {
    const ap = cy.getElementById(op.bssid);
    if (ap.nonempty()) targets = targets.union(ap).union(ap.connectedEdges());
  }
  if (targets.empty()) return () => {};

  targets.addClass("deauthing");
  const nodes = targets.nodes();
  let stopped = false;
  (function pulse() {
    if (stopped) return;
    nodes.animate(
      { style: { "overlay-opacity": 0.6, "overlay-padding": 18 } },
      { duration: 420, easing: "ease-out-sine", complete() {
        if (stopped) return;
        nodes.animate(
          { style: { "overlay-opacity": 0.28, "overlay-padding": 8 } },
          { duration: 420, easing: "ease-in-sine", complete: pulse });
      } });
  })();

  return () => {
    stopped = true;
    nodes.stop(true);                         // stop + clear any queued pulse
    targets.removeClass("deauthing");
    nodes.removeStyle("overlay-opacity");     // clear bypass so no halo lingers
    nodes.removeStyle("overlay-padding");
  };
}

async function confirmDeauth() {
  const op = pendingOp;
  const payload = {
    bssid: op.bssid,
    client: op.client || null,
    count: Number(document.getElementById("op-count").value) || 5,
    acknowledged: true,
    dry_run: false,
  };
  // Close the dialog right away: the deauth runs server-side and can take a
  // moment, so don't leave the user staring at a frozen modal.
  document.getElementById("op-modal").classList.add("hidden");
  pendingOp = null;
  // Show progress on the deauth button in the details panel (if still open):
  // "Sending deauth" while it runs, restored to its label when done.
  const btn = document.getElementById("op-deauth-btn");
  const label = btn ? btn.textContent : "";
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Sending deauth';
  }
  const stopFx = startDeauthFx(op);   // pulse the target until the deauth ends
  try {
    const res = await API.deauth(payload);
    toast(`Deauth ${res.status}`, res.status === "ok" ? "ok" : "error");
  } catch (e) {
    toast(e.message, "error");
  } finally {
    stopFx();
    if (btn) { btn.disabled = false; btn.textContent = label; }
  }
}

async function confirmEap() {
  const identity = document.getElementById("op-identity").value.trim();
  const iface = document.getElementById("op-iface").value.trim();
  const dry = document.getElementById("op-dry").checked;
  if (!identity) return toast("Enter an EAP identity", "error");
  if (!iface) return toast("Enter an interface", "error");
  const essid = pendingOp.essid;
  document.getElementById("op-modal").classList.add("hidden");
  pendingOp = null;
  // EAP_buster drives the interface in managed mode, which fights a live monitor
  // capture. Free the radio by stopping the capture first (real runs only).
  if (!dry && live.running) {
    toast("Stopping capture to free the interface…");
    try { await stopLive({ silent: true }); } catch (e) { /* ignore */ }
  }
  const box = document.getElementById("enterprise-result");
  if (box && !dry) {
    box.innerHTML = `<p class="hint">Running EAP enumeration on ${escapeHtml(iface)}.
      This can take several minutes…</p>`;
  }
  eapRunning = !dry;   // a real run streams its result into the panel; keep it open
  try {
    const res = await API.enterpriseEap({
      essid, identity, interface: iface, acknowledged: true, dry_run: dry,
    });
    renderEap(res, dry);
  } catch (e) {
    if (box) box.innerHTML = `<p class="hint" style="color:#ffb3ba">${escapeHtml(e.message)}</p>`;
    else toast(e.message, "error");
  } finally {
    eapRunning = false;
  }
}

/* ----------------------------------------------------------- enterprise */
// The certificate is shown in a centered modal so it reads clearly.
function showCertModal(html) {
  document.getElementById("cert-modal-body").innerHTML = html;
  document.getElementById("cert-modal").classList.remove("hidden");
}

function closeCertModal() {
  document.getElementById("cert-modal").classList.add("hidden");
}

function inspectCert(info) {
  // The certificate was extracted live by the helper and rides in the node
  // details, so read it straight from there — no file, no round-trip.
  renderCert({ status: "ok", certificates: info.radius_certs || [] });
}

// Friendly names for the distinguished-name components, so you don't have to
// remember the short codes.
const DN_LABELS = {
  CN: "Common Name (CN)",
  O: "Organization (O)",
  OU: "Organizational Unit (OU)",
  C: "Country (C)",
  ST: "State / Province (ST)",
  L: "Locality (L)",
  DC: "Domain Component (DC)",
  E: "Email",
  EMAILADDRESS: "Email",
  "1.2.840.113549.1.9.1": "Email",
  SN: "Surname (SN)",
  GN: "Given Name (GN)",
  SERIALNUMBER: "Serial Number",
  "2.5.4.5": "Serial Number",
};
function dnLabel(key) {
  return DN_LABELS[key] || DN_LABELS[key.toUpperCase()] || key;
}

// Parse an RFC 4514 distinguished name ("CN=...,O=...") into {key,val} pairs,
// honouring backslash escapes (e.g. "\,").
function parseDN(dn) {
  const parts = [];
  let cur = "", esc = false;
  for (const ch of String(dn || "")) {
    if (esc) { cur += ch; esc = false; }
    else if (ch === "\\") esc = true;
    else if (ch === ",") { parts.push(cur); cur = ""; }
    else cur += ch;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => {
    const i = p.indexOf("=");
    return { key: (i >= 0 ? p.slice(0, i) : "").trim(), val: (i >= 0 ? p.slice(i + 1) : p).trim() };
  }).filter((p) => p.val);
}

// The most recently rendered certificate, kept so it can be exported.
let lastCert = null;

function renderCert(res) {
  if (res.status === "empty" || !res.certificates || !res.certificates.length) {
    lastCert = null;
    showCertModal(`<p class="hint">No certificate found. The capture may be partial,
      the AP isn't EAP-TLS in cleartext, or TLS 1.3 encrypted it.</p>`);
    return;
  }
  lastCert = res;
  const row = (k, v) =>
    v ? `<div class="detail-row"><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(v)}</span></div>` : "";
  const dnRows = (dn) => {
    const rows = parseDN(dn).map((p) => row(dnLabel(p.key), p.val)).join("");
    return rows || row("Raw", dn);
  };
  const many = res.certificates.length > 1;
  showCertModal(
    (many ? `<p class="hint">${res.certificates.length} certificates in the chain `
          + `(leaf first). Scroll to see them all.</p>` : "") +
    `<div class="cert-scroll">` +
    res.certificates
      .map((c) =>
        `<h4>Subject</h4>${dnRows(c.subject)}` +
        `<h4>Issuer</h4>${dnRows(c.issuer)}` +
        `<h4>Validity &amp; serial</h4>` +
        row("Valid from", c.not_before) + row("Valid to", c.not_after) +
        row("Serial number", c.serial))
      .join(`<hr class="cert-sep"/>`) +
    `</div>` +
    `<div class="cert-actions">
       <button class="btn" id="cert-copy">Copy text</button>
       <button class="btn" id="cert-txt">Export .txt</button>
       <button class="btn" id="cert-img">Save image</button>
     </div>`);
  document.getElementById("cert-copy").onclick = () => copyText(certToText(lastCert));
  document.getElementById("cert-txt").onclick = () => exportCertTxt(lastCert);
  document.getElementById("cert-img").onclick = () => exportCertImage(lastCert);
}

/* ------------------------------------------------- certificate export */
// A timestamped base filename so successive exports don't collide.
function certFileBase() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `radius-cert-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}` +
         `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

// Flatten a certificate result into plain, copy-pasteable text.
function certToText(res) {
  if (!res) return "";
  const lines = ["RADIUS certificate", "=".repeat(42)];
  const dnLines = (dn) => {
    const parts = parseDN(dn);
    return parts.length
      ? parts.map((p) => `  ${dnLabel(p.key)}: ${p.val}`)
      : [`  ${dn || "(none)"}`];
  };
  (res.certificates || []).forEach((c, i) => {
    if (i) lines.push("", "-".repeat(42));
    lines.push("Subject:", ...dnLines(c.subject));
    lines.push("Issuer:", ...dnLines(c.issuer));
    lines.push("Validity & serial:");
    if (c.not_before) lines.push(`  Valid from: ${c.not_before}`);
    if (c.not_after) lines.push(`  Valid to: ${c.not_after}`);
    if (c.serial) lines.push(`  Serial number: ${c.serial}`);
  });
  return lines.join("\n");
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportCertTxt(res) {
  if (!res) return;
  downloadBlob(new Blob([certToText(res)], { type: "text/plain;charset=utf-8" }),
               certFileBase() + ".txt");
  toast("Certificate exported (.txt)", "ok");
}

// Draw the certificate text onto a canvas and save it as a PNG. Rendering the
// text ourselves keeps the canvas untainted — no external capture library.
function exportCertImage(res) {
  if (!res) return;
  const lines = certToText(res).split("\n");
  const css = getComputedStyle(document.documentElement);
  const pick = (name, fallback) => (css.getPropertyValue(name) || fallback).trim();
  const bg = pick("--panel-2", "#140e0e");
  const fg = pick("--text", "#f5eaea");
  const accent = pick("--accent", "#ff2a2a");
  const scale = window.devicePixelRatio || 2;
  const pad = 24, lineH = 22, fontPx = 14;
  const font = `${fontPx}px ui-monospace, "Cascadia Mono", Menlo, Consolas, monospace`;
  const measure = document.createElement("canvas").getContext("2d");
  measure.font = font;
  let maxW = 0;
  lines.forEach((l) => { maxW = Math.max(maxW, measure.measureText(l).width); });
  const w = Math.ceil(maxW + pad * 2);
  const h = Math.ceil(lines.length * lineH + pad * 2);
  const canvas = document.createElement("canvas");
  canvas.width = w * scale;
  canvas.height = h * scale;
  const ctx = canvas.getContext("2d");
  ctx.scale(scale, scale);
  ctx.fillStyle = bg;
  ctx.fillRect(0, 0, w, h);
  ctx.font = font;
  ctx.textBaseline = "top";
  lines.forEach((l, i) => {
    ctx.fillStyle = i === 0 ? accent : fg;
    ctx.fillText(l, pad, pad + i * lineH);
  });
  canvas.toBlob((blob) => {
    if (!blob) return toast("Could not render certificate image", "error");
    downloadBlob(blob, certFileBase() + ".png");
    toast("Certificate image saved", "ok");
  }, "image/png");
}

function renderEap(res, dry) {
  const box = document.getElementById("enterprise-result");
  if (!box) return;
  if (dry || res.status === "dry-run") {
    box.innerHTML = `<h4>EAP enumeration (dry run)</h4>` +
      `<p class="hint">Would run: <code>${escapeHtml((res.command || []).join(" "))}</code></p>`;
    return;
  }
  const rank = { yes: 0, maybe: 1, no: 2 };
  const dot = (s) => (s === "yes" ? "🟢" : s === "maybe" ? "🟡" : "⚪");
  const methods = (res.methods || []).slice()
    .sort((a, b) => (rank[a.supported] ?? 3) - (rank[b.supported] ?? 3));
  box.innerHTML = `<h4>EAP methods: ${escapeHtml(res.essid || "")}</h4>` +
    methods
      .map((m) =>
        `<div class="detail-row"><span class="k">${dot(m.supported)} ${escapeHtml(m.method)}</span>` +
        `<span class="v">${escapeHtml(m.supported)}</span></div>`)
      .join("");
}

// Inspect the RADIUS certificate from an uploaded .cap (offline, no root).
document.getElementById("cert-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  showCertModal(`<p class="hint">Inspecting ${escapeHtml(file.name)}…</p>`);
  try {
    renderCert(await API.enterpriseCertUpload(file));
  } catch (err) {
    showCertModal(`<p class="hint" style="color:#ffb3ba">${escapeHtml(err.message)}</p>`);
  } finally {
    e.target.value = "";
  }
});

// Persistent: it only closes via the × button (clicking the backdrop won't
// dismiss it), so the certificate stays up while you read it.
document.getElementById("cert-modal-close").onclick = closeCertModal;

// Attack path graph: close via the × button or by clicking the backdrop.
document.getElementById("attack-modal-close").onclick = closeAttackModal;
document.getElementById("attack-modal").addEventListener("click", (e) => {
  if (e.target.id === "attack-modal") closeAttackModal();
});

/* --------------------------------------------------------------- wiring up */
async function openNode(id) {
  try {
    const info = await API.node(id);
    showDetails(info);
  } catch (e) {
    toast(e.message, "error");
  }
}

cy.on("tap", "node", (evt) => openNode(evt.target.id()));
cy.on("tap", (evt) => {
  // Tapping the empty background deselects the focused node: clear any
  // isolate/highlight fade and close the details panel on the right. Keep the
  // panel open while a live EAP enumeration is streaming its result into it.
  if (evt.target === cy) {
    cy.elements().removeClass("faded");
    if (!eapRunning) closeDetails();
  }
});

// Remember any node the user drags: the live layout then pins it in place (see
// scheduleLiveLayout) instead of pulling it back on the next discovery. The mark
// is a plain class, so it clears automatically when the node is removed / the
// graph is reloaded.
cy.on("dragfree", "node", (evt) => evt.target.addClass("user-moved"));

document.getElementById("file-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (live.running) await stopLive();   // offline import replaces any live session
  try {
    toast("Parsing capture…");
    const payload = await API.import(file);
    renderGraph(payload);
    live.loaded = true;            // a capture is now available to replay
    refreshLiveButtons();
    toast(`Loaded ${payload.summary.access_points} APs / ${payload.summary.clients} clients`, "ok");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    e.target.value = "";
  }
});

// Wipe the loaded capture from the view and the server (a fresh start).
function clearGraph() {
  cy.elements().remove();
  updateStats({});
  populateFilterOptions();
  setEmptyState(true);
  closeDetails();
  live.loaded = false;
  refreshLiveButtons();
}

document.getElementById("clear-btn").onclick = async () => {
  // Stop any live/replay session first, but keep its toast silent so the single
  // shared toast can report both the clear and where a saved capture landed.
  let saved = null;
  if (live.running) saved = await stopLive({ silent: true });
  try { await API.clear(); } catch (e) { /* ignore */ }
  clearGraph();
  toast(saved ? `Capture cleared. Saved to ${saved}` : "Capture cleared", "ok");
};

document.getElementById("details-close").onclick = closeDetails;
document.getElementById("layout-select").onchange = (e) => runLayout(e.target.value);
["filter-enc", "filter-chan"].forEach(
  (id) => document.getElementById(id).addEventListener("change", applyFilters)
);
// Clickable legend rows toggle each node type on/off.
document.querySelectorAll(".legend-toggle").forEach((btn) =>
  btn.addEventListener("click", () => { btn.classList.toggle("off"); applyFilters(); })
);

// The filters overlay auto-dims when the pointer has been away for a moment so
// it stops covering the graph; hovering it (or a fresh capture appearing) brings
// it back. A collapse button also folds it down to just its title chip.
const LEGEND_IDLE_MS = 3000;
let legendDimTimer = null;
function wakeLegend() {
  clearTimeout(legendDimTimer);
  document.getElementById("graph-legend")?.classList.remove("dimmed");
}
function armLegendDim() {
  clearTimeout(legendDimTimer);
  legendDimTimer = setTimeout(
    () => document.getElementById("graph-legend")?.classList.add("dimmed"),
    LEGEND_IDLE_MS
  );
}
const legendEl = document.getElementById("graph-legend");
if (legendEl) {
  legendEl.addEventListener("mouseenter", wakeLegend);
  legendEl.addEventListener("mouseleave", armLegendDim);
  // Keyboard users get the same treatment: keep it lit while focus is inside it
  // (e.g. tabbing through the encryption / channel / layout selects).
  legendEl.addEventListener("focusin", wakeLegend);
  legendEl.addEventListener("focusout", (e) => {
    if (!legendEl.contains(e.relatedTarget)) armLegendDim();
  });
  armLegendDim(); // fade it out even if the pointer never visits
}
const legendCollapseBtn = document.getElementById("legend-collapse");
if (legendCollapseBtn && legendEl) {
  legendCollapseBtn.addEventListener("click", () => {
    const collapsed = legendEl.classList.toggle("collapsed");
    const label = collapsed ? "Show filters" : "Hide filters";
    legendCollapseBtn.title = label;
    legendCollapseBtn.setAttribute("aria-label", label);
    legendCollapseBtn.setAttribute("aria-expanded", String(!collapsed));
  });
}

// Sidebar feature panels behave as an accordion: opening one collapses the
// others, so a single tool is expanded at a time. (Closing a panel never
// re-triggers this, so there is no toggle loop.)
const sidebarPanels = Array.from(document.querySelectorAll(".sidebar details.panel"));
sidebarPanels.forEach((d) =>
  d.addEventListener("toggle", () => {
    if (!d.open) return;
    sidebarPanels.forEach((other) => { if (other !== d && other.open) other.open = false; });
  })
);

/* ------------------------------------------------------------- live capture */
const live = { ws: null, running: false, fitDone: false, layoutTimer: null,
               mode: null, channel: null, canDeauth: false, loaded: false };

// Clients with no edges are "unassociated"; recompute after live changes.
function recomputeUnassoc() {
  cy.nodes('[kind = "client"]').forEach((n) => {
    n.data("unassociated", n.degree(false) === 0);
  });
}

// Two ways to drive the live graph share one capture session: airodump (real
// radio, via the privileged helper) and replay (offline reveal of an imported
// capture). Only one runs at a time; reflect that on both panels' buttons.
// The airodump option controls — locked while a capture is running, since
// changing them mid-capture is meaningless.
const AIRODUMP_OPT_IDS = ["live-iface", "live-iface-refresh", "live-band",
  "live-save", "live-save-path", "live-save-browse",
  "live-channel", "live-encrypt", "live-essid", "live-bssid", "live-interval"];

function setDisabled(ids, disabled) {
  ids.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.disabled = disabled;
  });
}

// -------------------------------------------------------- channel picker
// Valid channels per band. A novice shouldn't have to know these, so we offer
// them as toggle chips instead of a free-text field; the band select decides
// which set is shown. Multi-select is allowed (airodump hops across them).
const CH_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
const CH_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
  124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
const NONOVERLAP_24 = new Set([1, 6, 11]);

function channelsForBand(band) {
  if (band === "5") return CH_5;
  if (band === "both") return CH_24.concat(CH_5);
  return CH_24;   // 2.4 GHz default
}

// Mirror the chip selection into the hidden #live-channel as a comma list; ""
// means Any, which the backend reads as "scan the whole band".
function syncChannelValue() {
  const wrap = document.getElementById("live-channel-chips");
  const hidden = document.getElementById("live-channel");
  if (!wrap || !hidden) return;
  const sel = [...wrap.querySelectorAll(".chan-chip:not(.any).on")]
    .map((c) => c.dataset.ch);
  hidden.value = sel.join(",");
}

// (Re)build the chip row for the current band, resetting the selection to Any.
function renderChannelChips() {
  const wrap = document.getElementById("live-channel-chips");
  if (!wrap) return;
  const band = (document.getElementById("live-band") || {}).value || "2.4";
  let html = `<button type="button" class="chan-chip any on" data-ch="">Any</button>`;
  for (const c of channelsForBand(band)) {
    const rec = band !== "5" && NONOVERLAP_24.has(c);
    html += `<button type="button" class="chan-chip${rec ? " rec" : ""}"`
      + `${rec ? ' title="Non-overlapping 2.4 GHz channel"' : ""}`
      + ` data-ch="${c}">${c}</button>`;
  }
  wrap.innerHTML = html;
  const hint = document.getElementById("live-channel-hint");
  if (hint) hint.textContent = band === "5"
    ? "pick one or more, or Any"
    : band === "both"
      ? "both bands; 1/6/11 don't overlap"
      : "1 / 6 / 11 don't overlap";
  syncChannelValue();
}

// Chip click: "Any" clears the specific picks; a number toggles itself and
// flips Any on only when nothing specific is selected.
function onChannelChipClick(e) {
  const chip = e.target.closest(".chan-chip");
  if (!chip || chip.disabled) return;
  const wrap = document.getElementById("live-channel-chips");
  if (chip.classList.contains("any")) {
    wrap.querySelectorAll(".chan-chip.on").forEach((c) => c.classList.remove("on"));
    chip.classList.add("on");
  } else {
    chip.classList.toggle("on");
    const anySpecific = wrap.querySelector(".chan-chip:not(.any).on");
    const anyChip = wrap.querySelector(".chan-chip.any");
    if (anyChip) anyChip.classList.toggle("on", !anySpecific);
  }
  syncChannelValue();
}

const _liveBandSel = document.getElementById("live-band");
if (_liveBandSel) _liveBandSel.addEventListener("change", renderChannelChips);
const _chanChips = document.getElementById("live-channel-chips");
if (_chanChips) _chanChips.addEventListener("click", onChannelChipClick);
renderChannelChips();

function refreshLiveButtons() {
  const running = live.running, mode = live.mode;
  const capturing = running && mode === "airodump";
  const air = document.getElementById("live-toggle");
  // Dark like Replay when idle; turns red (danger) once a capture is running.
  air.textContent = capturing ? "Stop live capture" : "Start live capture";
  air.classList.toggle("danger", capturing);
  air.disabled = !OFFENSIVE || (running && mode !== "airodump");
  document.getElementById("live-dot").classList.toggle("on", capturing);
  // Lock the capture options for the duration of a live capture.
  setDisabled(AIRODUMP_OPT_IDS, capturing);
  document.querySelectorAll("#live-channel-chips .chan-chip")
    .forEach((b) => { b.disabled = capturing; });

  const rep = document.getElementById("replay-toggle");
  const replaying = running && mode === "replay";
  // With no capture loaded the button imports one; once a capture exists it
  // replays it; while replaying it stops. "primary" only in the import state,
  // to flag it as the way in.
  const importMode = !replaying && !live.loaded;
  rep.textContent = replaying ? "Stop replay" : importMode ? "Import capture" : "Replay capture";
  rep.classList.toggle("danger", replaying);
  rep.classList.toggle("primary", importMode);
  // Locked only while a live airodump capture owns the session; importing or
  // replaying is otherwise always available.
  rep.disabled = capturing;
  setDisabled(["replay-interval"], replaying);
  document.getElementById("replay-dot").classList.toggle("on", replaying);
  document.getElementById("replay-hint").textContent = replaying
    ? "Revealing the capture… press Stop to halt."
    : live.loaded
    ? "Replays the loaded capture node by node."
    : "Import an airodump CSV to enable replay.";

  // Encryption / channel filters only carry meaning for an imported capture or
  // its replay — a live airodump session doesn't populate them, so hide them
  // while one is running (the Layout filter stays available).
  const repFilters = document.getElementById("replay-filters");
  if (repFilters) repFilters.classList.toggle("hidden", capturing);
}

function setLiveUI(running) {
  live.running = running;
  refreshLiveButtons();
}

// Where to drop freshly discovered nodes: the middle of the current graph, or
// the viewport centre when it is still empty.
function liveSpawnCenter() {
  const nodes = cy.nodes(":visible");
  const box = nodes.nonempty() ? nodes.boundingBox() : cy.extent();
  return { x: (box.x1 + box.x2) / 2, y: (box.y1 + box.y2) / 2 };
}

function applyPatch(p) {
  const spawn = liveSpawnCenter();
  cy.batch(() => {
    (p.remove || []).forEach((id) => cy.remove(cy.getElementById(id)));
    (p.add || []).forEach((el) => {
      const added = cy.add(el);
      if (el.group === "nodes") {
        added.addClass("fresh");
        // Drop each new node a moderate distance from the graph centre (random
        // angle, modest radius): spread enough not to stack on one spot, close
        // enough not to fling nodes far away.
        const ang = Math.random() * Math.PI * 2;
        const rad = 120 + Math.random() * 180;
        added.position({
          x: spawn.x + Math.cos(ang) * rad,
          y: spawn.y + Math.sin(ang) * rad,
        });
      }
    });
    (p.update || []).forEach((data) => {
      const ele = cy.getElementById(data.id);
      if (ele.nonempty()) ele.data(data);
    });
  });
  recomputeUnassoc();
  applyFilters();
  if (p.summary) updateStats(p.summary);
  setEmptyState(cy.nodes().length === 0);
  setTimeout(() => cy.nodes(".fresh").removeClass("fresh"), 1600);
  // Only relayout when the graph's shape actually changed (nodes/edges added or
  // removed). A data-only update (signal, beacons…) must not reshuffle nodes the
  // user may have arranged by hand.
  const structural = (p.add && p.add.length) || (p.remove && p.remove.length);
  if (structural) scheduleLiveLayout();
  if (detailNodeId) tickDetailRefresh();   // keep the open panel's values live
}

// Re-fetch the open node's details and update its field values in place, so the
// panel stays current during a live capture without the user reopening it.
async function tickDetailRefresh() {
  const id = detailNodeId;
  if (!id) return;
  try {
    refreshDetails(await API.node(id));
  } catch (e) { /* the node may have been pruned; leave the last values */ }
}

function scheduleLiveLayout() {
  clearTimeout(live.layoutTimer);
  live.layoutTimer = setTimeout(() => {
    // Keep the existing graph where it is: pin every node that is not brand-new
    // (".fresh"), so the layout only places the just-discovered nodes around the
    // stable graph instead of reshuffling everything into a tight cluster each
    // scan. Pinning almost all nodes also keeps the layout cheap (few free
    // nodes) and, with animation off, stops it pegging the CPU during a capture.
    const pinned = cy.nodes().not(".fresh").map((n) => ({
      nodeId: n.id(), position: { x: n.position("x"), y: n.position("y") },
    }));
    const l = cy.layout({
      name: "fcose", animate: false, randomize: false,
      packComponents: false, nodeRepulsion: 16000, idealEdgeLength: 130,
      nodeSeparation: 150, gravity: 0.1, gravityRange: 3.8, fit: false, padding: 60,
      fixedNodeConstraint: pinned,
    });
    // Fit once, after the first real layout, then leave the view to the user.
    l.one("layoutstop", () => {
      if (!live.fitDone) { fitGraph(); live.fitDone = true; }
    });
    l.run();
  }, 400);
}

function handleLiveMessage(msg) {
  if (msg.type === "init") {
    cy.elements().remove();
    if (msg.elements && (msg.elements.nodes.length || msg.elements.edges.length)) {
      renderGraph(msg);
      live.fitDone = true;
    } else {
      setEmptyState(false);
    }
  } else if (msg.type === "patch") {
    applyPatch(msg);
  } else if (msg.type === "handshake") {
    markHandshake(msg);
  } else if (msg.type === "wps") {
    markWps(msg);
  } else if (msg.type === "cert") {
    markCert(msg);
  } else if (msg.type === "stopped") {
    setLiveUI(false);
  }
}

function markHandshake(msg) {
  const node = cy.getElementById(msg.bssid);
  const name = msg.essid || msg.bssid;
  if (node.nonempty()) {
    node.data("hsLabel", "🔑 " + (node.data("label") || msg.bssid));
    node.addClass("has-handshake");
  }
  celebrateCat();   // cat + key hop 5 times on every captured WPA handshake
  toast(`WPA handshake captured: ${name}`, "ok");
}

function markWps(msg) {
  const name = msg.essid || msg.bssid;
  const v = msg.version ? ` v${msg.version}` : "";
  const lock = msg.locked ? " 🔒" : "";
  toast(`WPS enabled: ${name}${v}${lock}`, "ok");
}

function markCert(msg) {
  const name = msg.essid || msg.bssid;
  toast(`RADIUS certificate captured: ${name}. Open the AP to read it.`, "ok");
}

function openLiveSocket() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/live/ws`);
  live.ws = ws;
  ws.onmessage = (ev) => {
    try { handleLiveMessage(JSON.parse(ev.data)); } catch (e) { /* ignore */ }
  };
  ws.onclose = () => { live.ws = null; };
}

// Populate the interface pick-list from the host's detected wireless adapters.
async function loadInterfaces(prefer) {
  const sel = document.getElementById("live-iface");
  // Prefer an explicitly requested interface (the one the last capture used),
  // else keep the current selection. Stops the picker snapping back to the first
  // adapter (wlan0) after a capture, when the chosen one briefly left the list.
  const want = prefer || sel.value;
  try {
    const { interfaces } = await API.interfaces();
    if (!interfaces.length) {
      sel.innerHTML = '<option value="">no wireless interface found</option>';
      return;
    }
    sel.innerHTML = interfaces
      .map((i) => `<option value="${escapeHtml(i.name)}">${escapeHtml(i.name)} (${escapeHtml(i.mode)})</option>`)
      .join("");
    if (want && interfaces.some((i) => i.name === want)) sel.value = want;
  } catch (e) {
    sel.innerHTML = '<option value="">scan failed</option>';
  }
}

async function startLive() {
  // Live capture is always a real airodump-ng capture (radio), never a CSV.
  const iface = document.getElementById("live-iface").value.trim();
  if (!iface) return toast("Select a wireless interface", "error");
  live.iface = iface;   // remember the chosen adapter so stop can reselect it
  const interval = Number(document.getElementById("live-interval").value) || 1.2;
  const channel = document.getElementById("live-channel").value.trim() || null;
  const payload = {
    mode: "airodump",
    interface: iface,
    channel,
    band: document.getElementById("live-band").value || null,
    interval,
    encrypt: document.getElementById("live-encrypt").value || null,
    essid: document.getElementById("live-essid").value.trim() || null,
    bssid: document.getElementById("live-bssid").value.trim() || null,
    save: document.getElementById("live-save").checked,
    save_path: document.getElementById("live-save-path").value.trim() || null,
    acknowledged: true,
  };
  closeDetails();   // a fresh scan: drop any stale node details from the last one
  // Enabling monitor mode (airmon-ng) takes a couple of seconds, so show a
  // spinner on the button right away — mirrors the "Stopping…" state on stop.
  const btn = document.getElementById("live-toggle");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Starting…';
  try {
    live.fitDone = false;
    const res = await API.liveStart(payload);
    live.mode = "airodump";
    live.channel = channel;
    // Deauth needs a single fixed channel; a comma list makes airodump hop.
    live.canDeauth = !!channel && channel.split(",").filter((s) => s.trim()).length === 1;
    openLiveSocket();
    setLiveUI(true);   // rewrites the button to "Stop live capture"
    const onIface =
      res.interface && res.interface !== iface ? ` on ${res.interface}` : "";
    const extra = live.canDeauth ? ` (deauth enabled, ch ${channel})` : "";
    toast(`Live capture started${onIface}${extra}`, "ok");
    loadInterfaces(); // the adapter may now report as monitor / be renamed
  } catch (e) {
    toast(e.message, "error");
    refreshLiveButtons();   // restore the "Start live capture" button on failure
  }
}

// Replay: re-feed the imported capture progressively. Offline, no root.
async function startReplay() {
  if (!live.loaded) return toast("Import a capture first", "error");
  closeDetails();   // a fresh replay: drop any stale node details from the last one
  const interval = Number(document.getElementById("replay-interval").value) || 1.2;
  try {
    live.fitDone = false;
    await API.liveStart({ mode: "replay", interval });
    live.mode = "replay";
    live.channel = null;
    live.canDeauth = false;
    openLiveSocket();
    setLiveUI(true);
    toast("Replaying capture", "ok");
  } catch (e) {
    toast(e.message, "error");
  }
}

async function stopLive(opts = {}) {
  const wasReplay = live.mode === "replay";
  // Teardown (killing airodump, restoring the interface) takes a couple of
  // seconds, so show a spinner on the button right away. setLiveUI(false) below
  // rewrites the button text and clears it.
  const btn = document.getElementById(wasReplay ? "replay-toggle" : "live-toggle");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Stopping…';
  }
  let saved = null;
  try {
    const res = await API.liveStop();
    saved = res && res.saved_path;
  } catch (e) { /* ignore */ }
  if (live.ws) { live.ws.close(); live.ws = null; }
  live.mode = null;
  live.channel = null;
  live.canDeauth = false;
  setLiveUI(false);
  if (!opts.silent) {
    if (saved) toast(`Capture saved to ${saved}`, "ok");
    else toast(wasReplay ? "Replay stopped" : "Live capture stopped", "ok");
  }
  if (OFFENSIVE && !wasReplay) {
    // The helper restores managed mode + restarts NetworkManager asynchronously
    // after we disconnect, so auto-refresh the interface list now and a few times
    // shortly after: the adapter shows back in managed mode without the user
    // having to hit "rescan" manually.
    loadInterfaces(live.iface);
    [1500, 3000, 5000].forEach((ms) => setTimeout(() => loadInterfaces(live.iface), ms));
  }
  return saved;
}

document.getElementById("live-toggle").onclick = () =>
  live.running && live.mode === "airodump" ? stopLive() : startLive();

document.getElementById("replay-toggle").onclick = () => {
  if (live.running && live.mode === "replay") return stopLive();
  // No capture yet → this button doubles as the import entry point.
  if (!live.loaded) return document.getElementById("file-input").click();
  return startReplay();
};

document.getElementById("live-iface-refresh").onclick = () => loadInterfaces();

// Show the save path field only while "Save capture file" is ticked.
const liveSaveChk = document.getElementById("live-save");
if (liveSaveChk) liveSaveChk.addEventListener("change", () =>
  document.getElementById("save-path-row").classList.toggle("hidden", !liveSaveChk.checked));

// "Save as…" asks the server to open a native Save As dialog on this machine's
// desktop (a browser can't do it), and fills the path field from what the user
// picks. Empty means cancelled or no desktop dialog available -> falls back to
// ./captures with a timestamped name.
const saveBrowseBtn = document.getElementById("live-save-browse");
if (saveBrowseBtn) saveBrowseBtn.addEventListener("click", async () => {
  saveBrowseBtn.disabled = true;
  try {
    const { path } = await API.chooseSave();
    if (path) {
      document.getElementById("live-save-path").value = path;
      toast("Save location set", "ok");
    } else {
      toast("No file chosen (or no desktop dialog available); using ./captures");
    }
  } catch (e) {
    toast(e.message, "error");
  } finally {
    saveBrowseBtn.disabled = false;
  }
});

/* -------------------------------------------------------------- resizing */
// Drag a handle to resize the panel it sits beside. The sidebar (left) grows
// as the handle moves right; the details panel (right) grows as it moves left.
// Min/max come from the panels' CSS, so the graph never collapses to nothing.
function makeResizer(handleId, panelId, side) {
  const handle = document.getElementById(handleId);
  const panel = document.getElementById(panelId);
  if (!handle || !panel) return;
  let startX = 0, startW = 0, dragging = false;

  const bound = (w) => {
    const cs = getComputedStyle(panel);
    const min = parseInt(cs.minWidth, 10) || 180;
    const max = parseInt(cs.maxWidth, 10) || 640;
    return Math.max(min, Math.min(w, max));
  };
  const onMove = (e) => {
    if (!dragging) return;
    const dx = e.clientX - startX;
    panel.style.width = bound(side === "left" ? startW + dx : startW - dx) + "px";
    cy.resize();
  };
  const onUp = () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    window.removeEventListener("mousemove", onMove);
    window.removeEventListener("mouseup", onUp);
    requestAnimationFrame(() => cy.resize());
  };
  handle.addEventListener("mousedown", (e) => {
    dragging = true;
    startX = e.clientX;
    startW = panel.getBoundingClientRect().width;
    handle.classList.add("dragging");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    e.preventDefault();
  });
}
makeResizer("resizer-left", "sidebar", "left");
makeResizer("resizer-right", "details", "right");

/* ------------------------------------------------------------------ utils */
function copyText(text) {
  navigator.clipboard?.writeText(text).then(
    () => toast("Copied to clipboard", "ok"),
    () => toast(text)
  );
}

let toastTimer = null;
function toast(msg, kind) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "toast" + (kind ? " " + kind : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 3500);
}

// Show a short series of toasts, one after another, on the bar. Each toast resets
// its own hide timer, so stepping faster than that keeps the bar continuously up
// until the last one fades. Used to surface an AP's suggested attacks.
let toastSeqTimer = null;
function toastSequence(messages, kind) {
  clearTimeout(toastSeqTimer);
  let i = 0;
  const step = () => {
    if (i >= messages.length) return;
    toast(messages[i++], kind);
    toastSeqTimer = setTimeout(step, 2600);
  };
  step();
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

/* -------------------------------------------------------------- appearance */
// User-tunable look & feel: color palette, font family, font size. Stored in
// localStorage and applied via CSS variables / a theme class on <html>.
const PREF_KEY = "wh_prefs";
const THEMES = ["hacker", "cyber", "amber", "matrix"];
const FONTS = {
  system: '"Segoe UI", Roboto, Helvetica, Arial, sans-serif',
  mono: 'ui-monospace, monospace',
  jetbrains: '"JetBrains Mono", ui-monospace, monospace',
  fira: '"Fira Code", ui-monospace, monospace',
  source: '"Source Code Pro", ui-monospace, monospace',
  cascadia: '"Cascadia Code", "Cascadia Mono", ui-monospace, monospace',
  ibmplex: '"IBM Plex Mono", ui-monospace, monospace',
  ubuntumono: '"Ubuntu Mono", ui-monospace, monospace',
  dejavumono: '"DejaVu Sans Mono", ui-monospace, monospace',
  consolas: 'Consolas, "Lucida Console", monospace',
  menlo: 'Menlo, Monaco, "Liberation Mono", monospace',
  courier: '"Courier New", Courier, monospace',
  roboto: 'Roboto, "Helvetica Neue", Arial, sans-serif',
  ubuntu: 'Ubuntu, "Segoe UI", sans-serif',
  verdana: 'Verdana, Geneva, sans-serif',
  tahoma: 'Tahoma, Geneva, sans-serif',
  trebuchet: '"Trebuchet MS", Helvetica, sans-serif',
  georgia: 'Georgia, "Times New Roman", serif',
  times: '"Times New Roman", Times, serif',
};
const SIZE_MIN = 10, SIZE_MAX = 28;
const DEFAULT_PREFS = { theme: "hacker", font: "system", size: 14 };
const prefs = { ...DEFAULT_PREFS };

function clampSize(n) {
  n = parseInt(n, 10);
  if (!Number.isFinite(n)) return DEFAULT_PREFS.size;
  return Math.max(SIZE_MIN, Math.min(SIZE_MAX, n));
}

function loadPrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(PREF_KEY) || "{}");
    if (THEMES.includes(saved.theme)) prefs.theme = saved.theme;
    if (FONTS[saved.font]) prefs.font = saved.font;
    if (saved.size != null) prefs.size = clampSize(saved.size);
  } catch (e) { /* keep defaults */ }
}

function applyPrefs() {
  const el = document.documentElement;
  THEMES.forEach((t) => el.classList.remove("theme-" + t));
  el.classList.add("theme-" + prefs.theme);
  el.style.setProperty("--font", FONTS[prefs.font]);
  // Zoom the whole document so the size setting scales EVERYTHING — text,
  // buttons, inputs, spacing — not just text. 14px is the design baseline.
  el.style.zoom = (prefs.size / 14).toFixed(4);
  if (typeof cy !== "undefined") requestAnimationFrame(() => cy.resize());
}

function savePrefs() {
  try { localStorage.setItem(PREF_KEY, JSON.stringify(prefs)); } catch (e) { /* ignore */ }
}

function syncSettingsForm() {
  document.getElementById("set-theme").value = prefs.theme;
  document.getElementById("set-font").value = prefs.font;
  document.getElementById("set-size").value = prefs.size;
  const sv = document.getElementById("set-size-val");
  if (sv) sv.textContent = prefs.size;
}

loadPrefs();
applyPrefs();   // apply before first paint work so the chosen theme shows at once

document.getElementById("settings-btn").onclick = () => {
  syncSettingsForm();
  document.getElementById("settings-modal").classList.remove("hidden");
};
document.getElementById("settings-done").onclick = () =>
  document.getElementById("settings-modal").classList.add("hidden");
document.getElementById("settings-modal").addEventListener("click", (e) => {
  if (e.target.id === "settings-modal") e.currentTarget.classList.add("hidden"); // backdrop
});
document.getElementById("set-theme").onchange = (e) => {
  prefs.theme = e.target.value; applyPrefs(); savePrefs();
};
document.getElementById("set-font").onchange = (e) => {
  prefs.font = e.target.value; applyPrefs(); savePrefs();
};
const sizeInput = document.getElementById("set-size");
const sizeVal = document.getElementById("set-size-val");
sizeInput.oninput = (e) => {                 // live preview as you drag the slider
  prefs.size = clampSize(e.target.value);
  if (sizeVal) sizeVal.textContent = prefs.size;
  applyPrefs(); savePrefs();
};
document.getElementById("settings-reset").onclick = () => {
  Object.assign(prefs, DEFAULT_PREFS);
  applyPrefs(); savePrefs(); syncSettingsForm();
};

/* ------------------------------------------------------------------ start */
(async function init() {
  try {
    const cfg = await API.config();
    OFFENSIVE = !!cfg.offensive_available;
  } catch (e) {
    // The privileged helper is required to launch, so live capture is available;
    // a transient config hiccup shouldn't hide it.
    OFFENSIVE = true;
  }
  // WiFiCatcher runs as a single mode: the privileged helper is always present,
  // so the live-capture panel is shown and the interface list is loaded.
  loadInterfaces();

  // A live/replay session that is still running should survive a reload — rejoin
  // it. Otherwise a reload starts fresh: stale imported data is discarded so the
  // page never resurrects a capture the user thought they had moved on from.
  let reconnected = false;
  try {
    const status = await API.liveStatus();
    if (status.running) {
      live.mode = status.mode;
      live.channel = status.channel;
      live.canDeauth = !!status.can_deauth;
      live.loaded = status.mode === "replay"; // a replay implies a loaded capture
      live.fitDone = false;
      openLiveSocket();            // the init snapshot rebuilds the live graph
      setLiveUI(true);
      reconnected = true;
    }
  } catch (e) {
    /* no live session to rejoin */
  }
  if (!reconnected) {
    try { await API.clear(); } catch (e) { /* ignore */ }
    setEmptyState(true);
  }
  refreshLiveButtons();            // set initial button/enabled state
})();
