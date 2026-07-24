/* WiFiCatcher frontend: Cytoscape graph and interaction. */
"use strict";

const API = {
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
  eapStart: (payload) =>
    fetchJSON("/api/operations/enterprise/eap-methods/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  eapStatus: () => fetchJSON("/api/operations/enterprise/eap-methods/status"),
  eapStop: () => fetchJSON("/api/operations/enterprise/eap-methods/stop", { method: "POST" }),
  eapIdentitiesAll: () => fetchJSON("/api/operations/enterprise/eap-identities"),
  ensureMonitor: (iface) =>
    fetchJSON("/api/live/monitor", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface }),
    }),
  liveStopForEap: (iface) =>
    fetchJSON("/api/live/stop-for-eap", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ interface: iface }),
    }),
  liveStart: (payload) =>
    fetchJSON("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  liveStop: () => fetchJSON("/api/live/stop", { method: "POST" }),
  interfaces: () => fetchJSON("/api/live/interfaces"),
  fsList: (path) =>
    fetchJSON("/api/fs/list" + (path ? "?path=" + encodeURIComponent(path) : "")),
  // Read a file the user picked with the in-app browser, straight off disk.
  importLocal: (path) =>
    fetchJSON("/api/import/local", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    }),
  certLocal: (path, bssid) =>
    fetchJSON("/api/operations/enterprise/cert/local", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, ap_bssid: bssid || null }),
    }),
  eapIdentityLocal: (path, bssid) =>
    fetchJSON("/api/operations/enterprise/eap-identity/local", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, ap_bssid: bssid || null }),
    }),
  enterpriseCert: (payload) =>
    fetchJSON("/api/operations/enterprise/cert", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
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
        // SVG glyphs floating on the canvas: no fill/clip; border stays invisible
        // until a status class colours it (selected / fresh / handshake / enterprise).
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
    // Per-encryption AP icons. Order matters: enterprise is last so an 802.1X AP
    // keeps its purple waves even when its privacy also matches WPA3.
    {
      selector: 'node[kind = "ap"][privacy *= "WEP"]',
      style: { "background-image": "/static/img/node-ap-wep.svg?v=1" },
    },
    {
      selector: 'node[kind = "ap"][privacy *= "OPN"]',
      style: { "background-image": "/static/img/node-ap-open.svg?v=1" },
    },
    {
      selector: 'node[kind = "ap"][privacy *= "WPA3"]',
      style: { "background-image": "/static/img/node-ap-wpa3.svg?v=1" },
    },
    {
      selector: 'node[kind = "ap"][?enterprise]',
      style: { "background-image": "/static/img/node-ap-enterprise.svg?v=1" },
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
    // Only on the hidden->visible transition (a capture just appeared): running it
    // every setEmptyState would re-arm the dim timer each patch (~1.2s < 3s) and never dim.
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

// Canonical WiFi technology token for an AP. Pure WPA3 (SAE only) is kept
// distinct from a WPA2/WPA3 transition network, since they don't share attacks.
function apTech(d) {
  const priv = (d.privacy || "").toUpperCase();
  if (d.enterprise || priv.includes("MGT")) return "enterprise";
  if (priv.includes("WEP")) return "wep";
  const wpa3 = priv.includes("WPA3");
  const wpa2 = priv.includes("WPA2") || (priv.includes("WPA") && !wpa3);
  if (wpa3 && wpa2) return "wpa2-wpa3";
  if (wpa3) return "wpa3";
  if (priv.includes("WPA")) return "wpa-psk";
  if (priv.includes("OPN") || priv.includes("OPEN")) return "open";
  return "unknown";
}

const TECH_LABEL = {
  enterprise: "WPA2-Enterprise", wep: "WEP", wpa3: "WPA3",
  "wpa2-wpa3": "WPA2/WPA3", "wpa-psk": "WPA/WPA2-PSK", open: "Open",
};
const TECH_BADGE_CLASS = {
  enterprise: "ent", wep: "wep", wpa3: "wpa3", "wpa-psk": "psk", open: "open",
};

// User-facing technology label for the graph filter (groups real technology
// instead of the raw airodump privacy string).
function apTechLabel(d) {
  const t = apTech(d);
  return t === "unknown" ? (d.privacy || "Unknown") : TECH_LABEL[t];
}

// The coloured badge(s) for the detail panel. A WPA2/WPA3 network gets two.
function techTags(info) {
  const t = apTech(info);
  if (t === "wpa2-wpa3") return [{ label: "WPA2", cls: "wpa3" }, { label: "WPA3", cls: "wpa3" }];
  if (t === "unknown") return [{ label: info.privacy || "Unknown", cls: "psk" }];
  return [{ label: TECH_LABEL[t], cls: TECH_BADGE_CLASS[t] }];
}

// The ATTACK_DATA keys that apply to an AP. WPA2/WPA3 gets both WPA2 and WPA3.
function techKeysFor(info) {
  if (!info || info.kind !== "ap") return [];
  const t = apTech(info);
  if (t === "wpa2-wpa3") return ["wpa-psk", "wpa3"];
  if (t === "enterprise") return ["wpa-enterprise"];
  return ["wep", "wpa3", "wpa-psk", "open"].includes(t) ? [t] : [];
}

// [{key, data}] of every attack-data set that applies to this AP.
function attackDataFor(info) {
  return techKeysFor(info)
    .map((k) => (ATTACK_DATA[k] ? { key: k, data: ATTACK_DATA[k] } : null))
    .filter(Boolean);
}

// Selected values per multi-select filter; an empty set means "show all".
const filterSel = {
  "filter-enc": new Set(),
  "filter-chan": new Set(),
  "filter-essid": new Set(),
  "filter-bssid": new Set(),
};

function populateFilterOptions() {
  const encs = new Set();
  const chans = new Set();
  const essids = new Set();
  const bssids = new Set();
  cy.nodes('[kind = "ap"]').forEach((n) => {
    encs.add(apTechLabel(n.data()));
    if (n.data("channel")) chans.add(String(n.data("channel")));
    if (n.data("essid")) essids.add(n.data("essid"));
    bssids.add(n.id());
  });
  fillMultiSelect("filter-enc", [...encs].sort());
  fillMultiSelect("filter-chan", [...chans].sort((a, b) => Number(a) - Number(b)));
  fillMultiSelect("filter-essid", [...essids].sort());
  fillMultiSelect("filter-bssid", [...bssids].sort());
}

// Build a checkbox dropdown for one filter, keeping any still-valid selections.
// The label shows "all" when nothing is picked, or "N selected" otherwise.
function fillMultiSelect(id, values) {
  const host = document.getElementById(id);
  if (!host) return;
  // Rebuilding replaces the trigger/menu nodes; drop any open-menu state on them.
  if (openMs && host.contains(openMs.menu)) closeMs();
  const sel = filterSel[id];
  [...sel].forEach((v) => { if (!values.includes(v)) sel.delete(v); });
  const opts = values
    .map(
      (v) =>
        `<label class="ms-opt"><input type="checkbox" value="${escapeHtml(v)}"${
          sel.has(v) ? " checked" : ""
        }/><span>${escapeHtml(v)}</span></label>`
    )
    .join("");
  host.innerHTML =
    `<button type="button" class="ms-trigger"></button>` +
    `<div class="ms-menu hidden">${opts || '<p class="ms-empty">none</p>'}</div>`;
  const trigger = host.querySelector(".ms-trigger");
  const menu = host.querySelector(".ms-menu");
  const sync = () => {
    trigger.textContent = sel.size === 0 ? "all" : `${sel.size} selected`;
    trigger.classList.toggle("active", sel.size > 0);
  };
  menu.addEventListener("click", (e) => e.stopPropagation());
  host.querySelectorAll(".ms-opt input").forEach((cb) => {
    cb.onchange = () => {
      if (cb.checked) sel.add(cb.value); else sel.delete(cb.value);
      sync();
      applyFilters();
    };
  });
  trigger.onclick = (e) => {
    e.stopPropagation();
    const wasOpen = openMs && openMs.menu === menu;
    closeMs();
    if (wasOpen) return;      // clicking the open trigger just closes it
    openMs = { menu, trigger };
    menu.classList.remove("hidden");
    positionMs();
  };
  sync();
}

// The dropdown currently open (menu + trigger), or null. Scrolling repositions the
// fixed menu rather than closing it (closing on scroll swallowed mid-scroll clicks).
let openMs = null;
function closeMs() {
  if (!openMs) return;
  openMs.menu.classList.add("hidden");
  openMs = null;
}
function positionMs() {
  if (!openMs) return;
  // Anchor the fixed menu under the trigger so it floats over the panel edge
  // instead of being clipped by the panel's own scroll box.
  const r = openMs.trigger.getBoundingClientRect();
  openMs.menu.style.left = `${r.left}px`;
  openMs.menu.style.top = `${r.bottom + 4}px`;
  openMs.menu.style.minWidth = `${r.width}px`;
}
document.addEventListener("click", closeMs);
document.addEventListener("scroll", positionMs, true);
window.addEventListener("resize", positionMs);

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
  // A node passes a filter when its set is empty (all) or contains its value.
  const encs = filterSel["filter-enc"];
  const chans = filterSel["filter-chan"];
  const essids = filterSel["filter-essid"];
  const bssids = filterSel["filter-bssid"];

  cy.batch(() => {
    cy.nodes().forEach((n) => {
      const kind = n.data("kind");
      let show = true;
      if (kind === "ap") {
        if (!showAps) show = false;
        if (encs.size && !encs.has(apTechLabel(n.data()))) show = false;
        if (chans.size && !chans.has(String(n.data("channel")))) show = false;
        if (essids.size && !essids.has(n.data("essid"))) show = false;
        if (bssids.size && !bssids.has(n.id())) show = false;
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
// Sortable, searchable table alternative to the graph, read straight from the live
// Cytoscape model so it tracks live updates and honours the same legend filters (.hidden-node).
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
    render: (n) => cellOr(n.data("privacy")) },
  { key: "cipher", label: "Cipher",
    val: (n) => (n.data("cipher") || "").toLowerCase(),
    render: (n) => cellOr(n.data("cipher")) },
  { key: "authentication", label: "Auth",
    val: (n) => (n.data("authentication") || "").toLowerCase(),
    render: (n) => cellOr(n.data("authentication")) },
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
  // The node details panel belongs to the graph; switching to the table closes
  // it (clicking a table row reopens it for that node).
  if (isTable) closeDetails();
  document.getElementById("table-view").classList.toggle("hidden", !isTable);
  document.querySelectorAll(".vt-btn").forEach((b) =>
    b.classList.toggle("active", b.dataset.view === currentView));
  // The node search overlay navigates the canvas, so it is graph-only; the table has
  // its own row filter. Hide it in table view (and when empty) and close the dropdown.
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

// Just the field rows (+ probed ESSIDs), kept separate so a live capture can refresh
// values in place without rebuilding the action buttons a running op may be driving.
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
    row("WPS", info.wps ? (info.wps_version || "Yes") : "Not detected");
    if (info.wps) row("WPS locked", info.wps_locked ? "Yes" : "No");
    // EAP Response/Identity usernames captured live for this enterprise AP; one
    // click-to-copy row each so a domain user can be grabbed directly.
    if (info.eap_identities && info.eap_identities.length) {
      const names = [...new Set(info.eap_identities.map((e) => e.identity))];
      names.forEach((n) => rowCopy("EAP identity", n));
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

// Refresh only the open panel's field values in place, leaving the action buttons
// untouched so a running op's button state survives.
function refreshDetails(info) {
  if (!info || info.id !== detailNodeId) return;
  const fields = document.getElementById("detail-fields");
  if (!fields) return;
  fields.innerHTML = buildDetailFields(info);
  attachCopyable(fields);
}

// Attack advisor content per WiFi security type: an attack tree as flat nodes with
// parent pointers, rendered as the panel list and, on demand, a graph.
const ATTACK_DATA = {
  "wpa-psk": {
    family: "WPA/WPA2-PSK",
    nodes: [
      {"id": "root", "parent": null, "label": "WPA/WPA2-PSK", "kind": "root"},
      {"id": "g_psk", "parent": "root", "label": "Offline Cracking", "kind": "goal"},
      {"id": "hs", "parent": "g_psk", "label": "4-way handshake capture and crack", "kind": "attack", "desc": "Capture the 4-way handshake when a client connects, or force it with deauth packets, then crack the password offline."},
      {"id": "pmkid", "parent": "g_psk", "label": "PMKID capture and crack", "kind": "attack", "desc": "Capture the PMKID when a client connects, via deauth, or by exploiting vulnerable routers with a single association request using hcxdumptool, then crack it offline."},
      {"id": "g_wps", "parent": "root", "label": "WPS", "kind": "goal"},
      {"id": "wps_online", "parent": "g_wps", "label": "Online PIN brute force", "kind": "attack", "desc": "An interactive attack that keeps trying WPS PINs against the access point until it finds the valid one, using a tool such as Reaver."},
      {"id": "wps_pixie", "parent": "g_wps", "label": "Offline Pixie Dust", "kind": "attack", "desc": "Exploits weak random values in the WPS setup exchange to recover the PIN offline in seconds, using a tool such as pixiewps."},
    ],
  },
  "wep": {
    family: "WEP (Wired Equivalent Privacy)",
    nodes: [
      {"id": "root", "parent": null, "label": "WEP", "kind": "root"},
      {"id": "g_ivs", "parent": "root", "label": "Collect IVs", "kind": "goal"},
      {"id": "arp", "parent": "g_ivs", "label": "ARP request replay", "kind": "attack", "desc": "Captures one encrypted ARP request and rebroadcasts it repeatedly, making the access point emit many fresh initialization vectors for cracking."},
      {"id": "frag", "parent": "g_ivs", "label": "Fragmentation attack", "kind": "attack", "desc": "Uses a small recovered keystream to send fragmented packets, tricking the access point into revealing enough keystream to forge traffic."},
      {"id": "chop", "parent": "g_ivs", "label": "ChopChop attack", "kind": "attack", "desc": "Repeatedly strips and guesses the last encrypted byte of a captured packet, gradually recovering its keystream without knowing the WEP key."},
      {"id": "g_client", "parent": "root", "label": "Attack a client", "kind": "goal"},
      {"id": "caffe", "parent": "g_client", "label": "Caffe Latte attack", "kind": "attack", "desc": "Targets a lone client away from its network, replaying modified ARP packets so it generates traffic exposing its stored WEP key."},
      {"id": "g_crack", "parent": "root", "label": "Crack the key", "kind": "goal"},
      {"id": "korek", "parent": "g_crack", "label": "KoreK statistical crack", "kind": "attack", "desc": "Analyzes many collected initialization vectors and applies statistical correlations to recover the WEP key faster than trying every possibility."},
      {"id": "brute", "parent": "g_crack", "label": "Brute force key crack", "kind": "attack", "desc": "Systematically tries every possible key against captured traffic until one correctly decrypts it, revealing the WEP key."},
    ],
  },
  "wpa-enterprise": {
    family: "WPA2-Enterprise",
    nodes: [
      {"id": "root", "parent": null, "label": "WPA2-Enterprise", "kind": "root"},
      {"id": "g_guess", "parent": "root", "label": "Guess the password", "kind": "goal"},
      {"id": "spray", "parent": "g_guess", "label": "Password spraying or bruteforcing", "kind": "attack", "desc": "The attacker tries common passwords across many accounts or many passwords against one, hoping weak credentials eventually grant network access."},
      {"id": "g_twin", "parent": "root", "label": "Evil twin", "kind": "goal"},
      {"id": "mschap", "parent": "g_twin", "label": "Capture and crack MSCHAPv2", "kind": "attack", "desc": "A rogue access point with a fake authentication server captures the MSCHAPv2 challenge and response, letting the password be cracked offline."},
      {"id": "downgrade", "parent": "g_twin", "label": "EAP downgrade", "kind": "attack", "desc": "The rogue access point pushes the client to negotiate a weaker EAP method, exposing credentials that a stronger method would protect."},
      {"id": "peap", "parent": "g_twin", "label": "PEAP relay", "kind": "attack", "desc": "The attacker relays PEAP messages between the victim and the real server, hijacking the session to gain authenticated network access."},
      {"id": "g_method", "parent": "root", "label": "Break the EAP method", "kind": "goal"},
      {"id": "eaptls", "parent": "g_method", "label": "EAP TLS certificate attack", "kind": "attack", "desc": "The attacker presents a fraudulent server certificate that clients fail to verify, tricking them into trusting a malicious authentication server."},
      {"id": "eapmd5", "parent": "g_method", "label": "EAP MD5 capture and crack", "kind": "attack", "desc": "The attacker sniffs the EAP MD5 challenge and hashed response, then cracks it offline since this method lacks server authentication."},
    ],
  },
  "open": {
    family: "Open network",
    nodes: [
      {"id": "root", "parent": null, "label": "Open network", "kind": "root"},
      {"id": "g_access", "parent": "root", "label": "Get onto the network", "kind": "goal"},
      {"id": "cpbypass", "parent": "g_access", "label": "Captive portal bypass", "kind": "attack", "desc": "A captive portal only gates internet access, so spoofing the MAC of an already-authorised client (or tunnelling over DNS / ICMP) slips past the login page and onto the network, opening the way to the impersonation attacks below."},
      {"id": "g_imp", "parent": "root", "label": "Impersonate the network", "kind": "goal"},
      {"id": "twin", "parent": "g_imp", "label": "Evil twin", "kind": "attack", "desc": "The attacker broadcasts a fake access point, cloning the network name or using an inviting one, so devices connect and their traffic is intercepted."},
      {"id": "portal", "parent": "twin", "label": "Captive portal phishing", "kind": "attack", "desc": "A fake login page appears after connecting, tricking users into entering passwords or personal details that the attacker quietly steals."},
      {"id": "mitm", "parent": "twin", "label": "Man in The Middle", "kind": "attack", "desc": "The attacker reroutes the victim's traffic through their own device, letting them read or alter data while both sides suspect nothing."},
    ],
  },
  "wpa3": {
    family: "WPA3",
    nodes: [
      {"id": "root", "parent": null, "label": "WPA3", "kind": "root"},
      {"id": "g_soon", "parent": "root", "label": "Coming soon", "kind": "goal"},
    ],
  },
};

// One line about this AP's own WPS state, shown for WPA/WPA2 PSK.
function wpsNote(info) {
  if (!info.wps) return "";
  return info.wps_locked
    ? "WPS is enabled but locked on this AP, so the WPS PIN brute-force is likely blocked."
    : "Given that WPS is enabled, a WPS PIN brute-force attack should be the primary exploitation attempt on this AP.";
}

// The "Suggested attacks" panel block for an AP (or "" when nothing applies),
// mirroring the attack path graph: one block per category, then its attacks.
function attackAdvisorHtml(info) {
  const datas = attackDataFor(info);
  if (!datas.length) return "";
  // Each attack is its own little "bubble" card with its name and description.
  const card = (a) =>
    `<div class="atk-card"><span class="atk-name">${escapeHtml(a.label)}</span>` +
    (a.desc ? `<span class="atk-desc">${escapeHtml(a.desc)}</span>` : "") + `</div>`;
  // One family block (title, its categories and attacks) per applicable
  // technology — a WPA2/WPA3 network shows both the WPA2 and the WPA3 block.
  const blocks = datas.map(({ key, data }) => {
    const nodes = data.nodes;
    const root = nodes.find((n) => n.parent === null) || nodes[0];
    const childrenOf = (id) => nodes.filter((n) => n.parent === id);
    // Chained attacks (e.g. captive portal under evil twin) stay nested.
    const renderTree = (pid) => childrenOf(pid).filter((n) => n.kind === "attack").map((c) => {
      const inner = renderTree(c.id);
      return card(c) + (inner ? `<div class="atk-children">${inner}</div>` : "");
    }).join("");
    const cats = childrenOf(root.id).filter((n) => n.kind === "goal").map((cat) =>
      `<p class="advisor-cat-name">${escapeHtml(cat.label)}</p>${renderTree(cat.id)}`
    ).join("");
    const note = key === "wpa-psk" ? wpsNote(info) : "";
    const noteHtml = note ? `<p class="advisor-wps">${escapeHtml(note)}</p>` : "";
    return `<p class="advisor-family">${escapeHtml(data.family)}</p>${noteHtml}${cats}`;
  }).join("");
  return `<details class="subpanel attack-advisor">
    <summary>Common attacks</summary>
    <div class="panel-body">
      ${blocks}
      <button class="btn" id="attack-tree-btn">View attack paths</button>
      <p class="advisor-note">Guidance only. Use exclusively on networks you are authorized to test.</p>
    </div>
  </details>`;
}

// Render the attack tree as an on-demand Cytoscape graph in a modal — a fresh
// instance per open, destroyed on close so it never competes with the live graph.
let attackCy = null;
function _cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
}
function openAttackModal(info) {
  const datas = attackDataFor(info);
  if (!datas.length || typeof cytoscape === "undefined") return;
  document.getElementById("attack-modal-title").textContent =
    "Attack paths: " + datas.map((d) => d.data.family).join(" / ");
  // Left-to-right tidy tree: x by depth, y packed by leaves (parent at children's
  // midpoint). Multiple techs stack vertically; ids namespaced by tech so roots don't collide.
  const XS = 300, YS = 72;
  const elements = [];
  let yOffset = 0;
  for (const { key, data } of datas) {
    const nodes = data.nodes;
    const root = nodes.find((n) => n.parent === null) || nodes[0];
    const kids = {};
    for (const n of nodes) if (n.parent) (kids[n.parent] = kids[n.parent] || []).push(n.id);
    const pos = {};
    let leaf = 0;
    (function place(id, depth) {
      const cs = kids[id] || [];
      if (!cs.length) { pos[id] = { x: depth * XS, y: leaf++ * YS }; return; }
      cs.forEach((c) => place(c, depth + 1));
      const ys = cs.map((c) => pos[c].y);
      pos[id] = { x: depth * XS, y: (Math.min(...ys) + Math.max(...ys)) / 2 };
    })(root.id, 0);
    const nid = (id) => key + ":" + id;
    let maxY = yOffset;
    for (const n of nodes) {
      const p = { x: pos[n.id].x, y: pos[n.id].y + yOffset };
      if (p.y > maxY) maxY = p.y;
      elements.push({ data: { id: nid(n.id), label: n.label, kind: n.kind }, position: p });
      if (n.parent) elements.push({ data: { id: nid(n.parent) + ">" + nid(n.id), source: nid(n.parent), target: nid(n.id) } });
    }
    yOffset = maxY + YS * 2;   // gap before the next technology's tree
  }
  document.getElementById("attack-modal").classList.remove("hidden");
  if (attackCy) { attackCy.destroy(); attackCy = null; }
  const accent = _cssVar("--accent"), client = _cssVar("--client"),
    panel2 = _cssVar("--panel-2"),
    text = _cssVar("--text"), muted = _cssVar("--muted"),
    font = _cssVar("--font") || "inherit",
    onColor = _cssVar("--btn-primary-text") || "#0b0f12";
  attackCy = cytoscape({
    container: document.getElementById("attack-graph"),
    elements,
    style: [
      { selector: "node", style: {
          label: "data(label)", "font-family": font, "text-wrap": "wrap",
          "text-max-width": "150px", "font-size": "12px", color: text,
          "text-valign": "center", "text-halign": "center",
          "background-color": panel2, "background-opacity": 1,
          "border-width": 2, "border-color": accent,
          shape: "round-rectangle", width: "label", height: "label", padding: "11px" } },
      // The target sits on the left, filled. Category nodes (goals) are filled in
      // the client blue; the concrete attacks keep the accent outline.
      { selector: 'node[kind="root"]', style: {
          "background-color": accent, color: onColor, "font-weight": "bold", "border-width": 0 } },
      { selector: 'node[kind="goal"]', style: {
          "background-color": client, color: onColor, "font-weight": "bold", "border-width": 0 } },
      // Thin orthogonal (taxi) connectors flowing rightward: the structured tree
      // look preferred over fat diagonal arrows.
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
  detailNodeId = info.id;
  const title = isAp ? info.essid || "&lt;Hidden&gt;" : info.id;
  const clientAssociated =
    !isAp && info.associated_bssid && info.associated_bssid !== "(not associated)";
  // Offensive / enterprise actions need a *live* airodump session, not a static
  // import or replay (deauth additionally needs a fixed channel).
  const liveActive = live.running && live.mode === "airodump";
  let offBtn = "";
  if (live.canDeauth && isAp) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth this AP</button>`;
  } else if (live.canDeauth && clientAssociated) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth from AP</button>`;
  }

  // Enterprise (802.1X) actions need a live capture.
  const enterprise = isAp && info.enterprise;
  // A technology badge on every AP (coloured to match its icon), so enterprise
  // is not the only kind that gets a tag.
  const techBadge = isAp
    ? techTags(info).map((t) =>
        `<span class="tech-badge tech-${t.cls}">${escapeHtml(t.label)}</span>`).join("")
    : "";
  // The RADIUS cert button appears only once the warden has actually captured
  // the certificate live for this AP (it rides along in the node details).
  const certReady = enterprise && info.radius_certs && info.radius_certs.length;
  // RADIUS cert button appears only once the warden has captured it live for
  // this AP. EAP enumeration is a standalone tool in the Enterprise panel.
  const entBtns = certReady
    ? `<button class="btn" id="op-cert-btn">Read RADIUS cert</button>` : "";

  // Attack advisor is static per AP, so it lives outside #detail-fields (which the
  // live tick rebuilds) — otherwise opening it would snap shut on the next refresh.
  const advisor = isAp ? attackAdvisorHtml(info) : "";

  body.innerHTML = `
    <span class="kind-badge ${info.kind}">${isAp ? "Access Point" : "Client"}</span>
    ${techBadge}
    <h3>${escapeHtml(title)}</h3>
    <div id="detail-fields">${buildDetailFields(info)}</div>
    <div class="actions">
      <button class="btn" id="neighbors-btn">Highlight neighbors</button>
      <button class="btn" id="isolate-btn">Isolate</button>
      ${offBtn}
      ${entBtns}
    </div>
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
  const treeBtn = document.getElementById("attack-tree-btn");
  if (treeBtn) treeBtn.onclick = () => openAttackModal(info);

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
// True while a live EAP enumeration is running: it writes into the details panel
// asynchronously (minutes), so a background tap must not close the panel.
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

document.getElementById("op-cancel").onclick = () => {
  document.getElementById("op-modal").classList.add("hidden");
  pendingOp = null;
};

document.getElementById("op-confirm").onclick = () => {
  if (pendingOp) confirmDeauth();
};

// Pulse a red halo while a deauth runs server-side: a client deauth lights the client,
// its AP and their link; an AP deauth lights the AP and its links. Returns a stop fn.
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

/* -------------------------------------------------------- EAP enumeration */
// Standalone Enterprise tool: pick an interface, SSID and domain user, then
// probe which EAP methods the AP accepts (live, streamed).

// Populate the interface picker, preferring a running capture's monitor vif.
// data-mode carries each mode so run() knows whether to switch to monitor first.
async function fillEapInterfaces() {
  const sel = document.getElementById("eap-iface");
  if (!sel) return;
  const prefer = live.monitorIface;
  const current = sel.value;   // keep the user's pick across refreshes if still present
  try {
    const { interfaces } = await API.interfaces();
    if (!interfaces.length) {
      sel.innerHTML = '<option value="">no wireless interface found</option>';
      return;
    }
    sel.innerHTML = interfaces.map((i) => {
      const cap = i.name === prefer ? ", in capture" : "";
      return `<option value="${escapeHtml(i.name)}" data-mode="${escapeHtml(i.mode)}">` +
        `${escapeHtml(i.name)} (${escapeHtml(i.mode)}${cap})</option>`;
    }).join("");
    const pick = interfaces.find((i) => i.mode === "monitor")
      || interfaces.find((i) => i.mode === "managed") || interfaces[0];
    sel.value = (current && interfaces.some((i) => i.name === current)) ? current
      : (prefer && interfaces.some((i) => i.name === prefer)) ? prefer : pick.name;
  } catch (e) {
    sel.innerHTML = '<option value="">scan failed</option>';
  }
}

// Captured identities as clickable chips that fill the domain-user field.
async function fillEapIdentitySuggestions() {
  const box = document.getElementById("eap-id-suggest");
  if (!box) return;
  let ids = [];
  try { ids = (await API.eapIdentitiesAll()).identities || []; } catch (e) { ids = []; }
  if (!ids.length) { box.innerHTML = ""; return; }
  box.innerHTML =
    `<p class="hint eapid-suggest-label">Captured identities (click to use):</p>` +
    `<div class="eapid-chips">${ids.map((n) =>
      `<button type="button" class="eapid-chip" data-id="${escapeHtml(n)}">${escapeHtml(n)}</button>`).join("")}</div>`;
  box.querySelectorAll(".eapid-chip").forEach((b) => {
    b.onclick = () => { document.getElementById("eap-identity").value = b.dataset.id; };
  });
}

function refreshEapPanel() {
  fillEapInterfaces();
  fillEapIdentitySuggestions();
}

async function runEapEnum() {
  const sel = document.getElementById("eap-iface");
  const iface = sel ? sel.value.trim() : "";
  const essid = document.getElementById("eap-essid").value.trim();
  const identity = document.getElementById("eap-identity").value.trim();
  if (!iface) return toast("Select an interface", "error");
  if (!essid) return toast("Enter the SSID", "error");
  if (!identity) return toast("Enter a domain user (DOMAIN\\user)", "error");
  const box = document.getElementById("eap-enum-result");
  const fail = (msg) => {
    eapRunning = false;
    setEapButtonBusy(false);
    if (box) box.innerHTML = `<p class="hint" style="color:#ffb3ba">${escapeHtml(msg)}</p>`;
  };
  eapRunning = true;
  setEapButtonBusy(true);
  // EAP_buster needs the adapter in monitor mode (NM-free). If it's the live capture's
  // monitor vif, stop keeping monitor; else switch to monitor if not already.
  let monIface = iface;
  try {
    if (live.running && iface === live.monitorIface) {
      toast("Stopping capture, keeping monitor mode for EAP…");
      await stopLive({ silent: true, eapBase: live.iface });
      monIface = live.eapMonitorIface || iface;
    } else if (!sel.selectedOptions[0] || sel.selectedOptions[0].dataset.mode !== "monitor") {
      toast("Enabling monitor mode…");
      monIface = (await API.ensureMonitor(iface)).interface || iface;
    }
    await API.eapStart({ essid, identity, interface: monIface, acknowledged: true });
  } catch (e) {
    return fail(e.message);
  }
  clearTimeout(eapPollTimer);
  pollEap(essid, monIface, Date.now(), 0);
}

// Toggle the "Enumerate EAP methods" button between idle and a disabled, spinning
// "Enumerating EAP methods…" state, revealing the Stop button while it runs.
function setEapButtonBusy(busy) {
  const btn = document.getElementById("eap-run-btn");
  if (btn) {
    btn.disabled = busy;
    btn.innerHTML = busy
      ? '<span class="spinner"></span>Enumerating EAP methods…'
      : "Enumerate EAP methods";
  }
  const stop = document.getElementById("eap-stop-btn");
  if (stop) stop.classList.toggle("hidden", !busy);
}

// Cancel a running EAP enumeration: stop polling, reset the UI, and tell the
// backend to close the stream (which makes the warden kill EAP_buster).
async function stopEapEnum() {
  clearTimeout(eapPollTimer);
  eapRunning = false;
  setEapButtonBusy(false);
  const box = document.getElementById("eap-enum-result");
  if (box) box.innerHTML = `<p class="hint">Enumeration stopped.</p>`;
  try { await API.eapStop(); } catch (e) { /* best effort */ }
  toast("EAP enumeration stopped", "ok");
}

let eapPollTimer = null;
// Poll the streaming enumeration, painting each method as EAP_buster resolves it.
async function pollEap(essid, iface, t0, fails) {
  let st;
  try {
    st = await API.eapStatus();
  } catch (e) {
    const box = document.getElementById("eap-enum-result");
    if (fails >= 4) {   // give up after a few consecutive poll failures
      eapRunning = false;
      setEapButtonBusy(false);
      if (box) box.innerHTML = `<p class="hint" style="color:#ffb3ba">${escapeHtml(e.message)}</p>`;
      return;
    }
    eapPollTimer = setTimeout(() => pollEap(essid, iface, t0, fails + 1), 2500);
    return;
  }
  if (!st.done) {
    renderEapLive(st, iface, essid, t0);
    eapPollTimer = setTimeout(() => pollEap(essid, iface, t0, 0), 2500);
    return;
  }
  eapRunning = false;
  setEapButtonBusy(false);
  if (st.error) {
    const box = document.getElementById("eap-enum-result");
    if (box) box.innerHTML = `<p class="hint" style="color:#ffb3ba">${escapeHtml(st.error)}</p>`;
    else toast(st.error, "error");
  } else {
    renderEap({ status: "ok", essid, methods: st.methods });
  }
}

// The in-progress panel: spinner, elapsed clock, count, and the methods so far.
function renderEapLive(st, iface, essid, t0) {
  const box = document.getElementById("eap-enum-result");
  if (!box) return;
  const s = Math.floor((Date.now() - t0) / 1000);
  const clock = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  const dot = (v) => (v === "yes" ? "🟢" : v === "maybe" ? "🟡" : "⚪");
  const done = (st.methods || []).map((m) =>
    `<div class="detail-row"><span class="k">${dot(m.supported)} ${escapeHtml(m.method)}</span>` +
    `<span class="v">${escapeHtml(m.supported)}</span></div>`).join("");
  // No "Enumerating…" heading here: the Run button already shows that with its
  // spinner. Just the live status line and the methods as they resolve.
  box.innerHTML =
    `<p class="hint">${escapeHtml(essid || "")} on ${escapeHtml(iface)} · ${clock} elapsed · ` +
    `${(st.methods || []).length} tested. Each method is tried in turn.</p>` +
    (done ? `<div class="eap-result-card">${done}</div>` : "");
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
  // The certificate was extracted live by the warden and rides in the node
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
// The most recently enumerated EAP methods, kept so they can be exported.
let lastEap = null;

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

// Draw plain text onto a canvas and save it as a PNG. Rendering the text
// ourselves keeps the canvas untainted — no external capture library. Shared by
// the certificate and EAP-methods exports.
function saveTextImage(text, fileBase, okMsg) {
  const lines = text.split("\n");
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
    if (!blob) return toast("Could not render image", "error");
    downloadBlob(blob, fileBase + ".png");
    toast(okMsg, "ok");
  }, "image/png");
}

function exportCertImage(res) {
  if (res) saveTextImage(certToText(res), certFileBase(), "Certificate image saved");
}

/* ------------------------------------------------- EAP methods export */
function eapFileBase() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `eap-methods-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}` +
         `-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

// Flatten enumerated EAP methods into plain, copy-pasteable text.
function eapToText(res) {
  if (!res) return "";
  const rank = { yes: 0, maybe: 1, no: 2 };
  const methods = (res.methods || []).slice()
    .sort((a, b) => (rank[a.supported] ?? 3) - (rank[b.supported] ?? 3));
  const lines = [`EAP methods: ${res.essid || ""}`, "=".repeat(42)];
  methods.forEach((m) => lines.push(`  ${m.method}: ${m.supported}`));
  return lines.join("\n");
}

function exportEapTxt(res) {
  if (!res) return;
  downloadBlob(new Blob([eapToText(res)], { type: "text/plain;charset=utf-8" }),
               eapFileBase() + ".txt");
  toast("EAP methods exported (.txt)", "ok");
}

function exportEapImage(res) {
  if (res) saveTextImage(eapToText(res), eapFileBase(), "EAP methods image saved");
}

function renderEap(res) {
  const box = document.getElementById("eap-enum-result");
  if (!box) return;
  lastEap = res;
  const rank = { yes: 0, maybe: 1, no: 2 };
  const dot = (s) => (s === "yes" ? "🟢" : s === "maybe" ? "🟡" : "⚪");
  const methods = (res.methods || []).slice()
    .sort((a, b) => (rank[a.supported] ?? 3) - (rank[b.supported] ?? 3));
  box.innerHTML =
    `<h4>EAP methods: ${escapeHtml(res.essid || "")}</h4>` +
    `<div class="eap-result-card">` +
    methods
      .map((m) =>
        `<div class="detail-row"><span class="k">${dot(m.supported)} ${escapeHtml(m.method)}</span>` +
        `<span class="v">${escapeHtml(m.supported)}</span></div>`)
      .join("") +
    `</div>` +
    `<div class="eap-actions">
       <button class="btn" id="eap-copy">Copy text</button>
       <button class="btn" id="eap-txt">Export .txt</button>
       <button class="btn" id="eap-img">Save image</button>
     </div>`;
  document.getElementById("eap-copy").onclick = () => copyText(eapToText(lastEap));
  document.getElementById("eap-txt").onclick = () => exportEapTxt(lastEap);
  document.getElementById("eap-img").onclick = () => exportEapImage(lastEap);
}

// Inspect the RADIUS certificate from a locally-picked .cap (offline, no root).
document.getElementById("cert-open-btn").onclick = () =>
  openFsOpen("Open capture", [".cap", ".pcap", ".pcapng"], async (path) => {
    showCertModal(`<p class="hint">Inspecting ${escapeHtml(path)}…</p>`);
    try {
      renderCert(await API.certLocal(path));
    } catch (err) {
      showCertModal(`<p class="hint" style="color:#ffb3ba">${escapeHtml(err.message)}</p>`);
    }
  });

// Read EAP Response/Identity usernames from a locally-picked .cap (offline, no root).
document.getElementById("eapid-open-btn").onclick = () =>
  openFsOpen("Open capture", [".cap", ".pcap", ".pcapng"], async (path) => {
    const box = document.getElementById("eapid-result");
    box.innerHTML = `<p class="hint">Reading ${escapeHtml(path)}…</p>`;
    try {
      renderEapIdentities(await API.eapIdentityLocal(path), box);
    } catch (err) {
      box.innerHTML = `<p class="hint" style="color:#ffb3ba">${escapeHtml(err.message)}</p>`;
    }
  });

// Fill the interface list + identity suggestions when the EAP enumeration tool is
// expanded, and run the probe on demand.
document.getElementById("eap-run-btn").onclick = runEapEnum;
document.getElementById("eap-stop-btn").onclick = stopEapEnum;
document.getElementById("eap-iface-refresh").onclick = () => fillEapInterfaces();
document.getElementById("eap-enum-details").addEventListener("toggle", (e) => {
  if (e.target.open) refreshEapPanel();
});

// Render a list of captured EAP identities into a container.
function renderEapIdentities(res, box) {
  const ids = (res && res.identities) || [];
  if (!ids.length) {
    toast("No EAP identity found in the capture.", "ok");
    box.innerHTML = `<p class="hint">No EAP identity found. The capture may hold ` +
      `none, or the identities are the anonymous outer id of a tunnelled method ` +
      `(PEAP / EAP-TTLS), where the real username stays inside the TLS tunnel.</p>`;
    return;
  }
  box.innerHTML =
    `<div class="eapid-list">` +
    ids.map((e) =>
      `<div class="detail-row"><span class="k copyable" title="Click to copy">${escapeHtml(e.identity)}</span>` +
      `<span class="v">${escapeHtml(e.client || "")}</span></div>`).join("") +
    `</div>`;
  box.querySelectorAll(".k.copyable").forEach((el) => { el.onclick = () => copyText(el.textContent); });
}

// Persistent: it only closes via the × button (clicking the backdrop won't
// dismiss it), so the certificate stays up while you read it.
document.getElementById("cert-modal-close").onclick = closeCertModal;

// Attack path graph: close via the × button or by clicking the backdrop.
document.getElementById("attack-modal-close").onclick = closeAttackModal;
document.getElementById("attack-modal").addEventListener("click", (e) => {
  if (e.target.id === "attack-modal") closeAttackModal();
});

// Node-colour legend: the "i" in the filters header opens it; close via × or backdrop.
const nodeLegendModal = document.getElementById("node-legend-modal");
document.getElementById("legend-info").onclick = (e) => {
  e.stopPropagation();   // don't let the click reach the legend collapse/dim logic
  nodeLegendModal.classList.remove("hidden");
};
document.getElementById("node-legend-close").onclick = () =>
  nodeLegendModal.classList.add("hidden");
nodeLegendModal.addEventListener("click", (e) => {
  if (e.target.id === "node-legend-modal") nodeLegendModal.classList.add("hidden");
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
  // Tapping the empty background clears any isolate/highlight fade and closes the
  // details panel — but keep it open while a live EAP enumeration streams into it.
  if (evt.target === cy) {
    cy.elements().removeClass("faded");
    if (!eapRunning) closeDetails();
  }
});

// Mark a dragged node so the live layout pins it in place (see scheduleLiveLayout)
// instead of pulling it back on the next discovery. Plain class, clears on reload.
cy.on("dragfree", "node", (evt) => evt.target.addClass("user-moved"));

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
// Clickable legend rows toggle each node type on/off.
document.querySelectorAll(".legend-toggle").forEach((btn) =>
  btn.addEventListener("click", () => { btn.classList.toggle("off"); applyFilters(); })
);

// The filters overlay auto-dims when the pointer is away so it stops covering the
// graph; hovering it (or a fresh capture) brings it back. Collapse folds it to a chip.
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

// Sidebar panels act as an accordion: opening one collapses the others. Closing
// never re-triggers this, so there is no toggle loop.
const sidebarPanels = Array.from(document.querySelectorAll(".sidebar details.panel"));
sidebarPanels.forEach((d) =>
  d.addEventListener("toggle", () => {
    if (!d.open) return;
    sidebarPanels.forEach((other) => { if (other !== d && other.open) other.open = false; });
  })
);

/* ------------------------------------------------------------- live capture */
const live = { ws: null, running: false, fitDone: false, layoutTimer: null,
               mode: null, channel: null, canDeauth: false, loaded: false,
               iface: null, monitorIface: null, eapMonitorIface: null };

// Clients with no edges are "unassociated"; recompute after live changes.
function recomputeUnassoc() {
  cy.nodes('[kind = "client"]').forEach((n) => {
    n.data("unassociated", n.degree(false) === 0);
  });
}

// Airodump (real radio, via the warden) and replay share one session; only one runs
// at a time. These airodump option controls are locked while a capture runs.
const AIRODUMP_OPT_IDS = ["live-iface", "live-iface-refresh", "live-band",
  "live-save", "live-save-path", "live-save-browse",
  "live-channel", "live-encrypt", "live-essid", "live-bssid", "live-interval"];

function setDisabled(ids, disabled) {
  ids.forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.disabled = disabled;
    // Container fields (multi-field) hold the real controls as children.
    el.querySelectorAll("input, select, button").forEach((c) => { c.disabled = disabled; });
  });
}

/* ----------------------------------------------------- repeatable fields */
// Live-capture Protocol / ESSID / BSSID fields each hold several values (one airodump
// flag apiece) as a stack of rows: the first row adds, later rows remove themselves.
const PROTO_OPTS = [["", "any"], ["WEP", "WEP"], ["WPA2", "WPA2"],
  ["WPA3", "WPA3"], ["OPN", "Open"]];

function initMultiField(id) {
  const host = document.getElementById(id);
  if (!host) return;
  const kind = host.dataset.kind;          // "proto" | "text" | "mac"
  const ph = host.dataset.ph || "";
  const label = host.dataset.label || "";  // repeated on every row, so each field is named
  const makeRow = (first) => {
    const row = document.createElement("div");
    row.className = "mf-row";
    const lab = document.createElement("span");
    lab.className = "mf-label";
    lab.textContent = label;
    let ctrl;
    if (kind === "proto") {
      ctrl = document.createElement("select");
      ctrl.innerHTML = PROTO_OPTS
        .map(([v, l]) => `<option value="${v}">${l}</option>`).join("");
    } else {
      ctrl = document.createElement("input");
      ctrl.placeholder = ph;
    }
    ctrl.className = "mini-input";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "mf-btn";
    btn.textContent = first ? "+" : "−";      // + / minus sign
    btn.title = first ? "Add another" : "Remove";
    btn.onclick = first ? () => host.appendChild(makeRow(false)) : () => row.remove();
    row.append(lab, ctrl, btn);
    return row;
  };
  host.innerHTML = "";
  host.appendChild(makeRow(true));
}

// Non-empty, de-duplicated values of a repeatable field, in order.
function collectMultiField(id) {
  const host = document.getElementById(id);
  if (!host) return [];
  const vals = [...host.querySelectorAll("input, select")]
    .map((c) => c.value.trim()).filter(Boolean);
  return [...new Set(vals)];
}

// -------------------------------------------------------- channel picker
// Valid channels per band, offered as toggle chips (not free text); the band select
// picks the set. Multi-select is allowed (airodump hops across them).
const CH_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
const CH_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
  124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];

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
    html += `<button type="button" class="chan-chip" data-ch="${c}">${c}</button>`;
  }
  wrap.innerHTML = html;
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
["live-encrypt", "live-essid", "live-bssid"].forEach(initMultiField);

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
  // No capture loaded → imports; capture loaded → replays; replaying → stops.
  // "primary" only in the import state, to flag it as the way in.
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
    : "Import an airodump-ng CSV file (.csv) to enable replay.";

  // Scan filters (tech / channel / ESSID / BSSID) are for reviewing a finished scan,
  // so hide them during a live capture and show them once stopped or replaying.
  const repFilters = document.getElementById("replay-filters");
  if (repFilters) repFilters.classList.toggle("hidden", capturing);
}

function setLiveUI(running) {
  live.running = running;
  refreshLiveButtons();
  // Stopping reveals the scan filters; build their options from the final graph
  // (they stay hidden during a live capture, so are populated only now).
  if (!running) populateFilterOptions();
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
        // Drop each new node at a random angle and modest radius from the centre:
        // spread enough not to stack, close enough not to fling far away.
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
  // Only relayout on structural changes (nodes/edges added or removed); a data-only
  // update (signal, beacons…) must not reshuffle nodes the user arranged by hand.
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
    // Pin every non-fresh node so the layout only places just-discovered nodes around
    // the stable graph (no reshuffle). Few free nodes + no animation keeps CPU low.
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
  } else if (msg.type === "eap_identity") {
    markEapIdentity(msg);
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

function markCert(msg) {
  const name = msg.essid || msg.bssid;
  toast(`RADIUS certificate captured: ${name}. Open the AP to read it.`, "ok");
}

function markEapIdentity(msg) {
  const name = msg.essid || msg.bssid;
  toast(`EAP identity captured on ${name}: ${msg.identity}`, "ok");
  // Refresh the AP panel if it is open so the captured identity shows there too.
  if (detailNodeId === msg.bssid) openNode(msg.bssid);
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
  // Prefer an explicitly requested interface (the last capture's), else keep the
  // current pick — stops the picker snapping back to wlan0 when it briefly drops out.
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
    encrypt: collectMultiField("live-encrypt"),
    essid: collectMultiField("live-essid"),
    bssid: collectMultiField("live-bssid"),
    save: document.getElementById("live-save").checked,
    save_path: document.getElementById("live-save-path").value.trim() || null,
    acknowledged: true,
  };
  closeDetails();   // a fresh scan: drop any stale node details from the last one
  // Switching to a live scan discards any imported capture still loaded for
  // replay, so the two never mix.
  if (live.loaded) {
    try { await API.clear(); } catch (e) { /* ignore */ }
    live.loaded = false;
  }
  // Wipe the previous session's graph and zero the Overview right away, so a new
  // scan starts from a clean slate instead of showing the old counts.
  cy.elements().remove();
  updateStats({});
  setEmptyState(true);
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
    // The base adapter now runs as a monitor vif (e.g. wlan0 -> wlan0mon); keep
    // both so EAP can map the monitor interface back to its managed base.
    live.monitorIface = (res && res.interface) || null;
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
  // Teardown (killing airodump, restoring the interface) takes a couple of seconds,
  // so spin the button now; setLiveUI(false) below rewrites and clears it.
  const btn = document.getElementById(wasReplay ? "replay-toggle" : "live-toggle");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>Stopping…';
  }
  let saved = null;
  live.eapMonitorIface = null;
  try {
    // For an EAP handoff, stop but keep the adapter in monitor mode (NM-free) and
    // learn the monitor interface to run EAP_buster on; otherwise a normal stop.
    const res = opts.eapBase
      ? await API.liveStopForEap(opts.eapBase)
      : await API.liveStop();
    saved = res && res.saved_path;
    if (opts.eapBase) live.eapMonitorIface = res && res.monitor_interface;
  } catch (e) { if (opts.eapBase) toast(e.message, "error"); }
  if (live.ws) { live.ws.close(); live.ws = null; }
  live.mode = null;
  live.channel = null;
  live.canDeauth = false;
  live.monitorIface = null;
  setLiveUI(false);
  if (!opts.silent) {
    if (saved) toast(`Capture saved to ${saved}`, "ok");
    else toast(wasReplay ? "Replay stopped" : "Live capture stopped", "ok");
  }
  if (OFFENSIVE && !wasReplay && !opts.eapBase) {
    // The warden restores managed mode + restarts NetworkManager asynchronously, so
    // refresh the interface list now and a few times after (skipped for EAP, which keeps monitor).
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
  if (!live.loaded) return importFromPicker();
  return startReplay();
};

document.getElementById("live-iface-refresh").onclick = () => loadInterfaces();

// Show the save path field only while "Save capture file" is ticked.
const liveSaveChk = document.getElementById("live-save");
if (liveSaveChk) liveSaveChk.addEventListener("change", () =>
  document.getElementById("save-path-row").classList.toggle("hidden", !liveSaveChk.checked));

/* ------------------------------------------------------- in-app file picker */
// Themed backend filesystem browser to SAVE a capture or OPEN one off disk (no OS
// dialog, no upload — the server reads the path). Modes: "save" and "open".
let fsCurrent = null;      // folder currently shown
let fsWritable = false;    // is fsCurrent writable (save mode)
let fsMode = "save";
let fsExts = null;         // allowed extensions in open mode (lowercase, with dot)
let fsSelected = null;     // chosen file path in open mode
let fsOnPick = null;       // callback(path) in open mode
const fsModal = document.getElementById("fs-modal");

function fsExtOk(name) {
  const l = name.toLowerCase();
  return !!fsExts && fsExts.some((x) => l.endsWith(x));
}

async function fsNavigate(path) {
  let data;
  try {
    data = await API.fsList(path);
  } catch (e) {
    toast(e.message, "error");
    return;
  }
  fsCurrent = data.path;
  fsWritable = data.writable;
  fsSelected = null;
  document.getElementById("fs-path").textContent = data.path;
  const join = (name) => (data.path === "/" ? "/" + name : data.path + "/" + name);
  const rows = [];
  if (data.parent !== null) {
    rows.push(`<button class="fs-row fs-up" data-path="${escapeHtml(data.parent)}"><span class="fs-ico">↑</span>..</button>`);
  }
  for (const e of data.entries) {
    if (e.is_dir) {
      rows.push(`<button class="fs-row fs-dir" data-path="${escapeHtml(join(e.name))}"><span class="fs-ico">📁</span>${escapeHtml(e.name)}</button>`);
    } else if (fsMode === "open" && fsExtOk(e.name)) {
      rows.push(`<button class="fs-row fs-pick" data-path="${escapeHtml(join(e.name))}"><span class="fs-ico">📄</span>${escapeHtml(e.name)}</button>`);
    } else {
      rows.push(`<div class="fs-row fs-file"><span class="fs-ico">📄</span>${escapeHtml(e.name)}</div>`);
    }
  }
  const list = document.getElementById("fs-list");
  list.innerHTML = rows.join("") || `<p class="fs-empty">Empty folder</p>`;
  list.querySelectorAll(".fs-dir, .fs-up").forEach((el) => {
    el.onclick = () => fsNavigate(el.dataset.path);
  });
  list.querySelectorAll(".fs-pick").forEach((el) => {
    el.onclick = () => {
      fsSelected = el.dataset.path;
      list.querySelectorAll(".fs-pick").forEach((x) => x.classList.remove("selected"));
      el.classList.add("selected");
      document.getElementById("fs-choose").disabled = false;
      document.getElementById("fs-hint").textContent = "Selected: " + fsSelected;
    };
  });
  fsSyncFooter();
}

// Footer state (button label/enabled + hint) depends on the mode.
function fsSyncFooter() {
  const chooseBtn = document.getElementById("fs-choose");
  const hint = document.getElementById("fs-hint");
  if (fsMode === "save") {
    chooseBtn.disabled = !fsWritable;
    hint.textContent = fsWritable
      ? "airodump-ng appends -01.cap to the name you enter."
      : "This folder is not writable — pick another.";
  } else {
    chooseBtn.disabled = !fsSelected;
    if (!fsSelected) hint.textContent = "Pick a " + fsExts.join(" / ") + " file.";
  }
}

// Open the picker to choose a save location for the live capture.
async function openFsSave() {
  fsMode = "save"; fsExts = null; fsOnPick = null;
  document.getElementById("fs-title").textContent = "Choose save location";
  document.getElementById("fs-name-row").classList.remove("hidden");
  document.getElementById("fs-choose").textContent = "Save here";
  const current = document.getElementById("live-save-path").value.trim();
  const slash = current.lastIndexOf("/");
  const startDir = slash > 0 ? current.slice(0, slash) : (slash === 0 ? "/" : null);
  document.getElementById("fs-name").value = slash >= 0 ? current.slice(slash + 1) : current;
  await fsNavigate(startDir);
  fsModal.classList.remove("hidden");
}

// Open the picker to select an existing file (import / cert / EAP identity).
async function openFsOpen(title, exts, onPick) {
  fsMode = "open"; fsExts = exts.map((e) => e.toLowerCase()); fsOnPick = onPick;
  document.getElementById("fs-title").textContent = title;
  document.getElementById("fs-name-row").classList.add("hidden");
  document.getElementById("fs-choose").textContent = "Open";
  await fsNavigate(null);   // start in the home directory
  fsModal.classList.remove("hidden");
}

function fsChoose() {
  if (fsMode === "open") {
    if (!fsSelected) return;
    const cb = fsOnPick, path = fsSelected;
    fsModal.classList.add("hidden");
    if (cb) cb(path);
    return;
  }
  const name = document.getElementById("fs-name").value.trim();
  if (!name) return toast("Enter a file name", "error");
  if (!fsWritable) return toast("This folder is not writable", "error");
  // airodump appends -01.cap, so store the base path without an extension.
  const base = name.replace(/\.(cap|pcap|pcapng|csv)$/i, "");
  document.getElementById("live-save-path").value =
    fsCurrent === "/" ? "/" + base : fsCurrent + "/" + base;
  fsModal.classList.add("hidden");
  toast("Save location set", "ok");
}

const saveBrowseBtn = document.getElementById("live-save-browse");
if (saveBrowseBtn) saveBrowseBtn.addEventListener("click", openFsSave);
document.getElementById("fs-close").onclick = () => fsModal.classList.add("hidden");
document.getElementById("fs-cancel").onclick = () => fsModal.classList.add("hidden");
document.getElementById("fs-choose").onclick = fsChoose;
fsModal.addEventListener("click", (e) => {
  if (e.target.id === "fs-modal") fsModal.classList.add("hidden");
});

// Import a capture chosen with the in-app browser (read from disk, no upload).
async function importFromPicker() {
  openFsOpen("Open capture", [".csv", ".txt"], async (path) => {
    if (live.running) await stopLive();
    try {
      toast("Parsing capture…");
      const payload = await API.importLocal(path);
      renderGraph(payload);
      live.loaded = true;
      refreshLiveButtons();
      toast(`Loaded ${payload.summary.access_points} APs / ${payload.summary.clients} clients`, "ok");
    } catch (err) {
      toast(err.message, "error");
    }
  });
}

/* -------------------------------------------------------------- resizing */
// Drag a handle to resize the panel beside it (sidebar grows rightward, details
// leftward). Min/max come from the panels' CSS, so the graph never fully collapses.
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
    // The privileged warden is required to launch, so live capture is available;
    // a transient config hiccup shouldn't hide it.
    OFFENSIVE = true;
  }
  // WiFiCatcher runs as a single mode: the privileged warden is always present,
  // so the live-capture panel is shown and the interface list is loaded.
  loadInterfaces();

  // A still-running live/replay session should survive a reload, so rejoin it.
  // Otherwise start fresh: discard stale imported data rather than resurrect it.
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
