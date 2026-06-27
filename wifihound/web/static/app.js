/* WiFiHound frontend: Cytoscape graph and interaction. */
"use strict";

const API = {
  async import(file) {
    const fd = new FormData();
    fd.append("file", file);
    return fetchJSON("/api/import", { method: "POST", body: fd });
  },
  graph: () => fetchJSON("/api/graph"),
  node: (id) => fetchJSON(`/api/node/${encodeURIComponent(id)}`),
  search: (q) => fetchJSON(`/api/search?q=${encodeURIComponent(q)}`),
  config: () => fetchJSON("/api/config"),
  enrich: () => fetchJSON("/api/enrich/oui", { method: "POST" }),
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
        "text-margin-y": 5,
        "text-wrap": "ellipsis",
        "text-max-width": 130,
        "text-outline-color": "#0a1016",
        "text-outline-width": 2.5,
        "min-zoomed-font-size": 6,
        "border-width": 2,
        "border-color": "#0a1016",
        width: 26,
        height: 26,
      },
    },
    {
      selector: 'node[kind = "ap"]',
      style: {
        "background-color": "#ff5d6c",
        width: "mapData(degree, 0, 12, 34, 64)",
        height: "mapData(degree, 0, 12, 34, 64)",
        "font-size": 12,
        "font-weight": "bold",
      },
    },
    { selector: 'node[kind = "client"]', style: { "background-color": "#4da6ff" } },
    {
      selector: 'node[kind = "client"][?unassociated]',
      style: { "background-color": "#8a93a8" },
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
          packComponents: true, nodeRepulsion: 16000, idealEdgeLength: 130,
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
  document.getElementById("empty-state").classList.toggle("hidden", cy.nodes().length > 0);
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
function applyFilters() {
  const showAps = document.getElementById("filter-aps").checked;
  const showClients = document.getElementById("filter-clients").checked;
  const showUnassoc = document.getElementById("filter-unassoc").checked;
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
}

/* ----------------------------------------------------------------- details */
function showDetails(info) {
  const body = document.getElementById("details-body");
  const isAp = info.kind === "ap";
  const rows = [];
  const row = (k, v) =>
    v !== null && v !== undefined && v !== ""
      ? rows.push(`<div class="detail-row"><span class="k">${k}</span><span class="v">${escapeHtml(v)}</span></div>`)
      : null;

  if (isAp) {
    row("ESSID", info.essid);
    row("BSSID", info.id);
    row("Channel", info.channel);
    row("Encryption", info.privacy);
    row("Cipher", info.cipher);
    row("Auth", info.authentication);
    row("Signal", info.power != null ? `${info.power} dBm` : null);
    row("Beacons", info.beacons);
    row("Data", info.data);
    row("Vendor", info.vendor);
    row("Clients", info.degree);
    row("First seen", info.first_seen);
    row("Last seen", info.last_seen);
  } else {
    row("MAC", info.id);
    row("Vendor", info.vendor);
    row("Associated to", info.associated_bssid);
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

  const title = isAp ? info.essid || "&lt;Hidden&gt;" : info.id;
  const clientAssociated =
    !isAp && info.associated_bssid && info.associated_bssid !== "(not associated)";
  let offBtn = "";
  if (OFFENSIVE && isAp) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth this AP…</button>`;
  } else if (OFFENSIVE && clientAssociated) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth from AP…</button>`;
  }

  body.innerHTML = `
    <span class="kind-badge ${info.kind}">${isAp ? "Access Point" : "Client"}</span>
    <h3>${escapeHtml(title)}</h3>
    ${rows.join("")}
    ${probes}
    <div class="actions">
      <button class="btn" id="neighbors-btn">Highlight neighbors</button>
      ${offBtn}
    </div>`;

  const panel = document.getElementById("details");
  const wasHidden = panel.classList.contains("hidden");
  panel.classList.remove("hidden");
  document.getElementById("neighbors-btn").onclick = () => highlightNeighbors(info.id);
  const deauthBtn = document.getElementById("op-deauth-btn");
  if (deauthBtn) deauthBtn.onclick = () => openDeauthModal(info);

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
  document.getElementById("details").classList.add("hidden");
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

/* ----------------------------------------------------------- context menu */
cy.cxtmenu({
  selector: "node",
  menuRadius: 80,
  fillColor: "rgba(16, 28, 39, 0.95)",
  activeFillColor: "rgba(52, 211, 153, 0.85)",
  commands: (ele) => {
    const id = ele.id();
    const isAp = ele.data("kind") === "ap";
    const cmds = [
      { content: "Details", select: () => openNode(id) },
      { content: "Neighbors", select: () => highlightNeighbors(id) },
      { content: "Isolate", select: () => isolate(id) },
      { content: "Copy ID", select: () => copyText(id) },
    ];
    // Deauth an AP directly, or a client off its associated AP (degree > 0).
    const canDeauthNode = isAp || (ele.data("kind") === "client" && ele.degree(false) > 0);
    if (OFFENSIVE && canDeauthNode) {
      cmds.push({
        content: "Deauth",
        select: () => API.node(id).then(openDeauthModal),
        fillColor: "rgba(255, 93, 108, 0.85)",
      });
    }
    return cmds;
  },
});

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

function openDeauthModal(info) {
  // Target an AP directly, or a client off its associated AP.
  const isAp = info.kind === "ap";
  const bssid = isAp ? info.id : info.associated_bssid;
  const client = isAp ? null : info.id;
  pendingOp = { bssid, client };

  const target = isAp
    ? `AP <strong>${escapeHtml(info.essid || info.id)}</strong> (${escapeHtml(info.id)})`
    : `client <strong>${escapeHtml(info.id)}</strong> off AP <strong>${escapeHtml(bssid)}</strong>`;
  const capLine = live.canDeauth
    ? `Uses the live capture interface, locked on channel <strong>${escapeHtml(live.channel)}</strong>.`
    : `<span style="color:#ffb3ba">No fixed-channel airodump capture is running — start a
       live airodump capture on a channel to enable deauth.</span>`;

  document.getElementById("op-title").textContent = "Deauthentication";
  document.getElementById("op-body").innerHTML = `
    <p>Target ${target}</p>
    <p class="hint">${capLine}</p>
    <label>Deauth bursts (1–64, 0 = continuous not allowed)</label>
    <input id="op-count" type="number" min="1" max="64" value="5"/>
    <label><input type="checkbox" id="op-dry"/> Dry run (build command only)</label>`;
  document.getElementById("op-confirm").disabled = !live.canDeauth;
  document.getElementById("op-modal").classList.remove("hidden");
}

document.getElementById("op-cancel").onclick = () => {
  document.getElementById("op-modal").classList.add("hidden");
  pendingOp = null;
};

document.getElementById("op-confirm").onclick = async () => {
  if (!pendingOp) return;
  const payload = {
    bssid: pendingOp.bssid,
    client: pendingOp.client || null,
    count: Number(document.getElementById("op-count").value) || 5,
    acknowledged: true,
    dry_run: document.getElementById("op-dry").checked,
  };
  try {
    const res = await API.deauth(payload);
    toast(`Deauth ${res.status}: ${res.command.join(" ")}`, "ok");
  } catch (e) {
    toast(e.message, "error");
  } finally {
    document.getElementById("op-modal").classList.add("hidden");
    pendingOp = null;
  }
};

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
  if (evt.target === cy) cy.elements().removeClass("faded");
});

document.getElementById("file-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (live.running) await stopLive();   // offline import replaces any live session
  try {
    toast("Parsing capture…");
    const payload = await API.import(file);
    renderGraph(payload);
    toast(`Loaded ${payload.summary.access_points} APs / ${payload.summary.clients} clients`, "ok");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    e.target.value = "";
  }
});

document.getElementById("enrich-btn").onclick = async () => {
  try {
    const payload = await API.enrich();
    const summary = (await API.graph()).summary;
    renderGraph({ ...payload, summary });
    toast(`Resolved ${payload.resolved} vendors`, "ok");
  } catch (e) {
    toast(e.message, "error");
  }
};

document.getElementById("reset-btn").onclick = () => {
  cy.elements().removeClass("faded highlight");
  cy.nodes().removeClass("hidden-node");
  document.querySelectorAll(".filter input").forEach((c) => (c.checked = true));
  document.getElementById("filter-enc").value = "";
  document.getElementById("filter-chan").value = "";
  fitGraph();
};

document.getElementById("details-close").onclick = closeDetails;
document.getElementById("layout-select").onchange = (e) => runLayout(e.target.value);
["filter-aps", "filter-clients", "filter-unassoc", "filter-enc", "filter-chan"].forEach(
  (id) => document.getElementById(id).addEventListener("change", applyFilters)
);

/* ------------------------------------------------------------- live capture */
const live = { ws: null, running: false, fitDone: false, layoutTimer: null,
               mode: null, channel: null, canDeauth: false };

// Clients with no edges are "unassociated"; recompute after live changes.
function recomputeUnassoc() {
  cy.nodes('[kind = "client"]').forEach((n) => {
    n.data("unassociated", n.degree(false) === 0);
  });
}

function setLiveUI(running) {
  live.running = running;
  document.getElementById("live-toggle").textContent = running ? "Stop live" : "Start live";
  document.getElementById("live-toggle").classList.toggle("danger", running);
  document.getElementById("live-dot").classList.toggle("on", running);
}

function applyPatch(p) {
  cy.batch(() => {
    (p.remove || []).forEach((id) => cy.remove(cy.getElementById(id)));
    (p.add || []).forEach((el) => {
      const added = cy.add(el);
      if (el.group === "nodes") added.addClass("fresh");
    });
    (p.update || []).forEach((data) => {
      const ele = cy.getElementById(data.id);
      if (ele.nonempty()) ele.data(data);
    });
  });
  recomputeUnassoc();
  applyFilters();
  if (p.summary) updateStats(p.summary);
  document.getElementById("empty-state").classList.toggle("hidden", cy.nodes().length > 0);
  setTimeout(() => cy.nodes(".fresh").removeClass("fresh"), 1600);
  scheduleLiveLayout();
}

function scheduleLiveLayout() {
  clearTimeout(live.layoutTimer);
  live.layoutTimer = setTimeout(() => {
    const l = cy.layout({
      name: "fcose", animate: true, animationDuration: 500, randomize: false,
      packComponents: true, nodeRepulsion: 16000, idealEdgeLength: 130,
      nodeSeparation: 150, gravity: 0.15, gravityRange: 3.8, fit: false, padding: 60,
    });
    // Fit once, after the first real layout, then leave the view to the user.
    l.one("layoutstop", () => {
      if (!live.fitDone) { fitGraph(); live.fitDone = true; }
    });
    l.run();
  }, 700);
}

function handleLiveMessage(msg) {
  if (msg.type === "init") {
    cy.elements().remove();
    if (msg.elements && (msg.elements.nodes.length || msg.elements.edges.length)) {
      renderGraph(msg);
      live.fitDone = true;
    } else {
      document.getElementById("empty-state").classList.add("hidden");
    }
  } else if (msg.type === "patch") {
    applyPatch(msg);
  } else if (msg.type === "handshake") {
    markHandshake(msg);
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
  toast(`WPA handshake captured: ${name}`, "ok");
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
async function loadInterfaces() {
  const sel = document.getElementById("live-iface");
  const prev = sel.value;
  try {
    const { interfaces } = await API.interfaces();
    if (!interfaces.length) {
      sel.innerHTML = '<option value="">no wireless interface found</option>';
      return;
    }
    sel.innerHTML = interfaces
      .map((i) => `<option value="${escapeHtml(i.name)}">${escapeHtml(i.name)} (${escapeHtml(i.mode)})</option>`)
      .join("");
    if (prev && interfaces.some((i) => i.name === prev)) sel.value = prev;
  } catch (e) {
    sel.innerHTML = '<option value="">scan failed</option>';
  }
}

async function startLive() {
  // Live capture is always a real airodump-ng capture (radio), never a CSV.
  const iface = document.getElementById("live-iface").value.trim();
  if (!iface) return toast("Select a wireless interface", "error");
  const interval = Number(document.getElementById("live-interval").value) || 1.2;
  const channel = document.getElementById("live-channel").value.trim() || null;
  if (!confirm("Start a real radio capture on " + iface +
               (channel ? " (channel " + channel + ")" : "") +
               "?\nThe interface will be switched to monitor mode if needed.\n" +
               "Authorized testing only: networks you own or may assess.")) return;
  const payload = {
    mode: "airodump",
    interface: iface,
    channel,
    interval,
    encrypt: document.getElementById("live-encrypt").value || null,
    wps: document.getElementById("live-wps").checked,
    essid: document.getElementById("live-essid").value.trim() || null,
    bssid: document.getElementById("live-bssid").value.trim() || null,
    acknowledged: true,
  };
  try {
    live.fitDone = false;
    const res = await API.liveStart(payload);
    live.mode = "airodump";
    live.channel = channel;
    live.canDeauth = !!channel;
    openLiveSocket();
    setLiveUI(true);
    const onIface =
      res.interface && res.interface !== iface ? ` on ${res.interface}` : "";
    const extra = live.canDeauth ? ` — deauth enabled (ch ${channel})` : "";
    toast(`Live capture started${onIface}${extra}`, "ok");
    loadInterfaces(); // the adapter may now report as monitor / be renamed
  } catch (e) {
    toast(e.message, "error");
  }
}

async function stopLive() {
  try { await API.liveStop(); } catch (e) { /* ignore */ }
  if (live.ws) { live.ws.close(); live.ws = null; }
  live.mode = null;
  live.channel = null;
  live.canDeauth = false;
  setLiveUI(false);
  toast("Live capture stopped", "ok");
  if (OFFENSIVE) loadInterfaces(); // adapter is back to managed mode now
}

document.getElementById("live-toggle").onclick = () =>
  live.running ? stopLive() : startLive();

document.getElementById("live-iface-refresh").onclick = () => loadInterfaces();

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

/* ------------------------------------------------------------------ start */
(async function init() {
  try {
    const cfg = await API.config();
    OFFENSIVE = !!cfg.offensive_available;
  } catch (e) {
    /* default OFFENSIVE = false */
  }
  if (OFFENSIVE) {
    // Real radio capture is unlocked only when the server enables offensive ops.
    loadInterfaces();
  } else {
    // No root: lock the live-capture controls and explain why.
    document.getElementById("live-locked").style.display = "";
    document.getElementById("live-airodump-opts").style.display = "none";
    document.getElementById("live-toggle").disabled = true;
  }
  try {
    const payload = await API.graph();
    if (payload.elements.nodes.length) renderGraph(payload);
  } catch (e) {
    /* nothing loaded yet */
  }
})();
