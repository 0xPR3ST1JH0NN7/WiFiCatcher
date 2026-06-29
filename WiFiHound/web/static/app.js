/* WiFiHound frontend: Cytoscape graph and interaction. */
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
      style: { "border-color": "#a78bfa", "border-width": 4 },
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
// Show the "no capture" splash when empty; show the graph legend only when
// there are nodes to read it against.
function setEmptyState(empty) {
  document.getElementById("empty-state").classList.toggle("hidden", !empty);
  const legend = document.getElementById("graph-legend");
  if (legend) legend.classList.toggle("hidden", empty);
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
  // Offensive / enterprise actions act on a *live* radio capture, so they are
  // pointless on a static import or replay — only offer them during a live
  // airodump session (deauth additionally needs a fixed channel).
  const liveActive = live.running && live.mode === "airodump";
  let offBtn = "";
  if (live.canDeauth && isAp) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth this AP…</button>`;
  } else if (live.canDeauth && clientAssociated) {
    offBtn = `<button class="btn danger" id="op-deauth-btn">Deauth from AP…</button>`;
  }

  // Enterprise (802.1X) badge is informational; its actions need a live capture.
  const enterprise = isAp && info.enterprise;
  const entBadge = enterprise
    ? `<span class="kind-badge enterprise">802.1X Enterprise</span>` : "";
  let entBtns = "";
  if (enterprise && liveActive) {
    entBtns += `<button class="btn" id="op-cert-btn">Inspect RADIUS cert</button>`;
    entBtns += `<button class="btn" id="op-eap-btn">Enumerate EAP methods…</button>`;
  }

  body.innerHTML = `
    <span class="kind-badge ${info.kind}">${isAp ? "Access Point" : "Client"}</span>
    ${entBadge}
    <h3>${escapeHtml(title)}</h3>
    ${rows.join("")}
    ${probes}
    <div class="actions">
      <button class="btn" id="neighbors-btn">Highlight neighbors</button>
      <button class="btn" id="isolate-btn">Isolate</button>
      <button class="btn" id="copy-btn">Copy ${isAp ? "BSSID" : "MAC"}</button>
      ${offBtn}
      ${entBtns}
    </div>
    <div id="enterprise-result"></div>`;

  const panel = document.getElementById("details");
  const wasHidden = panel.classList.contains("hidden");
  panel.classList.remove("hidden");
  document.getElementById("resizer-right").classList.remove("hidden");
  document.getElementById("neighbors-btn").onclick = () => highlightNeighbors(info.id);
  document.getElementById("isolate-btn").onclick = () => isolate(info.id);
  document.getElementById("copy-btn").onclick = () => copyText(info.id);
  const deauthBtn = document.getElementById("op-deauth-btn");
  if (deauthBtn) deauthBtn.onclick = () => openDeauthModal(info);
  const certBtn = document.getElementById("op-cert-btn");
  if (certBtn) certBtn.onclick = () => inspectCert(info);
  const eapBtn = document.getElementById("op-eap-btn");
  if (eapBtn) eapBtn.onclick = () => openEapModal(info);

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
    <p class="hint">Active 802.1X authentication. Runs for several minutes and the
      interface is switched to <strong>managed</strong> mode (don't use one mid-capture).
      Use a legitimate identity; anonymous ones give unreliable results.</p>
    <label>EAP identity</label>
    <input id="op-identity" placeholder="DOMAIN\\user"/>
    <label>Interface</label>
    <input id="op-iface" placeholder="wlan0"/>
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
// something is happening. A client deauth lights the client and the link to its
// AP (the deauth targets that association); an AP deauth lights the AP and its
// links. Returns a stop function that ends the animation and clears the effect.
function startDeauthFx(op) {
  let targets = cy.collection();
  if (op.client) {
    const client = cy.getElementById(op.client);
    const ap = op.bssid ? cy.getElementById(op.bssid) : cy.collection();
    if (client.nonempty()) targets = targets.union(client);
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
  toast("Sending deauth…");
  const stopFx = startDeauthFx(op);   // pulse the target until the deauth ends
  try {
    const res = await API.deauth(payload);
    toast(`Deauth ${res.status}`, res.status === "ok" ? "ok" : "error");
  } catch (e) {
    toast(e.message, "error");
  } finally {
    stopFx();
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
  const box = document.getElementById("enterprise-result");
  if (box && !dry) {
    box.innerHTML = `<p class="hint">Running EAP enumeration on ${escapeHtml(iface)}.
      This can take several minutes…</p>`;
  }
  try {
    const res = await API.enterpriseEap({
      essid, identity, interface: iface, acknowledged: true, dry_run: dry,
    });
    renderEap(res, dry);
  } catch (e) {
    if (box) box.innerHTML = `<p class="hint" style="color:#ffb3ba">${escapeHtml(e.message)}</p>`;
    else toast(e.message, "error");
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

async function inspectCert(info) {
  showCertModal(`<p class="hint">Inspecting RADIUS certificate…</p>`);
  try {
    renderCert(await API.enterpriseCert({ ap_bssid: info.id }));
  } catch (e) {
    showCertModal(`<p class="hint" style="color:#ffb3ba">${escapeHtml(e.message)}</p>`);
  }
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
  showCertModal(
    res.certificates
      .map((c) =>
        `<h4>Subject</h4>${dnRows(c.subject)}` +
        `<h4>Issuer</h4>${dnRows(c.issuer)}` +
        `<h4>Validity &amp; serial</h4>` +
        row("Valid from", c.not_before) + row("Valid to", c.not_after) +
        row("Serial number", c.serial))
      .join(`<hr class="cert-sep"/>`) +
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
// radio, needs root) and replay (offline reveal of an imported capture). Only
// one runs at a time; reflect that on both panels' buttons.
// The airodump option controls — locked while a capture is running, since
// changing them mid-capture is meaningless.
const AIRODUMP_OPT_IDS = ["live-iface", "live-iface-refresh", "live-band",
  "live-save", "live-channel", "live-encrypt", "live-wps", "live-essid",
  "live-bssid", "live-interval"];

function setDisabled(ids, disabled) {
  ids.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.disabled = disabled;
  });
}

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

  const rep = document.getElementById("replay-toggle");
  const replaying = running && mode === "replay";
  rep.textContent = replaying ? "Stop replay" : "Replay capture";
  rep.classList.toggle("danger", replaying);
  rep.disabled = (running && mode !== "replay") || (!running && !live.loaded);
  setDisabled(["replay-interval"], replaying);
  document.getElementById("replay-dot").classList.toggle("on", replaying);
  document.getElementById("replay-hint").textContent = replaying
    ? "Revealing the capture… press Stop to halt."
    : live.loaded
    ? "Replays the loaded capture node by node."
    : "Import a capture first, then replay it.";

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
        // Seed a spread-out position so new nodes read as a graph straight away
        // instead of stacking on one spot until fcose runs a moment later.
        added.position({
          x: spawn.x + (Math.random() - 0.5) * 460,
          y: spawn.y + (Math.random() - 0.5) * 340,
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
    band: document.getElementById("live-band").value || null,
    interval,
    encrypt: document.getElementById("live-encrypt").value || null,
    wps: document.getElementById("live-wps").checked,
    essid: document.getElementById("live-essid").value.trim() || null,
    bssid: document.getElementById("live-bssid").value.trim() || null,
    save: document.getElementById("live-save").checked,
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
    const extra = live.canDeauth ? ` (deauth enabled, ch ${channel})` : "";
    toast(`Live capture started${onIface}${extra}`, "ok");
    loadInterfaces(); // the adapter may now report as monitor / be renamed
  } catch (e) {
    toast(e.message, "error");
  }
}

// Replay: re-feed the imported capture progressively. Offline, no root.
async function startReplay() {
  if (!live.loaded) return toast("Import a capture first", "error");
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
  if (OFFENSIVE && !wasReplay) loadInterfaces(); // adapter is back to managed mode now
  return saved;
}

document.getElementById("live-toggle").onclick = () =>
  live.running && live.mode === "airodump" ? stopLive() : startLive();

document.getElementById("replay-toggle").onclick = () =>
  live.running && live.mode === "replay" ? stopLive() : startReplay();

document.getElementById("live-iface-refresh").onclick = () => loadInterfaces();

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
sizeInput.oninput = (e) => {                 // live preview as you type/spin
  prefs.size = clampSize(e.target.value); applyPrefs(); savePrefs();
};
sizeInput.onchange = (e) => {                 // snap the field to the clamped value
  prefs.size = clampSize(e.target.value); e.target.value = prefs.size;
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
    /* default OFFENSIVE = false */
  }
  if (OFFENSIVE) {
    // Real radio capture is unlocked only when the server enables offensive ops.
    loadInterfaces();
  } else {
    // Not root: live capture (and the deauth / EAP actions it unlocks) can't
    // run, so hide that panel entirely instead of showing dead controls. The
    // offline tools (import, replay, RADIUS cert upload) stay available.
    document.getElementById("live-panel").classList.add("hidden");
    document.getElementById("root-note").classList.remove("hidden");
  }

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
