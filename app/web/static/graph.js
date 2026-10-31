/* Aegis fund-flow graph — Cytoscape.js + dagre (left→right by hop).
   Loaded only by templates/trace_graph.html (with the vendored cytoscape/dagre). Controls: zoom in/out/fit,
   edge labels on/off, details panel, fullscreen (Fullscreen API), find, legend filters ([data-ff-show]),
   recommended-action focus buttons ([data-ff-focus]). Node and edge labels hide when zoomed out (class ff-lbl-off,
   see keepReadable); the overview labels and the callouts take over.
   Copy buttons (.ff-copy[data-copy]) are handled by static/js/trace.js.
   Encoding (server side: app/tracing/annotate.py): fill = coin of the largest tainted inflow, shape = chain,
   diameter = sqrt(tainted USD), border + lock badge = freeze status from the case's stop orders (a thin dotted
   blue border, no badge, = only cited in a letter to someone else), red dashed pulsing ring + red callout =
   recommended stop-order target. On-chain freeze readings (app/freeze: Tether / Circle blacklist read from the token
   contract) get their own style: a thick magenta double border + a lock-and-chain badge (`onchain_frozen`), never
   the stop-order "frozen" green (which an exchange's reply confirms; the victim's border is green too); a freeze the
   issuer lifted again (`onchain_unfrozen`: funds can move) gets a dashed magenta border and no badge. The details
   panel lists the readings (check time, block, method, freeze tx, failed transfer attempts, the lift). The legend
   row comes from case/_freeze_legend.html. Hover (desktop): a compact card per node / edge from `data.hover`
   (app/tracing/hover.py: owner, status, authority, flows), built from text nodes; a click still opens the panel.
   The panel reads the same hover data for its taint, request status and next step (so card and panel agree), lists
   every movement of each link (`transfers`), and shows plain words for codes (`graph-labels`), never a flag code,
   a placeholder's internal id or an asserted hop's synthetic hash. */
(function () {
  "use strict";
  const dataEl = document.getElementById("graph-data");
  const container = document.getElementById("cy");
  if (!dataEl || !container || typeof cytoscape === "undefined") return;
  const elements = JSON.parse(dataEl.textContent);
  const flagEl = document.getElementById("flag-text");
  const FLAG_TEXT = flagEl ? JSON.parse(flagEl.textContent) : {};
  // plain words for the trace's codes (app/tracing/hover.py display_labels): flags, address types, why the walk
  // stopped, data sources, recommendation kinds. A code without a label is shown with its underscores as spaces.
  const labelsEl = document.getElementById("graph-labels");
  const LABELS = labelsEl ? JSON.parse(labelsEl.textContent) : {};
  const plain = (map, code) => ((LABELS[map] || {})[code]) || String(code == null ? "" : code).replace(/_/g, " ");
  if (typeof cytoscapeDagre !== "undefined") cytoscape.use(cytoscapeDagre);

  const EXPLORER = {
    ethereum: { address: "https://etherscan.io/address/", tx: "https://etherscan.io/tx/" },
    arbitrum: { address: "https://arbiscan.io/address/", tx: "https://arbiscan.io/tx/" },
    base: { address: "https://basescan.org/address/", tx: "https://basescan.org/tx/" },
    bsc: { address: "https://bscscan.com/address/", tx: "https://bscscan.com/tx/" },
    polygon: { address: "https://polygonscan.com/address/", tx: "https://polygonscan.com/tx/" },
    tron: { address: "https://tronscan.org/#/address/", tx: "https://tronscan.org/#/transaction/" },
    bitcoin: { address: "https://mempool.space/address/", tx: "https://mempool.space/tx/" },
  };
  const usd = (v) => v == null || isNaN(Number(v)) ? "—" : "$" + Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 });
  const usdShort = (v) => {
    const n = Number(v) || 0;
    if (n >= 1e6) return "$" + (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
    if (n >= 1e3) return "$" + (n / 1e3).toFixed(n >= 1e4 ? 0 : 1) + "k";
    return "$" + n.toFixed(0);
  };
  // 0x1234…abcd: the graph shows the short form, the details panel the full value (with a copy button)
  const shortAddr = (a) => !a ? "" : a.length <= 14 ? a : a.slice(0, 6) + "…" + a.slice(-4);
  const shortTx = (h) => !h ? "" : h.length <= 22 ? h : h.slice(0, 10) + "…" + h.slice(-6);
  const trunc = (s, n) => !s ? "" : s.length <= n ? s : s.slice(0, n - 1) + "…";
  // a placeholder (an address still to be resolved, e.g. USDT_DEST_PENDING) is never shown by its internal id
  const isPlaceholder = (d) => (d.address || "").includes("_") || (d.flags || []).includes("pending_input");
  const addrText = (d) => isPlaceholder(d) ? "address not resolved" : shortAddr(d.address);
  // an asserted hop (no transaction hash yet: ASSERTED:… / …PENDING) is never shown by its synthetic id
  const syntheticTx = (h) => /^ASSERTED:|PENDING/.test(h || "");
  const maxTaint = Math.max(1, ...elements.edges.map(e => e.data.taint_usd || 0));
  const width = (t) => 1 + 5 * Math.sqrt((t || 0) / maxTaint);

  // freeze status (stop orders) -> border colour and lock badge; keep in step with .ff-fz in css/trace.css
  const FZ = {
    requested: { color: "#ffb547", label: "requested" },
    acknowledged: { color: "#ffb547", label: "acknowledged" },
    frozen: { color: "#3ddc97", label: "frozen" },
    declined: { color: "#8b98a8", label: "declined" },
    released: { color: "#2dd4bf", label: "released" },
    draft: { color: "#8b98a8", label: "draft (not sent)" },
    cited: { color: "#7cc4ff", label: "only cited" },  // no lock badge: no freeze was asked of the wallet
  };
  const TERMINAL = "#e6edf3";  // white, so it never reads as the orange "requested" border
  const REC = "#ff5c5c";
  const lockSvg = (color, open) => "data:image/svg+xml;utf8," + encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">` +
    `<circle cx="12" cy="12" r="11" fill="#0b0f14" stroke="${color}" stroke-width="2"/>` +
    `<path d="${open ? "M9 11V8.5a3 3 0 0 1 5.8-1" : "M9 11V8.5a3 3 0 0 1 6 0V11"}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round"/>` +
    `<rect x="7" y="11" width="10" height="7" rx="1.5" fill="${color}"/></svg>`);
  const LOCK = Object.fromEntries(Object.entries(FZ).filter(([k]) => k !== "cited")
    .map(([k, v]) => [k, lockSvg(v.color, k === "released")]));
  // on-chain issuer freeze (app/freeze): a lock with a chain link on it; keep in step with .fz-oc-mark in css/freeze.css
  const ONCHAIN = "#ff4fd0";  // magenta: no other border uses it
  const CHAIN_LOCK = "data:image/svg+xml;utf8," + encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">` +
    `<circle cx="12" cy="12" r="11" fill="#0b0f14" stroke="${ONCHAIN}" stroke-width="2"/>` +
    `<path d="M8.5 10.5V8.2a3.5 3.5 0 0 1 7 0v2.3" fill="none" stroke="${ONCHAIN}" stroke-width="2" stroke-linecap="round"/>` +
    `<rect x="6.5" y="10.5" width="11" height="7.5" rx="1.5" fill="${ONCHAIN}"/>` +
    `<path d="M10 14.2h4" stroke="#0b0f14" stroke-width="1.6" stroke-linecap="round"/>` +
    `<circle cx="9.6" cy="14.2" r="1.3" fill="none" stroke="#0b0f14" stroke-width="1.1"/>` +
    `<circle cx="14.4" cy="14.2" r="1.3" fill="none" stroke="#0b0f14" stroke-width="1.1"/></svg>`);
  // freeze-status nodes keep a minimum on-screen diameter (FZ_MIN_PX) and a lock badge of at most 0.6 × that
  // diameter (15 CSS px at most), so the coin colour and chain shape stay visible next to the badge at any zoom.
  // The style functions read `view.z`; keepReadable updates it and re-styles these nodes on zoom.
  const view = { z: 1 };
  const FZ_MIN_PX = 18;
  const zoomK = (cap) => Math.min(cap, Math.max(1, 1 / view.z));
  const fzDiam = (e) => Math.max(e.data("size") || 18, FZ_MIN_PX / view.z);
  const fzBadge = (e) => LOCK[e.data("freeze_status")] ? Math.min(15 * zoomK(Infinity), 0.6 * fzDiam(e)) : 0;
  const FZ_BORDER = { requested: 6, acknowledged: 3.5, frozen: 6, declined: 3, released: 3.5, draft: 2.5, cited: 2 };
  const fzBorder = (e) => Math.min((FZ_BORDER[e.data("freeze_status")] || 2) * zoomK(2.6), 0.15 * fzDiam(e));
  const ocBadge = (e) => Math.min(15 * zoomK(Infinity), 0.6 * fzDiam(e));
  const ocBorder = (e) => Math.min(9 * zoomK(2.6), 0.2 * fzDiam(e));

  // name, then address and value, under the node (a column of nodes stays compact; the details panel has
  // the full values). A recommended node reserves two more lines (RESERVED_LINES), where its red callout is drawn
  // (the callout box is ~16px tall at font 10: text 10 + padding 2 × 2 + border 1 × 2), so dagre keeps room for it.
  const labelFor = (d) => {
    if (d.callout) return d.text;
    const name = d.entity || d.label;
    const value = d.value_label || "";
    const base = name ? trunc(name, 20) + "\n" + addrText(d) + (value ? " " + value : "")
      : addrText(d) + (value ? "\n" + value : "");
    return d.recommended ? base + "\n\u2800".repeat(RESERVED_LINES) : base;
  };
  const RESERVED_LINES = 2;
  // an asserted link says so on the graph itself (not only by its dashes): "? ETH · asserted"
  const edgeLabel = (d) => (d.amount_label || "") + (d.asserted && !d.virtual ? " · asserted" : "");
  const CALLOUT_GAP_PX = 4;  // zoomed out, a callout keeps this much room (CSS px) from neighbouring nodes
  // node (10px) and edge (9px) labels are switched on together once a node label renders at LABEL_MIN_PX CSS px
  // or more. graph.js decides, not Cytoscape's min-zoomed-font-size: that rounds zoom × devicePixelRatio up to a
  // power of two, so on a Retina screen it drew every label at 4-5 px. Zoomed further out, the overview labels
  // take over; callouts, lock badges and rings keep a readable on-screen size at any zoom (see keepReadable)
  const LABEL_MIN_PX = 8.5;
  const calloutText = (r) => "⚑ Stop order → " + trunc(r.short || r.entity, 16);

  const cy = cytoscape({
    container,
    elements,
    minZoom: 0.08,
    maxZoom: 4,
    style: [
      { selector: "node", style: {
          "shape": "data(shape)", "label": (e) => labelFor(e.data()),
          "background-color": "data(color)", "border-width": 1.5, "border-color": "#0b0f14",
          "width": "data(size)", "height": "data(size)",
          "color": "#e6edf3", "font-size": 10, "text-wrap": "wrap", "text-max-width": 130,
          "text-valign": "bottom", "text-margin-y": 2, "font-family": "JetBrains Mono, Consolas, monospace",
          "text-background-color": "#0b0f14", "text-background-opacity": 0.7, "text-background-padding": 1,
          "min-zoomed-font-size": 0,
      }},
      { selector: "node[?terminal]", style: { "border-color": TERMINAL, "border-width": 2.5 } },
      { selector: "node[risk >= 50]", style: { "border-color": "#ff5c5c", "border-width": 3 } },
      { selector: "node[type = 'victim']", style: { "border-color": "#3ddc97", "border-width": 3 } },
      { selector: "node[terminal_reason = 'context']", style: { "opacity": 0.45 } },
      // freeze status: distinct border + a lock badge on the top-right rim
      { selector: "node[?freeze_status]", style: {  // truthy only: `[attr]` also matches null
          "width": fzDiam, "height": fzDiam, "border-width": fzBorder,
          "background-image": (e) => LOCK[e.data("freeze_status")] || "none",
          "background-width": fzBadge, "background-height": fzBadge, "background-fit": "none",
          "background-position-x": "100%", "background-position-y": "0%",
          "background-offset-x": (e) => fzBadge(e) / 2, "background-offset-y": (e) => -fzBadge(e) / 2,
          "background-clip": "none", "background-image-containment": "over",
          "bounds-expansion": (e) => fzBadge(e) / 2 + 2,
      }},
      { selector: "node[freeze_status = 'requested']", style: { "border-color": FZ.requested.color, "border-style": "double" } },
      { selector: "node[freeze_status = 'acknowledged']", style: { "border-color": FZ.acknowledged.color, "border-style": "solid" } },
      { selector: "node[freeze_status = 'frozen']", style: { "border-color": FZ.frozen.color, "border-style": "solid" } },
      { selector: "node[freeze_status = 'declined']", style: { "border-color": FZ.declined.color, "border-style": "dashed" } },
      { selector: "node[freeze_status = 'released']", style: { "border-color": FZ.released.color, "border-style": "solid" } },
      { selector: "node[freeze_status = 'draft']", style: { "border-color": FZ.draft.color, "border-style": "dotted" } },
      { selector: "node[freeze_status = 'cited']", style: { "border-color": FZ.cited.color, "border-style": "dotted" } },
      // on-chain issuer freeze: drawn over any stop-order status (a fact read from the chain beats a request)
      { selector: "node[?onchain_frozen]", style: {
          "width": fzDiam, "height": fzDiam, "border-width": ocBorder, "border-color": ONCHAIN, "border-style": "double",
          "background-image": CHAIN_LOCK, "background-width": ocBadge, "background-height": ocBadge, "background-fit": "none",
          "background-position-x": "100%", "background-position-y": "0%",
          "background-offset-x": (e) => ocBadge(e) / 2, "background-offset-y": (e) => -ocBadge(e) / 2,
          "background-clip": "none", "background-image-containment": "over",
          "bounds-expansion": (e) => ocBadge(e) / 2 + 2,
      }},
      // the issuer lifted its blacklist again: dashed magenta, no badge (the funds can move)
      { selector: "node[?onchain_unfrozen]", style: {
          "width": fzDiam, "height": fzDiam, "border-width": (e) => Math.min(5 * zoomK(2.6), 0.15 * fzDiam(e)),
          "border-color": ONCHAIN, "border-style": "dashed",
      }},
      // recommended stop-order target: red dashed outer ring (pulses unless reduced motion is asked for)
      { selector: "node[?recommended]", style: {
          "outline-width": 3, "outline-color": REC, "outline-style": "dashed", "outline-offset": 5, "outline-opacity": 1,
          "transition-property": "outline-opacity, outline-offset", "transition-duration": "0.8s",
      }},
      { selector: "node[?recommended].ff-pulse", style: { "outline-opacity": 0.3, "outline-offset": 9 } },
      { selector: "node.ff-callout", style: {
          "width": 1, "height": 1, "background-opacity": 0, "border-width": 0, "outline-width": 0, "label": "data(text)",
          "color": "#ffd2d2", "font-size": 10, "font-weight": "bold", "text-valign": "center", "text-halign": "center",
          "text-wrap": "none", "text-max-width": 1000, "text-margin-y": 0,
          "text-background-color": "#5a1616", "text-background-opacity": 0.95, "text-background-padding": 2,
          "text-background-shape": "roundrectangle", "text-border-color": REC, "text-border-width": 1, "text-border-opacity": 1,
          "min-zoomed-font-size": 0, "z-index": 20, "events": "no",
      }},
      { selector: "edge", style: {
          "curve-style": "bezier", "target-arrow-shape": "triangle", "arrow-scale": 0.7,
          "width": (e) => width(e.data("taint_usd")),
          "line-color": (e) => e.data("taint_usd") > 0 ? e.data("coin_color") || "#c9a227" : "#3a4654",
          "target-arrow-color": (e) => e.data("taint_usd") > 0 ? e.data("coin_color") || "#c9a227" : "#3a4654",
          "label": (e) => edgeLabel(e.data()), "font-size": 9, "color": "#8b98a8", "text-rotation": "autorotate",
          "text-background-color": "#0b0f14", "text-background-opacity": 0.8, "text-background-padding": 1,
          "min-zoomed-font-size": 0,
      }},
      { selector: "edge[?asserted]", style: { "line-style": "dashed", "line-dash-pattern": [6, 4] } },
      { selector: "edge[?virtual]", style: { "line-style": "dotted" } },
      { selector: "edge.no-label", style: { "label": "" } },
      { selector: ".ff-lbl-off", style: { "label": "" } },
      { selector: ".dim", style: { "opacity": 0.15 } },
      { selector: "node.found", style: { "border-color": "#4f8cff", "border-width": 4, "border-style": "solid" } },
      { selector: ".ff-off", style: { "display": "none" } },
      // the timeline view's day guides (a thin line per day and its label): drawn under the graph, never hit
      { selector: "node.ff-dayline", style: { "shape": "rectangle", "width": 1, "height": "data(h)", "label": "",
          "background-color": "#5b6b7d", "background-opacity": 0.45, "border-width": 0, "events": "no", "z-index": 0 } },
      { selector: "node.ff-daylabel", style: { "shape": "round-rectangle", "width": 1, "height": 1, "label": "data(text)",
          "background-opacity": 0, "border-width": 0, "color": "#9fb0c2", "font-size": 11, "font-weight": 600,
          "text-valign": "bottom", "text-halign": "right", "text-margin-x": 4, "text-wrap": "wrap", "text-max-width": 4000,
          "text-justification": "left", "events": "no", "z-index": 0 } },
    ],
    // dagre spaces whole boxes, so it gets each node's box with its label: rows and columns never
    // overlap. A label sits below its node, not centred on it, so nodeSep must cover half the height
    // difference of two labels (one line vs two, ~6px).
    layout: { name: "dagre", rankDir: "LR", nodeDimensionsIncludeLabels: true, nodeSep: 6, rankSep: 32,
              edgeSep: 6, padding: 16 },
  });

  const real = () => cy.nodes().not(".ff-callout, .ff-day");
  const wrap = document.getElementById("ff-graph");
  const panel = document.getElementById("ff-panel");
  const info = document.getElementById("node-info");
  // every node / edge value is untrusted (fixture, provider, form input): escape before innerHTML
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (v) => Number(v) || 0;
  const copyBtn = (v, what) => `<button type="button" class="ff-copy" data-copy="${esc(v)}" title="Copy ${what}" aria-label="Copy ${what}">⧉</button>`;
  const linkable = (h) => !/PENDING|ASSERTED|→/.test(h);

  // fit `eles` (default: everything shown) into the part of the drawing area the overlays leave free: the
  // legend & filters box (bottom-left, open or collapsed) and the toolbar (top-right) sit over the graph, so the
  // fit reserves their height at the bottom / top (the recommended-actions column and the details panel already
  // narrow the drawing area). `animate` gives the duration in ms; `maxZoom` caps the zoom (a focus on one or two
  // addresses stops at FOCUS_MAX_ZOOM rather than filling the canvas).
  function fitView(eles, pad = 24, animate = 0, maxZoom = cy.maxZoom()) {
    eles = eles && eles.nonempty() ? eles : cy.elements().not(".ff-off");
    if (!eles.nonempty()) return;
    const box = container.getBoundingClientRect();
    const inset = (el, edge) => {
      if (!el || el.offsetParent === null) return 0;
      const r = el.getBoundingClientRect();
      return edge === "bottom" ? Math.max(0, box.bottom - r.top) : Math.max(0, r.bottom - box.top);
    };
    const top = Math.max(pad, inset(document.querySelector(".ff-tools"), "top") + 6);
    const bottom = Math.max(pad, inset(document.getElementById("ff-legend"), "bottom") + 6);
    const w = cy.width() - 2 * pad, h = cy.height() - top - bottom;
    let bb = eles.boundingBox();
    if (w <= 0 || h <= 0 || !bb.w || !bb.h) { cy.fit(eles, pad); if (cy.zoom() > maxZoom) cy.zoom(maxZoom); return; }
    const zoomFor = (b) => Math.min(maxZoom, cy.maxZoom(), Math.max(cy.minZoom(), Math.min(w / b.w, h / b.h)));
    let zoom = zoomFor(bb);
    // node / edge labels switch on or off at the target zoom (keepReadable): measure the box as it will be drawn
    const offThere = 10 * zoom < LABEL_MIN_PX;
    if (offThere !== !labelsShown()) {
      const lbl = real().union(cy.edges());
      lbl.toggleClass("ff-lbl-off", offThere);
      bb = eles.boundingBox();
      zoom = zoomFor(bb);
      lbl.toggleClass("ff-lbl-off", !offThere);
    }
    const pan = { x: pad + (w - zoom * bb.w) / 2 - zoom * bb.x1, y: top + (h - zoom * bb.h) / 2 - zoom * bb.y1 };
    if (animate) cy.animate({ zoom, pan, duration: animate });
    else cy.viewport({ zoom, pan });
  }

  // the open panel narrows the drawing area (the graph never hides under it); collapsed, the graph gets the full width
  function setPanel(open, refit) {
    if (!panel) return;
    const was = !panel.hidden;
    panel.hidden = !open;
    document.querySelectorAll('[data-ff-cmd="panel"]').forEach(b => b.setAttribute("aria-pressed", String(open)));
    if (wrap) wrap.classList.toggle("ff-panel-open", open);
    if (was !== open) {
      cy.resize();
      if (refit) fitView();
    }
  }

  function showNode(n, openPanel, dim = true) {
    if (!info) return;
    const d = n.data();
    const ex = EXPLORER[d.chain];
    if (d.callout) return;
    const inc = n.incomers("edge").map(e => e.data());
    const out = n.outgoers("edge").map(e => e.data());
    const x = d.hover || {};
    // one row per movement (a link between two addresses carries every transfer between them: `transfers`); an
    // asserted hop is said in words, never by its synthetic id; a cross-chain swap leg has no hash of its own
    const txOne = (t, link) => {
      const synth = syntheticTx(t.tx_hash);
      const hash = link.virtual ? `<span class="muted">cross-chain swap leg (the service's off-chain order)</span>`
        : synth ? `<b class="ff-asserted-t">asserted link</b> <span class="muted">(no transaction hash yet: not confirmed on-chain)</span>`
        : `<code title="${esc(t.tx_hash)}">${esc(shortTx(t.tx_hash))}</code>${copyBtn(t.tx_hash, "tx hash")}` +
          (ex && !t.asserted && linkable(t.tx_hash) ? ` <a href="${ex.tx + esc(t.tx_hash)}" target="_blank" rel="noopener noreferrer">↗</a>` : "");
      const when = (t.timestamp || "").replace("T", " ");
      const at = synth || t.asserted ? esc(when.slice(0, 10)) + " (date asserted)" : esc(when.slice(0, 19)) + " UTC";
      const amount = !link.virtual && t.amount == null ? esc(t.amount_label) + " (amount not on-chain)" : esc(t.amount_label);
      return `<div class="ff-tx">${hash}<br><span class="muted">${at} · ${amount} · taint ${usd(t.taint_usd)}` +
        `${t.data_source ? " · " + esc(plain("sources", t.data_source)) : ""}${t.asserted && !synth ? " · <b class='ff-asserted-t'>asserted</b>" : ""}</span>` +
        `${t.notes ? `<br><span class="muted">${esc(t.notes)}</span>` : ""}</div>`;
    };
    const partyOf = (id) => {
      const m = cy.getElementById(id);
      if (!m.nonempty()) return "";
      const p = m.data();
      return trunc(p.entity || p.label, 40) || addrText(p);
    };
    const isCtx = (link) => [link.source, link.target].some(id => {
      const m = cy.getElementById(id);
      return m.nonempty() && (m.data("flags") || []).includes("context_only");
    });
    const moves = (links) => links.reduce((k, e) => k + (e.transfers ? e.transfers.length : 1), 0);
    const linkRows = (links, dir) => links.map(e => {
      const ts = e.transfers || [e];
      return `<div class="ff-link">${dir === "in" ? "from" : "to"} <b>${esc(partyOf(dir === "in" ? e.source : e.target))}</b>` +
        `${ts.length > 1 ? ` <span class="muted">· ${ts.length} transfers</span>` : ""}${isCtx(e) ? ' <span class="muted">· pre-fraud context</span>' : ""}</div>` +
        ts.map(t => txOne(t, e)).join("");
    }).join("");
    // the same count as the hover card ("In 2 · Out 12"): the case's transfers (cross-chain swap legs included), the
    // asserted ones and the pre-fraud context transfers said apart, and the links they are drawn as
    const sideHead = (title, links) => {
      const ctx = links.filter(isCtx), own = links.filter(e => !isCtx(e));
      const k = moves(own), c = moves(ctx), a = own.reduce((s, e) => s + (e.transfers || [e]).filter(t => t.asserted && !e.virtual).length, 0);
      return `<b>${title}: ${k} transfer${k !== 1 ? "s" : ""}</b>` +
        `<span class="muted">${a ? ` · ${a} asserted` : ""}${c ? ` · + ${c} pre-fraud context` : ""}${links.length !== k + c ? ` · drawn as ${links.length} link${links.length !== 1 ? "s" : ""}` : ""}</span>`;
    };
    // a request's status as the hover card and the Block status page read it (the reply, the ticket), not the
    // letter's own state alone
    const shortEntity = (s) => String(s || "").replace(/\s*\([^)]*\)\s*/g, " ").trim();
    const authOf = (name) => (x.authorities || []).find(a => a.name === shortEntity(name) && a.sent);
    const fz = (d.stop_orders || []).map(o => {
      const a = o.match === "entity" ? authOf(o.recipient) : null;
      const chip = a ? "" : `<span class="ff-fz-t ${esc(o.status)}">${esc((FZ[o.status] || {}).label || o.status)}</span> `;
      return `<div class="ff-so">${chip}<a href="${esc(o.url)}">stop order #${esc(o.id)}</a> ${o.match === "entity" ? "to" : "citing this address, to"} <b>${esc(o.recipient)}</b>
        ${o.sent_at && !a ? `<span class="muted">· sent ${esc(o.sent_at)}</span>` : ""}
        ${a ? `<br><span class="ff-h-st ff-h-${esc(a.tone || "neutral")}">${esc(a.status)}</span>` : ""}
        ${o.amount_held ? `<br><b>${esc(o.amount_held)} ${esc(o.asset_held || "")}</b> reported held` : ""}</div>`;
    }).join("");
    const oc = d.onchain_freeze;
    const ocTx = (h) => !h ? "" : `<code title="${esc(h)}">${esc(shortTx(h))}</code>${copyBtn(h, "tx hash")}` +
      (ex && linkable(h) ? ` <a href="${ex.tx + esc(h)}" target="_blank" rel="noopener noreferrer">↗</a>` : "");
    const ocWhen = (v) => v ? esc(String(v).replace("T", " ").slice(0, 16)) + " UTC" : "—";
    const ocCheck = (c) => {
      const head = c.status === "error" ? `<span class="ff-fz-t declined">check failed: ${esc(c.error)}</span>`
        : c.blacklisted ? `<b class="ff-oc-t">${esc(c.label)}</b>`
        : `${c.unfrozen ? "removed from the blacklist" : "not blacklisted"} · balance ${esc(c.balance_label)} ${esc(c.symbol)}`;
      const u = c.unfrozen;
      const lifted = u ? `<br><b class="ff-oc-lift">Freeze lifted: the funds can move.</b> Was blacklisted ` +
        `${u.was_frozen_at_basis === "event" ? "" : "at or before "}${ocWhen(u.was_frozen_at)}` +
        `${u.last_blacklisted_balance_label ? " holding " + esc(u.last_blacklisted_balance_label) + " " + esc(c.symbol) : ""}; removed ` +
        (u.removed_at_basis === "event" ? `${ocWhen(u.removed_at)} · tx ${ocTx(u.removed_tx)}`
          : `at or before ${ocWhen(u.removed_at)} <span class="muted">(${esc(u.removed_note || "")})</span>`) : "";
      const burnt = c.balance_destroyed ? `<br>balance fell from ${esc(c.balance_destroyed.balance_before_label)} to 0 while blacklisted` +
        ` (${c.balance_destroyed.basis === "event" ? "DestroyedBlackFunds " + ocWhen(c.balance_destroyed.at) : "at or before " + ocWhen(c.balance_destroyed.at)})` : "";
      const when = c.blacklisted ? (c.frozen_at_basis === "event"
        ? `<br>blacklisted ${ocWhen(c.frozen_at)} · freeze tx ${ocTx(c.freeze_tx_hash)}`
        : `<br>frozen at or before ${ocWhen(c.frozen_at)} <span class="muted">(${esc(c.frozen_at_note || "the check time")})</span>`) + burnt : lifted;
      const fails = c.failed_count ? `<br>transfer attempts failing since ${ocWhen(c.first_failed_at)} (${esc(c.failed_count)}):` +
        (c.failed_txs || []).slice(0, 5).map(t => `<div class="ff-tx">${ocTx(t.hash)} <span class="muted">${esc(t.method)}</span></div>`).join("") : "";
      return `<div class="ff-so"><b>${esc(c.issuer)} ${esc(c.symbol)}</b>: ${head}` +
        (c.status === "ok" ? `<br><span class="muted">checked ${ocWhen(c.checked_at)}${c.block_number ? " · block " + esc(c.block_number) : ""} · ${esc(c.method)}${c.raw_sha256 ? " · sha256 " + esc(String(c.raw_sha256).slice(0, 12)) + "…" : ""}</span>` : "") +
        when + fails + "</div>";
    };
    const onchain = oc ? `<div class="flag ${oc.state === "frozen" ? "ff-oc-box" : oc.state === "unfrozen" ? "ff-oc-lifted" : "ff-oc-plain"}"><b>On-chain freeze check — ${esc(oc.title)}</b>${(oc.checks || []).map(ocCheck).join("")}</div>` : "";
    // who can act, its request status and the next step: the hover card's own section (app/tracing/hover.py), so the
    // card, this panel and the Recovery plan say the same. The owner's generic "Next" is shown only while nobody
    // has been asked (once a request is out, its status and the plan's move are the next step)
    const auths = x.authorities;
    const asked = (auths || []).some(a => a.sent);
    const who = auths == null ? "" : `<div class="flag ff-who"><b>Who can act</b>` +
      (auths.length ? auths.map(a => `<div class="ff-so"><b class="ff-who-n">${esc(a.name)}</b> <span class="muted">(${esc(a.role)})</span>` +
        `<br><span class="ff-h-st ff-h-${esc(a.tone || "neutral")}">${esc(a.status)}</span>` +
        (a.cited === false ? `<br><span class="ff-asserted-t">This address is not cited in the request</span>` : "") +
        (a.step ? `<br><span class="muted">Step: ${esc(a.step)}${a.more ? ` · ${esc(a.more)} more request${a.more !== 1 ? "s" : ""}` : ""}</span>` : "") +
        (a.next ? `<br><span class="ff-h-next">Next: ${esc(a.next)}</span>` : "") + "</div>").join("")
        : (x.no_authority ? `<div class="muted">${esc(x.no_authority)}</div>` : "")) +
      (x.move ? `<div class="ff-h-next">Next: ${esc(x.move)}</div>` : "") +
      (x.next_unavailable ? `<div class="muted">Next move unavailable (could not be read)</div>` : "") + "</div>";
    const ow = d.owner;
    const owner = ow ? `<div class="flag ff-owner"><b>Owner: ${esc(ow.owner_label)}</b> · ${esc(ow.kind_label)} · confidence <b>${esc(ow.confidence)}</b> <span class="muted">(${esc(ow.source_label)})</span>` +
      (ow.ask && !asked ? `<br>${esc(ow.ask)}` : "") + (ow.lines || []).map(l => `<br><span class="muted">${esc(l)}</span>`).join("") + "</div>" : "";
    const r = d.recommended;
    const rec = r ? `<div class="flag ff-rec-box"><b class="ff-rec-h">Recommended: ${esc(plain("rec_kind", r.kind))} → ${esc(r.short || r.entity)}</b><br>${esc(r.reason)}
        ${r.next ? `<br><span class="ff-h-next">Next${r.plan_rank ? ` (Recovery plan #${esc(r.plan_rank)})` : ""}: ${esc(r.next)}</span>` : ""}
        ${r.draft_id ? `<br><b>Stop order #${esc(r.draft_id)} is drafted, not sent yet.</b>` : r.drafted ? "<br><b>A stop order is drafted, not sent yet.</b>" : ""}
        ${r.url ? `<br><a class="btn small primary ff-rec-go" href="${esc(r.url)}">${r.draft_id ? "Review draft" : "Generate letter"} →</a>` : ""}</div>` : "";
    const tn = taintOf(d);
    const place = isPlaceholder(d);
    info.innerHTML = `
      <h3>${esc(d.entity || d.label || "Address")} <span class="tag">${esc(plain("chains", d.chain))}</span> <span class="tag">${esc(plain("types", d.type))}</span> <span class="tag ff-coin-tag" title="coin of the largest tainted inflow"><i class="ff-sw ${esc((d.coin || "other").toLowerCase())}"></i>${esc(d.coin || "")}</span></h3>
      ${place ? `<div class="ff-full ff-placeholder">Placeholder: the address is not resolved yet (the trace continues once it is)</div>`
        : `<div class="ff-full">${esc(d.address)} ${copyBtn(d.address, "address")}
        ${ex ? `<a href="${ex.address + esc(d.address)}" target="_blank" rel="noopener noreferrer" title="open in explorer">↗</a>` : ""}</div>`}
      ${owner}
      ${who}
      <div class="kv ff-kv">
        <div>Hop</div><div>${esc(d.hop)}</div>
        <div>${esc(tn.label)}</div><div><b>${esc(tn.value)}</b>${tn.share ? " " + esc(tn.share) : ""}</div>
        ${tn.note ? `<div></div><div class="muted">${esc(tn.note)}</div>` : ""}
        <div>Freeze priority</div><div><span class="risk ${num(d.risk) >= 50 ? "hi" : num(d.risk) >= 25 ? "md" : "lo"}">${num(d.risk)}</span></div>
        <div>Trace ends</div><div>${d.terminal ? "here: " + esc(plain("terminal", d.terminal_reason)) : "no — tracing continues"}</div>
        ${d.first_seen ? `<div>First seen</div><div>${esc(d.first_seen.slice(0, 10))}</div>` : ""}
      </div>
      ${onchain}
      ${rec}
      ${fz ? `<div class="flag"><b>Stop orders (${(d.stop_orders || []).length})</b>${fz}</div>` : ""}
      ${(d.flags || []).map(f => `<div class="flag"><b>${esc(plain("flags", f))}</b><br>${esc(FLAG_TEXT[f] || "")}` +
        (f === "stablecoin_freezable" && d.moved_on ? ` <b class="ff-asserted-t">The trace saw it move on from here: nothing is left to blacklist unless a balance check shows otherwise.</b>` : "") +
        `</div>`).join("")}
      <div class="flag">${sideHead("Inbound", inc)}${linkRows(inc, "in")}</div>
      <div class="flag">${sideHead("Outbound", out)}${linkRows(out, "out")}</div>`;
    if (openPanel) setPanel(true);
    cy.elements().removeClass("dim");
    if (dim) {
      cy.elements().addClass("dim");
      n.closedNeighborhood().removeClass("dim");
      n.closedNeighborhood("node").forEach(m => cy.getElementById("callout-" + m.id()).removeClass("dim"));
    }
  }

  // ------------------------------------------------------------- recommendation callouts
  // zoomed in (node labels shown), the callout is drawn at font 10 in the spare lines labelFor reserves under
  // each recommended node; zoomed out (node labels hidden), at a readable size just under the ring
  const labelsShown = () => 10 * cy.zoom() >= LABEL_MIN_PX;
  // zoomed out, callouts and overview labels keep 10 CSS px at any zoom (no cap: on a short graph with the
  // legend open the fit zoom can drop to ~0.2); the recommended ring's width is capped
  const scale = () => Math.min(2.6, Math.max(1, 1 / cy.zoom()));
  const textScale = () => Math.max(1, 1 / cy.zoom());
  const calloutScale = () => labelsShown() ? 1 : textScale();
  function placeCallout(n) {
    const c = cy.getElementById("callout-" + n.id());
    if (!c.nonempty()) return;
    let x = n.position("x"), y;
    if (labelsShown()) {
      // the label box is its lines × line height plus 1px of text background above and below: centre the
      // callout on the reserved lines at the bottom
      const lb = n.boundingBox({ includeNodes: false, includeLabels: true, includeOverlays: false, includeOutlines: false });
      const lines = labelFor(n.data()).split("\n").length;
      const lineH = (lb.h - 2) / lines;
      y = lb.y2 - 1 - lineH * RESERVED_LINES / 2;
    } else {
      // under the ring, or above it, centred or slid sideways (its far end still over the node), else to its right
      // or left: the first spot with the fewest neighbours in the way, counting their lock badges
      // (bounds-expansion) and a CALLOUT_GAP_PX margin. A callout keeps 10 CSS px, so on a zoomed-out dense
      // column it could otherwise cover a neighbour or read as belonging to it
      const kt = textScale(), nx = n.position("x"), ny = n.position("y"), off = n.height() / 2 + 16 * kt;
      const w = (calloutText(n.data("recommended")).length * 6.2 + 8) * kt, h = 18 * kt, pad = CALLOUT_GAP_PX * kt;
      const others = real().not(".ff-off").not(n)
        .map(m => m.boundingBox({ includeLabels: false, includeOverlays: false, includeOutlines: true }));
      const hits = ([cx, cy0]) => {
        const box = { x1: cx - w / 2 - pad, x2: cx + w / 2 + pad, y1: cy0 - h / 2 - pad, y2: cy0 + h / 2 + pad };
        return others.filter(b => overlaps(b, box)).length;
      };
      const slide = Math.max(0, w / 2 - n.width() / 2), side = n.width() / 2 + w / 2 + 6 * kt;
      const spots = [[nx, ny + off], [nx, ny - off], [nx + slide, ny + off], [nx - slide, ny + off],
                     [nx + slide, ny - off], [nx - slide, ny - off], [nx + side, ny], [nx - side, ny]];
      let best = spots[0], fewest = Infinity;
      for (const s of spots) {
        const k = hits(s);
        if (k < fewest) { best = s; fewest = k; }
        if (!k) break;
      }
      x = best[0];
      y = best[1];
    }
    c.position({ x, y });
  }
  // zoomed out, node labels are too small to read: the victim, one node per entity (its largest) and the
  // OVERVIEW_HOLDINGS largest wallets where funds sit (dormant / trace further: the biggest holdings, often
  // unattributed) keep a short label (name or address, and value) at a readable size instead
  const OVERVIEW_HOLDINGS = 3;
  const overview = (() => {
    const best = {};
    cy.nodes().forEach(n => {
      const d = n.data();
      const key = d.entity ? "e:" + d.entity : d.type === "victim" ? "victim" : null;
      if (key && (!best[key] || (d.value_usd || 0) > (best[key].data("value_usd") || 0))) best[key] = n;
    });
    cy.nodes().filter(n => {
      const d = n.data(), f = d.flags || [];
      return !d.callout && !d.entity && !isPlaceholder(d) && (d.value_usd || 0) >= 1000 && (f.includes("dormant") || f.includes("trace_next"));
    }).sort((a, b) => (b.data("value_usd") || 0) - (a.data("value_usd") || 0)).slice(0, OVERVIEW_HOLDINGS)
      .forEach(n => { best["h:" + n.id()] = n; });
    return cy.collection(Object.values(best)).sort((a, b) => (b.data("value_usd") || 0) - (a.data("value_usd") || 0));
  })();
  // on-screen box of a label of `chars` characters centred under a node (10px monospace ≈ 6.2px a character)
  const boxUnder = (n, chars, lines) => {
    const p = n.renderedPosition(), half = n.renderedWidth() / 2, w = chars * 6.2 + 6;
    return { x1: p.x - w / 2, x2: p.x + w / 2, y1: p.y + half + 1, y2: p.y + half + 3 + 13 * (lines || 1) };
  };
  const overlaps = (a, b) => a.x1 < b.x2 && b.x1 < a.x2 && a.y1 < b.y2 && b.y1 < a.y2;
  const overviewText = (d) => (d.entity ? trunc(d.entity, 18) : d.type === "victim" ? "Victim" : addrText(d)) +
    (d.value_label ? " " + d.value_label : "");
  let overviewOn = null;
  function keepReadable() {
    const k = scale(), kc = calloutScale(), kt = textScale();
    const on = !labelsShown();
    cy.batch(() => {
      real().toggleClass("ff-lbl-off", on);
      cy.edges().toggleClass("ff-lbl-off", on);
      cy.nodes(".ff-callout").style({ "font-size": 10 * kc, "text-background-padding": 2 * kc, "text-border-width": kc });
      if (view.z !== cy.zoom()) {
        view.z = cy.zoom();
        cy.nodes("[?freeze_status], [?onchain_frozen], [?onchain_unfrozen]").updateStyle();  // diameter, border and badge (fzDiam / fzBadge / fzBorder)
      }
      cy.nodes("[?recommended]").style({ "outline-width": 3 * Math.min(k, 1.8) });
      const z = cy.zoom();
      cy.nodes(".ff-daylabel").style({ "font-size": Math.max(11, 12 / z), "text-margin-x": 4 / z });
      cy.nodes(".ff-dayline").style({ "width": Math.max(1, 1 / z) });
    });
    // placed after the batch, so the label boxes have their new sizes
    cy.nodes("[?recommended]").forEach(placeCallout);
    cy.batch(() => {
      if (on) {
        // callouts first (their real on-screen boxes), then the largest nodes; a label that would collide with
        // one already placed is left out
        const taken = cy.nodes(".ff-callout").not(".ff-off").map(c => c.renderedBoundingBox({ includeLabels: true }));
        overview.forEach(n => {
          const text = overviewText(n.data());
          const box = boxUnder(n, text.length);
          if (n.data("recommended") || taken.some(t => overlaps(t, box))) {
            n.removeStyle("label font-size min-zoomed-font-size text-max-width text-wrap");
            return;
          }
          taken.push(box);
          n.style({ "label": text, "font-size": 10 * kt, "min-zoomed-font-size": 0, "text-max-width": 1000, "text-wrap": "none" });
        });
      } else if (overviewOn !== false) {
        overview.removeStyle("label font-size min-zoomed-font-size text-max-width text-wrap");
      }
      overviewOn = on;
    });
  }
  cy.batch(() => {
    cy.nodes("[?recommended]").forEach(n => {
      cy.add({ group: "nodes", data: { id: "callout-" + n.id(), callout: true, target_id: n.id(), text: calloutText(n.data("recommended")),
                                       shape: "rectangle", size: 1, color: "#000" },
               classes: "ff-callout", selectable: false, grabbable: false });
    });
  });
  keepReadable();
  let zoomFrame = 0;
  cy.on("zoom", () => {
    if (zoomFrame) return;
    zoomFrame = requestAnimationFrame(() => { zoomFrame = 0; keepReadable(); });
  });
  cy.on("position", "node[?recommended]", (evt) => placeCallout(evt.target));
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!reduceMotion && cy.nodes("[?recommended]").nonempty()) {
    setInterval(() => cy.nodes("[?recommended]").toggleClass("ff-pulse"), 900);
  }

  cy.on("tap", "node", (evt) => showNode(evt.target, true));
  cy.on("tap", (evt) => { if (evt.target === cy) cy.elements().removeClass("dim"); });
  cy.on("dbltap", "node", (evt) => {
    const d = evt.target.data(); const ex = EXPLORER[d.chain];
    if (ex && !d.address.includes("_")) window.open(ex.address + encodeURIComponent(d.address), "_blank", "noopener");
  });

  // ------------------------------------------------------------- hover cards (data.hover: app/tracing/hover.py)
  // a compact card near the pointer on node / edge mouseover, desktop only (a fine pointer that can hover): on touch a
  // tap keeps opening the details panel. Hidden on mouseout, pan, zoom, drag and tap. Built from text nodes only.
  const canHover = !!(window.matchMedia && window.matchMedia("(hover: hover) and (pointer: fine)").matches);
  const tip = document.createElement("div");
  tip.className = "ff-hover";
  tip.hidden = true;
  tip.setAttribute("role", "tooltip");
  (wrap || container.parentNode).appendChild(tip);
  const usd0 = (v) => v == null || isNaN(Number(v)) ? "—" : "$" + Number(v).toLocaleString(undefined, { maximumFractionDigits: Number(v) < 10 ? 2 : 0 });
  // the wallet's taint as the card and the details panel both say it: its own, the USD traced through a service's
  // payout wallet, or an upper bound (reached only over asserted links with no on-chain amount; the sender's same
  // untraced remainder is counted at each of its asserted destinations)
  function taintOf(d) {
    const st = (d.hover || {}).status || {};
    const tn = st.taint || { usd: d.taint_usd, share: num(d.taint_fraction), through: false,
                             upper: !!d.upper_bound, peers: d.asserted_peers || 0 };
    const sh = tn.share, upper = !!tn.upper && !tn.through, peers = Number(tn.peers) || 0;
    return {
      label: tn.through ? "Traced through" : upper ? "Tainted, up to" : "Tainted",
      value: (upper ? "≤ " : "") + usd0(tn.usd),
      share: sh == null ? "" : `(${sh > 0 && sh < 0.001 ? "<0.1" : (100 * sh).toFixed(1)}% of loss)`,
      note: upper ? "Upper bound: it arrived only over an asserted link with no on-chain amount (unconfirmed)" +
        (peers ? `; the same remainder is also counted at ${peers} other asserted destination${peers !== 1 ? "s" : ""}` : "")
        : tn.through ? "A service's payout wallet: the case funds passed through it (no taint of its own)" : "",
    };
  }
  const el = (tag, cls, text) => {
    const x = document.createElement(tag);
    if (cls) x.className = cls;
    if (text != null) x.textContent = String(text);
    return x;
  };
  const line = (parent, text, tone) => parent.appendChild(el("div", "ff-h-l" + (tone ? " ff-h-" + tone : ""), text));
  const section = (title) => { const s = el("div", "ff-h-sec"); s.appendChild(el("div", "ff-h-t", title)); tip.appendChild(s); return s; };
  // the priced USD ("+": some transfer has no USD), else why there is none: "asserted" (no on-chain amount), "no USD
  // price" (an on-chain amount of a token without a price); the swap legs; the traced (tainted) USD whenever the
  // priced figure alone would understate or misstate it
  const valueParts = (s, traced) => {
    const p = [], priced = Number(s.usd) > 0, swaps = s.swaps || [], t = Number(s.taint_usd) || 0;
    if (priced || (!s.partial && !swaps.length)) p.push(usd0(s.usd) + (s.partial ? "+" : ""));
    else if (s.partial) {
      if (s.asserted) p.push("amount not on-chain (asserted)");
      if (s.unpriced || !s.asserted) p.push("no USD price");
    }
    if (s.assets && s.assets.length) p.push(s.assets.join(", "));
    if (swaps.length) p.push("cross-chain swap " + swaps.join(", "));
    if (traced && t > 0 && (s.capped || !priced || s.partial || swaps.length || Math.abs(t - Number(s.usd)) >= 1)) {
      p.push((s.capped ? "≤ " : "") + usd0(t) + " traced");
    }
    return p;
  };
  // the count of the case's transfers (pre-fraud context apart), the asserted ones said apart: the details panel
  // counts the same way
  const sideText = (label, s) => !s ? label + " —" : !s.n ? `${label} 0`
    : [`${label} ${s.n}${s.asserted_n ? ` (${s.asserted_n} asserted)` : ""}`, ...valueParts(s, true)].join(" · ");
  const txLine = (parent, t) => {
    const r = el("div", "ff-h-l");
    r.appendChild(el("span", t.dir === "out" ? "ff-h-out" : "ff-h-in", t.dir === "out" ? "→ " : t.dir === "in" ? "← " : ""));
    r.appendChild(el("span", t.context ? "ff-h-muted" : null, t.amount + (t.usd != null ? " " + usd0(t.usd) : "") + (t.context ? " (pre-fraud)" : "")));
    r.appendChild(el("span", "ff-h-muted", " · " + (t.at || "time unknown") + (t.party ? (t.dir === "out" ? " · to " : " · from ") + t.party : "")));
    r.appendChild(el("span", "ff-h-tx", " " + t.tx));
    parent.appendChild(r);
  };
  function nodeCard(d) {
    const x = d.hover || {};
    tip.replaceChildren();
    const head = el("div", "ff-h-head");
    head.appendChild(el("b", null, trunc(d.entity || d.label || "Address", 48)));
    head.appendChild(el("span", "ff-h-addr", " " + addrText(d) + " · " + (d.chain || "")));
    tip.appendChild(head);
    const o = x.owner;
    if (o) {
      const s = section("Owner");
      line(s, o.known ? o.name + (o.category_label ? " · " + o.category_label : "") : o.self_custody ? o.category_label
        : "unknown · " + (o.category_label || "owner not identified"));
      if (o.label && o.label !== o.name) line(s, trunc(o.label, 110), "muted");
      if (o.deposit) line(s, o.deposit, "warn");
      if (o.float) line(s, o.float, "warn");
      if (o.pooled) line(s, o.pooled, "warn");
    }
    const st = x.status;
    if (st) {
      const s = section("Status");
      if (st.onchain == null) line(s, "On-chain readings unavailable (could not be read)", "muted");
      if (st.tags && st.tags.length) {
        const t = el("div", "ff-h-tags");
        st.tags.forEach(g => t.appendChild(el("span", "ff-h-tag ff-h-" + (g.tone || "muted"), g.t)));
        s.appendChild(t);
      }
      const tn = taintOf(d);
      line(s, `${tn.label} ${tn.value}${tn.share ? " " + tn.share : ""} · priority ${num(d.risk)}`);
      if (tn.note) line(s, tn.note, "muted");
      (st.onchain || []).forEach(c => {
        if (c.unchecked) line(s, `${c.issuer} ${c.symbol || ""}: balance not checked yet (run a freeze check)`, "warn");
        else if (c.checked) {
          line(s, `${c.issuer} ${c.symbol}: ${c.balance}${c.usd != null ? " (≈" + usd0(c.usd) + ")" : ""} · ` +
            (c.blacklisted ? "blacklisted (frozen on-chain)" : c.lifted ? "freeze lifted: the funds can move" : "not blacklisted") +
            ` · checked ${c.checked}`, c.blacklisted ? "ok" : c.lifted ? "danger" : null);
        } else line(s, `${c.issuer} ${c.symbol}: no good on-chain reading yet`, "muted");
        if (c.failed) line(s, `Last check failed ${c.failed.at} (${c.failed.error})` + (c.checked ? ": the last good reading is shown" : ""), "danger");
      });
      if (st.dropped) line(s, "Balance dropped since the trace: funds left this wallet", "danger");
      const al = st.alerts;
      if (al && al.n) {
        line(s, `Moved after the trace: ${al.n} watch alert${al.n !== 1 ? "s" : ""}` +
          (al.unacknowledged ? ` (${al.unacknowledged} unacknowledged)` : " (acknowledged)") + `, latest ${al.last}`, "danger");
      } else if (st.watched) {
        line(s, st.checked ? `On the watch list: no movement since the trace · last checked ${st.checked}`
          : "On the watch list: not checked since the trace", "muted");
      }
    }
    if (x.authorities == null) line(section("Authority"), "Request status unavailable (could not be read)", "muted");
    else {
      const s = section("Authority");
      if (!x.authorities.length && x.no_authority) line(s, x.no_authority, "muted");
      x.authorities.forEach(a => {
        const r = el("div", "ff-h-l");
        r.appendChild(el("b", null, a.name));
        r.appendChild(el("span", "ff-h-muted", ` (${a.role}) `));
        r.appendChild(el("span", "ff-h-st ff-h-" + (a.tone || "neutral"), a.status));
        s.appendChild(r);
        if (a.cited === false) line(s, "This address is not cited in the request", "warn");
        if (a.step || a.more) line(s, (a.step ? "Step: " + a.step : "") + (a.more ? `${a.step ? " · " : ""}${a.more} more request${a.more !== 1 ? "s" : ""}` : ""), "muted");
        if (a.next) line(s, "Next: " + a.next, "next");
      });
      if (x.move) line(s, "Next: " + x.move, "next");
      if (x.next_unavailable) line(s, "Next move unavailable (could not be read)", "muted");
      if (!s.querySelector(".ff-h-l")) s.remove();
    }
    const f = x.flows;
    if (f === null) line(section("Flows"), "Flows unavailable (could not be read)", "muted");
    if (f) {
      const s = section("Flows");
      line(s, sideText("In", f.in));
      line(s, sideText("Out", f.out));
      if ((f.in && f.in.capped) || (f.out && f.out.capped)) {
        line(s, "≤: capped at what reached this wallet (asserted links can count the same remainder more than once)", "muted");
      }
      if (f.first) line(s, f.first === f.last ? "Case transfer " + f.first : `First case transfer ${f.first} · last ${f.last}`, "muted");
      if (f.context) line(s, `${f.context} pre-fraud context transfer${f.context !== 1 ? "s" : ""} (shown for attribution, not the case's money)`, "muted");
      (f.top || []).forEach(t => txLine(s, t));
      if (f.in && f.out && f.in.n + f.out.n + (f.context || 0) > (f.top || []).length) line(s, `top ${(f.top || []).length} by value; click for every transfer`, "muted");
    }
  }
  function edgeCard(e) {
    const d = e.data(), x = d.hover;
    tip.replaceChildren();
    const head = el("div", "ff-h-head");
    head.appendChild(el("b", null, x && x.n > 1 ? `${x.n} transfers` : d.virtual ? "Cross-chain swap leg" : "Transfer"));
    const name = (n) => trunc(n.data("entity") || n.data("label") || addrText(n.data()), 24);
    head.appendChild(el("span", "ff-h-addr", " " + name(e.source()) + " → " + name(e.target())));
    tip.appendChild(head);
    const s = el("div", "ff-h-sec");
    tip.appendChild(s);
    if (x) {
      line(s, [...valueParts(x, false), "tainted " + usd0(x.taint_usd)].join(" · "));
      if (x.n > 1 && x.first) line(s, `First ${x.first} · last ${x.last}`, "muted");
      const shown = x.transfers || [];
      shown.forEach(t => txLine(s, t));
      if (x.n > shown.length) line(s, `top ${shown.length} by value of ${x.n}; click for all`, "muted");
    } else {
      line(s, (d.amount_label || "") + (d.amount_usd != null ? " · " + usd0(d.amount_usd) : "") + ` · tainted ${usd0(d.taint_usd)}`);
      txLine(s, { amount: d.asset || "", at: (d.timestamp || "").replace("T", " ").slice(0, 16) + " UTC", tx: syntheticTx(d.tx_hash) ? "asserted (no tx hash yet)" : shortTx(d.tx_hash) });
    }
  }
  let tipAt = null, tipFrame = 0;
  function placeTip() {
    tipFrame = 0;
    if (tip.hidden || !tipAt) return;
    const gap = 14, w = tip.offsetWidth, h = tip.offsetHeight, vw = window.innerWidth, vh = window.innerHeight;
    let x = tipAt.x + gap, y = tipAt.y + gap;
    if (x + w > vw - 4) x = tipAt.x - gap - w;
    if (y + h > vh - 4) y = tipAt.y - gap - h;
    tip.style.left = Math.max(4, Math.min(x, vw - w - 4)) + "px";
    tip.style.top = Math.max(4, Math.min(y, vh - h - 4)) + "px";
  }
  const track = (evt) => {
    const oe = evt.originalEvent;
    if (!oe || oe.clientX == null) return false;
    tipAt = { x: oe.clientX, y: oe.clientY };
    if (!tipFrame) tipFrame = requestAnimationFrame(placeTip);
    return true;
  };
  const hideTip = () => { tip.hidden = true; tipAt = null; };
  if (canHover) {
    cy.on("mouseover", "node", (evt) => {
      if (evt.target.data("callout") || !track(evt)) return;
      nodeCard(evt.target.data());
      tip.hidden = false;
    });
    cy.on("mouseover", "edge", (evt) => {
      if (!track(evt)) return;
      edgeCard(evt.target);
      tip.hidden = false;
    });
    cy.on("mousemove", "node, edge", (evt) => { if (!tip.hidden) track(evt); });
    cy.on("mouseout", "node, edge", hideTip);
    cy.on("viewport tapstart grab", hideTip);
    container.addEventListener("mouseleave", hideTip);
  }

  // ------------------------------------------------------------- focus (find, recommended actions)
  // the details panel opens first: it narrows the drawing area, so the fit that follows keeps the focused
  // addresses clear of it. Every focused address (and its neighbours) stays undimmed.
  const FOCUS_MAX_ZOOM = 1.6;
  function focusOn(hits, pad) {
    showNode(hits[0], true);
    cy.resize();
    const near = hits.closedNeighborhood();
    near.removeClass("dim");
    near.nodes().forEach(m => cy.getElementById("callout-" + m.id()).removeClass("dim"));
    fitView(near, pad, 250, FOCUS_MAX_ZOOM);
  }

  // ------------------------------------------------------------- controls
  const zoomBy = (f) => {
    const z = Math.min(cy.maxZoom(), Math.max(cy.minZoom(), cy.zoom() * f));
    cy.zoom({ level: z, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };
  const fullscreenEl = () => document.fullscreenElement || document.webkitFullscreenElement;
  function toggleFullscreen() {
    if (!wrap) return;
    if (fullscreenEl()) (document.exitFullscreen || document.webkitExitFullscreen).call(document);
    else (wrap.requestFullscreen || wrap.webkitRequestFullscreen || (() => {})).call(wrap);
  }
  const onFs = () => { cy.resize(); fitView(); };
  document.addEventListener("fullscreenchange", onFs);
  document.addEventListener("webkitfullscreenchange", onFs);

  let edgeLabels = true;
  const commands = {
    "zoom-in": () => zoomBy(1.25),
    "zoom-out": () => zoomBy(0.8),
    "fit": () => fitView(),
    "labels": (btn) => {
      edgeLabels = !edgeLabels;
      cy.edges().toggleClass("no-label", !edgeLabels);
      btn.setAttribute("aria-pressed", String(edgeLabels));
    },
    "panel": () => setPanel(panel ? panel.hidden : false, true),
    "fullscreen": toggleFullscreen,
    "timeline": (btn) => setTimeline(!timeline, btn),
  };
  // ------------------------------------------------------------- timeline view (an alternative layout)
  // The same graph (every wallet, transfer, colour, size, hover card and the details panel) laid out over time:
  // T = 0 (the victim's first outgoing transfer) at the left edge, then Day 0, Day 1, … as equal-width 24-hour
  // columns to the right; each wallet sits where the victim's funds first reached it, y = its row in the flow
  // view, so the branches keep their shape.
  const DAY = 86400000;
  let timeline = false, flowPos = null;
  const tlNote = document.getElementById("ff-timeline-note");
  const ts = (e) => { const t = Date.parse(e.data("timestamp") || ""); return Number.isFinite(t) ? t : null; };
  // when the funds first reached each wallet, never before t0: a link dated before the theft (a PI report's
  // "pre-theft deposit, context only") does not move a wallet left of T = 0; its own date stays on the link
  function nodeTimes(t0) {
    const inAt = {}, outAt = {};
    const first = (m, k, t) => { if (m[k] == null || t < m[k]) m[k] = t; };
    cy.edges().forEach(e => {
      const t = ts(e); if (t == null || t < t0) return;
      first(inAt, e.target().id(), t); first(outAt, e.source().id(), t);
    });
    const out = {};
    real().forEach(n => { const id = n.id(); out[id] = inAt[id] != null ? inAt[id] : outAt[id]; });
    // a wallet with no timed transfer: right after the latest wallet that sends to it (else T = 0)
    for (let pass = 0; pass < 3; pass++) real().forEach(n => {
      if (out[n.id()] != null) return;
      const prev = n.incomers("node").map(m => out[m.id()]).filter(v => v != null);
      if (prev.length) out[n.id()] = Math.max(...prev) + 60000;
    });
    real().forEach(n => { if (out[n.id()] == null) out[n.id()] = t0; });
    return out;
  }
  function setTimeline(on, btn) {
    const b = btn || document.querySelector('[data-ff-cmd="timeline"]');
    if (on === timeline) return;
    timeline = on;
    if (b) b.setAttribute("aria-pressed", String(on));
    cy.remove(cy.nodes(".ff-day"));
    if (!on) {
      if (flowPos) cy.batch(() => real().forEach(n => { if (flowPos[n.id()]) n.position(flowPos[n.id()]); }));
      if (tlNote) tlNote.hidden = true;
      fitView(); keepReadable();
      return;
    }
    const victimOut = real().filter("[type = 'victim']").outgoers("edge").map(ts).filter(v => v != null);
    const allT = cy.edges().map(ts).filter(v => v != null);
    if (!allT.length) { timeline = false; if (b) b.setAttribute("aria-pressed", "false"); return; }
    if (!flowPos) { flowPos = {}; real().forEach(n => { flowPos[n.id()] = { ...n.position() }; }); }
    const t0 = victimOut.length ? Math.min(...victimOut) : Math.min(...allT);
    const times = nodeTimes(t0);
    const dayOf = (t) => Math.floor((t - t0) / DAY);
    // x is linear in time: every day the same width. Wallets reached minutes apart (one transaction, or asserted
    // hops dated alike) still keep STEP apart in time order (ties in their flow order), so the width of a day is
    // what its busiest day needs (within MIN_DAY..MAX_DAY).
    const slotOf = (n) => times[n.id()] + ":" + String(Math.round(flowPos[n.id()].x)).padStart(8, "0");
    const bySlot = (p, q) => { const [pt, px] = p.split(":"), [qt, qx] = q.split(":"); return pt - qt || (px < qx ? -1 : px > qx ? 1 : 0); };
    const slots = [...new Set(real().map(slotOf))].sort(bySlot);
    const perDay = {};
    slots.forEach(k => { const d = dayOf(+k.split(":")[0]); perDay[d] = (perDay[d] || 0) + 1; });
    const STEP = 85, PAD = 50, MIN_DAY = 400, MAX_DAY = 1600;
    const dayW = Math.min(MAX_DAY, Math.max(MIN_DAY, 2 * PAD + STEP * Math.max(...Object.values(perDay))));
    const slotX = {};
    let prevX = -Infinity;
    slots.forEach(k => {
      const lin = PAD + (+k.split(":")[0] - t0) / DAY * dayW;
      prevX = slotX[k] = Math.max(lin, prevX + STEP);
    });
    const pos = {};
    const placed = [];
    real().sort((p, q) => times[p.id()] - times[q.id()]).forEach(n => {
      const px = slotX[slotOf(n)], w = n.width(), h = n.height();
      let y = flowPos[n.id()].y;
      const hit = () => placed.find(o => Math.abs(o.x - px) < (o.w + w) / 2 + 20 && Math.abs(o.y - y) < (o.h + h) / 2 + 26);
      for (let k = 0, o; k < 60 && (o = hit()); k++) y = o.y + (o.h + h) / 2 + 28;
      placed.push({ x: px, y, w, h }); pos[n.id()] = { x: px, y };
    });
    const last = Math.max(0, Math.floor((prevX - PAD) / dayW));
    const ys = placed.map(o => o.y), top = Math.min(...ys) - 80, bottom = Math.max(...ys) + 60;
    const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const fmt = (t) => { const d = new Date(t); return d.getUTCDate() + " " + MON[d.getUTCMonth()] + " " + d.toISOString().slice(11, 16); };
    const guide = (id, cls, data, gx, gy) => ({ group: "nodes", classes: "ff-day " + cls, data: { id, ...data },
      position: { x: gx, y: gy }, grabbable: false, selectable: false });
    const guides = [];
    for (let d = 0; d <= last + 1; d++) {
      guides.push(guide("ffday-l" + d, "ff-dayline", { h: bottom - top }, d * dayW, (top + bottom) / 2));
      if (d <= last) guides.push(guide("ffday-t" + d, "ff-daylabel",
        { text: (d ? "Day " + d : "Day 0 (T = 0)") + "\n" + fmt(t0 + d * DAY) }, d * dayW, top));
    }
    cy.batch(() => { cy.add(guides); real().forEach(n => n.position(pos[n.id()])); });
    // the day labels sit above the topmost wallet at a fixed on-screen size, so their place depends on the zoom
    const nodeTop = Math.min(...placed.map(o => o.y - o.h / 2));
    const lift = () => {
      const z = cy.zoom(), y = nodeTop - 48 / z;
      cy.batch(() => {
        cy.nodes(".ff-daylabel").positions(n => ({ x: n.position("x"), y }));
        cy.nodes(".ff-dayline").forEach(n => { n.data("h", bottom - y); n.position({ x: n.position("x"), y: (y + bottom) / 2 }); });
      });
    };
    const early = cy.edges().filter(e => { const t = ts(e); return t != null && t < t0; }).length;
    if (tlNote) {
      tlNote.textContent = `Timeline: T = 0 is ${victimOut.length ? "the victim's first transfer" : "the first transfer"}, ` +
        `${fmt(t0)} UTC; each column is 24 hours (Day 0 to Day ${last}). Each wallet sits where the funds first reached it.` +
        (early ? ` ${early} link${early === 1 ? "" : "s"} dated before T = 0 (context only, not the victim's funds) keep their own date on the link.` : "");
      tlNote.hidden = false;
    }
    fitView(); keepReadable(); lift(); fitView(); lift(); keepReadable();
  }

  document.querySelectorAll("[data-ff-cmd]").forEach(btn => {
    btn.addEventListener("click", () => { const f = commands[btn.dataset.ffCmd]; if (f) f(btn); });
  });

  const find = document.querySelector("[data-ff-find]");
  if (find) {
    find.addEventListener("input", () => {
      const q = find.value.trim().toLowerCase();
      cy.nodes().removeClass("found");
      if (q.length < 3) { cy.elements().removeClass("dim"); return; }
      const hits = real().filter(n => {
        const d = n.data();
        return [d.address, d.entity, d.label].some(v => v && String(v).toLowerCase().includes(q));
      });
      hits.addClass("found");
      if (hits.length === 1) focusOn(hits, 80);
      else if (hits.length) fitView(hits, 80, 250, FOCUS_MAX_ZOOM);
    });
  }
  // until the user pans or zooms, every resize (trace.js sizing the container, the recommendations column
  // opening or closing, a window resize) refits the whole graph
  let userMoved = false;
  cy.on("tapstart scrollzoom", () => { userMoved = true; });
  const settle = () => { cy.resize(); if (!userMoved) { fitView(); keepReadable(); } };
  window.addEventListener("resize", settle);
  requestAnimationFrame(settle);
  window.addEventListener("load", settle, { once: true });

  // ------------------------------------------------------------- legend filters
  const shows = Array.from(document.querySelectorAll("[data-ff-show]"));
  function applyFilters() {
    const on = Object.fromEntries(shows.map(c => [c.dataset.ffShow, c.checked]));
    cy.batch(() => {
      real().forEach(n => {
        const d = n.data();
        const keep = (!on.recommended || !!d.recommended)
          && (!on.freeze || (!!d.freeze_status && d.freeze_status !== "draft" && d.freeze_status !== "cited"))
          && (!on.nodust || !d.dust);
        n.toggleClass("ff-off", !keep);
        cy.getElementById("callout-" + n.id()).toggleClass("ff-off", !keep);
      });
    });
    fitView(cy.elements().not(".ff-off"), 40, 200);
  }
  shows.forEach(c => c.addEventListener("change", applyFilters));

  // ------------------------------------------------------------- recommended actions column
  document.querySelectorAll("[data-ff-focus]").forEach(btn => btn.addEventListener("click", () => {
    const ids = (btn.dataset.ffFocus || "").split(",").filter(Boolean);
    const hits = cy.collection(ids.map(id => cy.getElementById(id)).filter(n => n.nonempty()));
    if (!hits.nonempty()) return;
    hits.removeClass("ff-off");
    cy.nodes().removeClass("found");
    hits.addClass("found");
    focusOn(hits, 90);
  }));
  const recs = document.getElementById("ff-recs");
  if (recs) recs.addEventListener("toggle", () => { cy.resize(); fitView(); });
  // the legend overlays the bottom of the graph: on a short graph (laptop screens) it starts collapsed
  const legend = document.getElementById("ff-legend");
  // on-chain freeze legend row (case/_freeze_legend.html): after the stop-order row, only when a node has a reading
  const ocTpl = document.getElementById("ff-lg-onchain");
  if (legend && ocTpl && ocTpl.content && cy.nodes("[?onchain_freeze]").nonempty() && !legend.querySelector("[data-ff-onchain]")) {
    const rows = legend.querySelectorAll(".ff-lg-row");
    const after = rows.length > 3 ? rows[3] : rows[rows.length - 1];
    const row = ocTpl.content.firstElementChild.cloneNode(true);
    if (after && after.parentNode) after.parentNode.insertBefore(row, after.nextSibling);
  }
  if (legend) {
    const host = document.getElementById("ff-graph");
    if (host && host.clientHeight < 600) legend.open = false;
    legend.addEventListener("toggle", settle);
  }

  // pre-load the highest-priority node's details so the demo lands on the point (whole graph stays visible;
  // on narrow screens the panel stays collapsed until asked)
  const top = real().filter(n => (n.data("risk") || 0) > 0).sort((a, b) => b.data("risk") - a.data("risk"))[0];
  if (top) {
    const wide = window.innerWidth > 1800;  // below that the graph keeps the full width
    showNode(top, wide, false);
    if (wide) fitView();
  }
})();
