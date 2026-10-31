/* trace feature behaviour — owned by the trace feature (app/web/routes_trace.py).
   Loaded on every page (base.html): no-op unless this feature's elements are present. No inline scripts (CSP).
   - [data-ff-autosubmit] forms: submit when a select changes (the run / version selector)
   - .ff-copy[data-copy] buttons: copy the full value (addresses, tx hashes) to the clipboard
   - [data-ff-filters="<table id>"]: filter rows of that table by data-* attributes and free text
   - th [data-ff-sort]: sort a table by that column (data-v of each cell, numeric or text)
   - #letter-template on an authority page opened from the graph's recommended actions
     (…/authorities/entity-N?template=stop_order#generate): pre-select that template when it applies */
(function () {
  "use strict";

  // ------------------------------------------------------------- graph height
  // Size the graph from its real offset so it ends at the bottom of the viewport at any width.
  const graphBox = document.getElementById("ff-graph");
  if (graphBox) {
    const fit = () => {
      if (document.fullscreenElement === graphBox) return;
      const top = graphBox.getBoundingClientRect().top + window.scrollY;
      graphBox.style.setProperty("--ff-graph-top", Math.max(0, Math.round(top + 16)) + "px");
    };
    fit();
    window.dispatchEvent(new Event("resize"));  // graph.js resizes the Cytoscape canvas on window resize
    window.addEventListener("resize", fit);
    window.addEventListener("load", () => { fit(); window.dispatchEvent(new Event("resize")); }, { once: true });
  }

  // ------------------------------------------------------------- deep link: pre-selected letter template
  const tplSel = document.getElementById("letter-template");
  if (tplSel) {
    const want = new URLSearchParams(window.location.search).get("template");
    const opt = want ? Array.from(tplSel.options).find((o) => o.value === want && !o.disabled) : null;
    if (opt && tplSel.value !== want) {
      tplSel.value = want;
      tplSel.dispatchEvent(new Event("change", { bubbles: true }));
    }
  }

  // ------------------------------------------------------------- download menu: close on outside click
  document.addEventListener("click", (evt) => {
    document.querySelectorAll("details.ff-menu[open]").forEach((d) => { if (!d.contains(evt.target)) d.open = false; });
  });

  // ------------------------------------------------------------- version selector
  document.querySelectorAll("form[data-ff-autosubmit]").forEach((form) => {
    form.querySelectorAll(".ff-noscript").forEach((b) => { b.hidden = true; });
    form.querySelectorAll("select").forEach((sel) => sel.addEventListener("change", () => form.submit()));
  });

  // ------------------------------------------------------------- copy buttons
  function fallbackCopy(text) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* nothing else to try */ }
    ta.remove();
  }
  document.addEventListener("click", (evt) => {
    const btn = evt.target.closest ? evt.target.closest(".ff-copy[data-copy]") : null;
    if (!btn) return;
    evt.preventDefault();
    const text = btn.getAttribute("data-copy");
    const done = () => { btn.classList.add("ok"); setTimeout(() => btn.classList.remove("ok"), 1200); };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, () => { fallbackCopy(text); done(); });
    else { fallbackCopy(text); done(); }
  });

  // ------------------------------------------------------------- table filters
  document.querySelectorAll("[data-ff-filters]").forEach((box) => {
    const table = document.getElementById(box.getAttribute("data-ff-filters"));
    if (!table || !table.tBodies.length) return;
    const rows = Array.from(table.tBodies[0].rows);
    const controls = Array.from(box.querySelectorAll("[data-ff-filter]"));
    const counter = box.querySelector("[data-ff-count]");
    function apply() {
      const want = {};
      controls.forEach((c) => { want[c.getAttribute("data-ff-filter")] = c.value.trim().toLowerCase(); });
      let shown = 0;
      rows.forEach((r) => {
        let ok = true;
        for (const [k, v] of Object.entries(want)) {
          if (!v) continue;
          const have = (r.getAttribute("data-" + k) || "").toLowerCase();
          if (k === "q" ? !have.includes(v) : have !== v) { ok = false; break; }
        }
        r.hidden = !ok;
        if (ok) shown += 1;
      });
      if (counter) counter.textContent = shown === rows.length ? `${rows.length} rows` : `${shown} of ${rows.length} rows`;
    }
    controls.forEach((c) => c.addEventListener(c.tagName === "SELECT" ? "change" : "input", apply));
    apply();
  });

  // ------------------------------------------------------------- sortable columns
  document.querySelectorAll("table").forEach((table) => {
    const heads = table.tHead ? Array.from(table.tHead.rows[0].cells) : [];
    heads.forEach((th, idx) => {
      const btn = th.querySelector("[data-ff-sort]");
      if (!btn) return;
      btn.addEventListener("click", () => {
        const numeric = btn.getAttribute("data-ff-sort") === "num";
        const dir = th.getAttribute("aria-sort") === "ascending" ? -1 : 1;
        heads.forEach((h) => h.removeAttribute("aria-sort"));
        th.setAttribute("aria-sort", dir === 1 ? "ascending" : "descending");
        const body = table.tBodies[0];
        const key = (r) => {
          const cell = r.cells[idx];
          const v = cell ? (cell.getAttribute("data-v") ?? cell.textContent) : "";
          return numeric ? (parseFloat(v) || 0) : v.toLowerCase();
        };
        const sorted = Array.from(body.rows).sort((a, b) => {
          const x = key(a), y = key(b);
          return (x < y ? -1 : x > y ? 1 : 0) * dir;
        });
        sorted.forEach((r) => body.appendChild(r));
      });
    });
  });
})();
