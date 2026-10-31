// Block status page (app/web/routes_blocks.py). No inline scripts (CSP): progressive enhancement only,
// every form works without JavaScript.
(function () {
  "use strict";
  const AMOUNT = new Set(["frozen", "hold_placed", "funds_returned", "acknowledged"]);

  // filters: apply on change
  document.querySelectorAll("form[data-autosubmit]").forEach(function (form) {
    form.querySelectorAll("select, input[type=checkbox]").forEach(function (el) {
      el.addEventListener("change", function () { form.submit(); });
    });
  });

  // Confirm form: the amount / asset fields only for statuses that carry an amount
  document.querySelectorAll("select[data-amount-toggle]").forEach(function (sel) {
    const row = sel.closest("form").querySelector("[data-amount-row]");
    if (!row) return;
    const sync = function () { row.hidden = !AMOUNT.has(sel.value); };
    sel.addEventListener("change", sync);
    sync();
  });

  // a link to /cases/<id>/blocks#o12 opens that row's Confirm form
  const key = (window.location.hash || "").slice(1);
  if (/^[oc]\d{1,12}$/.test(key)) {
    const tr = document.getElementById(key);
    const box = tr && tr.querySelector("details[data-open-if-hash]");
    if (box && box.querySelector("summary.primary")) box.open = true;
  }
})();
