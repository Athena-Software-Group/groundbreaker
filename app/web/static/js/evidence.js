/* evidence feature behaviour — owned by the evidence feature (app/web/routes_evidence.py).
   Loaded on every page (base.html): no-op unless this feature's elements are present. No inline scripts (CSP).
   * [data-ev-filter="<selector>"]: filters the [data-ev-row] rows inside <selector> as you type.
   * [data-ev-file]: when a file is chosen and the form's title is empty, proposes the file name. */
(function () {
  "use strict";

  function initFilter(input) {
    var scope = document.querySelector(input.getAttribute("data-ev-filter"));
    if (!scope) return;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      scope.querySelectorAll("[data-ev-row]").forEach(function (row) {
        row.classList.toggle("ev-hidden", q !== "" && row.textContent.toLowerCase().indexOf(q) === -1);
      });
    });
  }

  function initFile(input) {
    input.addEventListener("change", function () {
      var form = input.form;
      var title = form && form.querySelector("[data-ev-title]");
      if (!title || title.value || !input.files || !input.files.length) return;
      title.value = input.files[0].name.replace(/\.[^.]+$/, "");
    });
  }

  function init() {
    document.querySelectorAll("[data-ev-filter]").forEach(initFilter);
    document.querySelectorAll("[data-ev-file]").forEach(initFile);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
