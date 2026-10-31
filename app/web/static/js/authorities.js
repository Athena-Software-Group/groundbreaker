/* authorities feature behaviour — owned by the authorities feature (app/web/routes_authorities.py).
   Loaded on every page (base.html): no-op unless this feature's elements are present. No inline scripts (CSP).
   Everything here is progressive enhancement: the forms and the timeline work without it. */
(function () {
  "use strict";

  // Timeline: expand / collapse every message body at once.
  var toggle = document.getElementById("tl-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var bodies = document.querySelectorAll(".timeline details.tl-body");
      var open = Array.prototype.some.call(bodies, function (d) { return !d.open; });
      bodies.forEach(function (d) { d.open = open; });
      toggle.textContent = open ? toggle.dataset.collapse : toggle.dataset.expand;
    });
  }

  // Deep link to one entry (#c12 / #o3): open its body.
  if (location.hash && /^#[co]\d+$/.test(location.hash)) {
    var target = document.getElementById(location.hash.slice(1));
    var details = target && target.querySelector("details.tl-body");
    if (details) { details.open = true; }
  }

  // Generate letter: show the reference picker the chosen template needs, and its description.
  var tpl = document.getElementById("letter-template");
  if (tpl) {
    var form = tpl.form;
    var first = Array.prototype.find.call(tpl.options, function (o) { return !o.disabled; });
    if (first && tpl.selectedOptions[0] && tpl.selectedOptions[0].disabled) { tpl.value = first.value; }
    var sync = function () {
      form.querySelectorAll(".auth-ref").forEach(function (box) {
        var active = box.dataset.for === tpl.value;
        box.hidden = !active;
        box.querySelectorAll("select, input").forEach(function (s) { s.disabled = !active; });
      });
      form.querySelectorAll(".auth-template-help li").forEach(function (li) {
        li.hidden = li.dataset.template !== tpl.value;
      });
    };
    tpl.addEventListener("change", sync);
    sync();
  }

  // Log correspondence: the reply deadline applies to outbound messages only.
  var dir = document.getElementById("log-direction");
  if (dir) {
    var due = dir.form.querySelector(".auth-due");
    var syncDue = function () {
      if (!due) { return; }
      var out = dir.value === due.dataset.direction;
      due.hidden = !out;
      due.querySelectorAll("input").forEach(function (i) { i.disabled = !out; });
    };
    dir.addEventListener("change", syncDue);
    syncDue();
  }
})();
