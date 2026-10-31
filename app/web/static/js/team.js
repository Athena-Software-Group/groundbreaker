/* team feature behaviour — owned by the team feature (app/web/routes_team.py); also the notifications
   tab / inbox and the header badge. Loaded on every page (base.html): no-op unless this feature's
   elements are present. No inline scripts (CSP). */
(function () {
  "use strict";

  // Header inbox badge: fill [data-inbox-count] when base.html provides it, else add a nav link.
  function inboxBadge() {
    var nav = document.querySelector("header.top nav");
    if (!nav || !document.querySelector("header.top .user-menu")) return;  // signed out
    var badge = document.querySelector("[data-inbox-count]");
    if (!badge) {
      var link = document.getElementById("nav-inbox");
      if (!link) {
        link = document.createElement("a");
        link.id = "nav-inbox";
        link.href = "/notifications";
        link.textContent = "Inbox ";
        if (location.pathname === "/notifications") link.className = "active";
        nav.appendChild(link);
      }
      badge = document.createElement("span");
      badge.className = "badge";
      badge.setAttribute("data-inbox-count", "");
      badge.hidden = true;
      link.appendChild(badge);
    }
    fetch("/notifications/unread-count", { credentials: "same-origin", headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d || typeof d.unread !== "number") return;
        badge.textContent = d.unread > 99 ? "99+" : String(d.unread);
        badge.hidden = d.unread === 0;
      })
      .catch(function () { /* the badge is a convenience */ });
  }

  // Role selects: show the expiry field only for external members.
  function roleForms() {
    document.querySelectorAll("[data-team-role-form]").forEach(function (form) {
      var select = form.querySelector("[data-team-role]");
      var expiry = form.querySelector("[data-team-expiry]");
      if (!select || !expiry) return;
      var sync = function () { expiry.hidden = select.value !== "external"; };
      select.addEventListener("change", sync);
      sync();
    });
  }

  // Confirmation for destructive forms (remove member, reset rules).
  function confirms() {
    document.querySelectorAll("form[data-team-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (ev) {
        if (!window.confirm(form.getAttribute("data-team-confirm"))) ev.preventDefault();
      });
    });
  }

  // Copy the one-time password.
  function copyButtons() {
    document.querySelectorAll("[data-team-copy]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var box = document.getElementById(btn.getAttribute("data-team-copy"));
        var code = box && box.querySelector("[data-team-otp]");
        if (!code || !navigator.clipboard) return;
        navigator.clipboard.writeText(code.textContent.trim()).then(function () {
          btn.textContent = "Copied";
          setTimeout(function () { btn.textContent = "Copy"; }, 1500);
        });
      });
    });
  }

  // Rule cards: dim a card while its "enabled" box is unticked.
  function ruleCards() {
    document.querySelectorAll("[data-rule-form]").forEach(function (form) {
      var box = form.querySelector("[data-rule-enabled]");
      if (!box) return;
      box.addEventListener("change", function () { form.classList.toggle("is-off", !box.checked); });
    });
  }

  inboxBadge();
  roleForms();
  confirms();
  copyButtons();
  ruleCards();
})();
