/* assistant feature behaviour — owned by the assistant feature (app/web/routes_assistant.py).
   Loaded on every page (base.html): no-op unless this feature's elements are present. No inline scripts (CSP).

   * Sub-tabs (Chat / Status summary / AI mode): switched in place; the links also work without JS.
     #assistant-summary and #assistant-mode in the URL open those sub-tabs.
   * Chat: turns go to POST /cases/{id}/assistant/chat with fetch() (JSON, CSRF token in X-CSRF-Token). The reply
     carries the messages already rendered by the server (Jinja-escaped, Markdown with raw HTML disabled and links
     limited to Aegis), so nothing the user or the model wrote is ever parsed as HTML here; what this script builds
     itself uses textContent only. A "thinking…" bubble with a timer and a Cancel button keeps the page usable
     during long model calls (~70 s); HTTP 429 (busy) offers a Retry button.
   * Typing "/" opens the command list (arrow keys, Enter / Tab to pick, Escape to close); suggestion chips and
     skill buttons fill the input and send. Without JavaScript every form posts and the page re-renders. */
(function () {
  "use strict";

  var root = document.getElementById("assistant");
  if (!root) { return; }

  // ------------------------------------------------------------------ sub-tabs
  var panels = root.querySelectorAll(".assistant-subpanel");
  var tabs = root.querySelectorAll(".assistant-subtab");

  function showSub(key, push) {
    var found = false;
    panels.forEach(function (p) { if (p.dataset.sub === key) { found = true; } });
    if (!found) { return; }
    panels.forEach(function (p) { p.hidden = p.dataset.sub !== key; });
    tabs.forEach(function (t) {
      var on = t.dataset.sub === key;
      t.classList.toggle("active", on);
      if (on) { t.setAttribute("aria-current", "page"); } else { t.removeAttribute("aria-current"); }
    });
    root.dataset.sub = key;
    if (push && window.history && window.history.replaceState) {
      var url = new URL(window.location.href);
      url.searchParams.set("tab", "assistant");
      url.searchParams.set("sub", key);
      url.hash = "";
      window.history.replaceState(null, "", url.toString());
    }
    if (key === "chat") { scrollLog(); }
  }

  root.addEventListener("click", function (ev) {
    var link = ev.target.closest(".assistant-subtab, [data-sub-link]");
    if (!link || !root.contains(link)) { return; }
    ev.preventDefault();
    showSub(link.dataset.sub || link.dataset.subLink, true);
  });

  var hash = window.location.hash;
  if (hash === "#assistant-summary") { showSub("summary", false); }
  else if (hash === "#assistant-mode" || hash === "#assistant-datapath") { showSub("mode", false); }

  // ------------------------------------------------------------------ chat
  var log = document.getElementById("assistant-log");
  var form = document.getElementById("assistant-chat-form");
  var dataEl = document.getElementById("assistant-chat-data");
  if (!log || !form || !dataEl) { scrollLog(); return; }

  var data = {};
  try { data = JSON.parse(dataEl.textContent || "{}"); } catch (e) { data = {}; }
  var skills = data.skills || [];
  var input = document.getElementById("assistant-input");
  var send = document.getElementById("assistant-send");
  var end = document.getElementById("assistant-chat-end");
  var chips = document.getElementById("assistant-suggestions");
  var status = document.getElementById("assistant-status");
  var menu = document.getElementById("assistant-autocomplete");
  var clearForm = document.getElementById("assistant-clear-form");
  var chatUrl = "/cases/" + data.case_id + "/assistant/chat";
  var busy = false;
  var controller = null;

  function csrf() {
    var f = form.querySelector("input[name=csrf_token]");
    return f ? f.value : "";
  }

  function scrollLog() {
    var l = document.getElementById("assistant-log");
    if (l) { l.scrollTop = l.scrollHeight; }
  }

  function bubble(role, who, text, extra) {
    var msg = document.createElement("div");
    msg.className = "assistant-msg " + role + (extra ? " " + extra : "");
    var w = document.createElement("div");
    w.className = "who";
    w.textContent = who;
    var t = document.createElement("div");
    t.className = "text";
    t.textContent = text;
    msg.appendChild(w);
    msg.appendChild(t);
    log.insertBefore(msg, end);
    scrollLog();
    return msg;
  }

  function setBusy(on) {
    busy = on;
    send.disabled = on;
    root.querySelectorAll(".assistant-chip, .assistant-cmd-form button").forEach(function (b) { b.disabled = on; });
    if (!on && status) { status.textContent = ""; }
  }

  function renderSuggestions(list) {
    if (!chips) { return; }
    chips.textContent = "";
    var label = document.createElement("span");
    label.className = "muted assistant-suggest-label";
    label.textContent = "Suggested:";
    chips.appendChild(label);
    (list || []).forEach(function (cmd) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "assistant-chip";
      b.dataset.command = cmd;
      b.textContent = cmd;
      b.title = "Run " + cmd;
      chips.appendChild(b);
    });
  }

  function thinking() {
    var msg = bubble("assistant", "Pythia", "Thinking", "assistant-thinking");
    var started = Date.now();
    var timer = document.createElement("div");
    timer.className = "muted assistant-generated";
    msg.appendChild(timer);
    var cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "btn small assistant-retry";
    cancel.textContent = "Cancel";
    cancel.addEventListener("click", function () { if (controller) { controller.abort(); } });
    msg.appendChild(cancel);
    var tick = function () {
      var s = Math.round((Date.now() - started) / 1000);
      timer.textContent = s + " s — model calls can take a minute or more; you can keep reading the case meanwhile.";
      if (status) { status.textContent = "Working… " + s + " s"; }
    };
    tick();
    msg._timer = window.setInterval(tick, 1000);
    return msg;
  }

  function drop(el) {
    if (!el) { return; }
    if (el._timer) { window.clearInterval(el._timer); }
    if (el.parentNode) { el.parentNode.removeChild(el); }
  }

  function failure(text, message, retry) {
    var msg = bubble("assistant", retry ? "Busy" : "Error", message, "error");
    if (retry) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "btn small assistant-retry";
      b.textContent = "Retry";
      b.addEventListener("click", function () { drop(msg); submit(text); });
      msg.appendChild(b);
    }
  }

  function submit(text) {
    text = (text || "").trim();
    if (!text || busy) { return; }
    closeMenu();
    showSub("chat", false);
    var mine = bubble("user", "You", text, "assistant-pending");
    var wait = thinking();
    setBusy(true);
    input.value = "";
    controller = window.AbortController ? new AbortController() : null;
    fetch(chatUrl, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "Accept": "application/json", "X-CSRF-Token": csrf(),
                 "X-Requested-With": "fetch" },
      body: JSON.stringify({ text: text }),
      signal: controller ? controller.signal : undefined
    }).then(function (resp) {
      return resp.json().catch(function () { return {}; }).then(function (body) {
        return { ok: resp.ok, status: resp.status, body: body };
      });
    }).then(function (r) {
      drop(wait);
      if (r.ok) {
        drop(mine);
        // server-rendered, escaped message HTML (see the header comment)
        end.insertAdjacentHTML("beforebegin", r.body.html || "");
        renderSuggestions(r.body.suggestions);
      } else if (r.status === 429) {
        drop(mine);
        input.value = text;
        failure(text, r.body.detail || "The AI service is busy. Try again in a moment.", true);
      } else {
        mine.classList.remove("assistant-pending");
        var detail = r.body.detail;
        if (typeof detail !== "string") { detail = "The request failed (" + r.status + ")."; }
        failure(text, detail, false);
      }
    }).catch(function (err) {
      drop(wait);
      if (err && err.name === "AbortError") {
        failure(text, "Cancelled here. The server may still finish the request; reload the tab to see it.", true);
      } else {
        failure(text, "The request could not be completed (network error).", true);
      }
    }).then(function () {
      controller = null;
      setBusy(false);
      scrollLog();
      input.focus();
    });
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    submit(input.value);
  });

  // command buttons: skills palette, actions inside messages (forms) and suggestion chips (buttons)
  root.addEventListener("submit", function (ev) {
    var f = ev.target;
    if (!f.classList || !f.classList.contains("assistant-cmd-form")) { return; }
    ev.preventDefault();
    var t = f.querySelector("input[name=text]");
    if (t) { input.value = t.value; submit(t.value); }
  });
  root.addEventListener("click", function (ev) {
    var chip = ev.target.closest("button.assistant-chip");
    if (!chip || chip.closest("form")) { return; }
    ev.preventDefault();
    input.value = chip.dataset.command || "";
    submit(input.value);
  });

  if (clearForm) {
    clearForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (busy) { return; }
      fetch(clearForm.action, { method: "POST", body: new FormData(clearForm), credentials: "same-origin",
                                headers: { "Accept": "application/json" } })
        .then(function (resp) { return resp.json(); })
        .then(function (body) {
          log.querySelectorAll(".assistant-msg:not(.assistant-welcome)").forEach(function (m) { drop(m); });
          renderSuggestions(body.suggestions || []);
          if (status) { status.textContent = "Conversation cleared."; }
        })
        .catch(function () { if (status) { status.textContent = "Could not clear the conversation."; } });
    });
  }

  // ------------------------------------------------------------------ "/" autocomplete
  var items = [];
  var active = -1;

  function closeMenu() {
    if (!menu) { return; }
    menu.hidden = true;
    menu.textContent = "";
    items = [];
    active = -1;
    input.removeAttribute("aria-activedescendant");
  }

  function highlight(i) {
    active = i;
    items.forEach(function (li, j) {
      li.classList.toggle("active", j === i);
      li.setAttribute("aria-selected", j === i ? "true" : "false");
    });
    if (items[i]) {
      input.setAttribute("aria-activedescendant", items[i].id);
      items[i].scrollIntoView({ block: "nearest" });
    }
  }

  function pick(i) {
    var s = items[i] && items[i]._skill;
    if (!s) { return; }
    input.value = s.command + (s.args ? " " : "");
    closeMenu();
    input.focus();
    if (!s.args) { submit(input.value); }
  }

  function openMenu() {
    if (!menu) { return; }
    var v = input.value;
    if (v.charAt(0) !== "/" || v.indexOf(" ") >= 0 || v.indexOf("\n") >= 0) { closeMenu(); return; }
    var q = v.slice(1).toLowerCase();
    // commands that start with what was typed come first (so Enter on "/st" picks /stop-orders), then
    // skills with a word of the title starting with it; the first row is highlighted
    var byCommand = skills.filter(function (s) { return s.command.slice(1).indexOf(q) === 0; });
    var byTitle = q ? skills.filter(function (s) {
      return byCommand.indexOf(s) < 0 && s.title.toLowerCase().split(/[^a-z0-9]+/).some(function (w) {
        return w.indexOf(q) === 0;
      });
    }) : [];
    var matches = byCommand.concat(byTitle);
    menu.textContent = "";
    items = [];
    matches.forEach(function (s, i) {
      var li = document.createElement("li");
      li.id = "assistant-ac-" + i;
      li.setAttribute("role", "option");
      var c = document.createElement("span");
      c.className = "mono";
      c.textContent = s.command + (s.args ? " " + s.args : "");
      var d = document.createElement("span");
      d.className = "muted";
      d.textContent = s.title + " — " + s.description;
      li.appendChild(c);
      li.appendChild(d);
      li._skill = s;
      li.addEventListener("mousedown", function (ev) { ev.preventDefault(); pick(i); });
      menu.appendChild(li);
      items.push(li);
    });
    menu.hidden = items.length === 0;
    highlight(items.length ? 0 : -1);
  }

  input.addEventListener("input", openMenu);
  input.addEventListener("blur", function () { window.setTimeout(closeMenu, 120); });
  input.addEventListener("keydown", function (ev) {
    var open = menu && !menu.hidden && items.length;
    if (open && ev.key === "ArrowDown") { ev.preventDefault(); highlight((active + 1) % items.length); return; }
    if (open && ev.key === "ArrowUp") { ev.preventDefault(); highlight((active - 1 + items.length) % items.length); return; }
    if (open && (ev.key === "Enter" || ev.key === "Tab") && active >= 0) { ev.preventDefault(); pick(active); return; }
    if (open && ev.key === "Escape") { ev.preventDefault(); closeMenu(); return; }
    if (ev.key === "Enter" && !ev.shiftKey && !ev.isComposing) { ev.preventDefault(); submit(input.value); }
  });

  if (window.location.hash === "#assistant-chat-end" || root.dataset.sub === "chat") { scrollLog(); }
})();
