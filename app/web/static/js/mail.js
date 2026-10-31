/* mail feature behaviour — owned by the mail feature (app/web/routes_mail.py).
   Loaded on every page (base.html): no-op unless this feature's elements are present. No inline scripts (CSP).
   Convenience only: the server enforces every confirmation and sends at most once whatever the browser does. */
(function () {
  "use strict";

  // Preview: enable Send / Record as sent only once every confirmation box is ticked; disable it on submit.
  ["mail-send-form", "mail-record-form", "mail-retire-form"].forEach(function (id) {
    var form = document.getElementById(id);
    if (!form) { return; }
    var btn = form.querySelector("button[type=submit]");
    var boxes = form.querySelectorAll("input[data-mail-confirm]");
    var sync = function () {
      var all = Array.prototype.every.call(boxes, function (b) { return b.checked; });
      if (btn) { btn.disabled = !all; }
    };
    boxes.forEach(function (b) { b.addEventListener("change", sync); });
    sync();
    form.addEventListener("submit", function () {
      if (btn) {
        // let this submit go through, then block a second one
        window.setTimeout(function () { btn.disabled = true; btn.textContent = btn.dataset.sending || "Sending…"; }, 0);
      }
    });
  });

  // Compose: "Use it" puts the standard subject into the subject field.
  document.querySelectorAll("button[data-mail-subject-use]").forEach(function (b) {
    b.addEventListener("click", function () {
      var src = document.getElementById(b.dataset.mailSubjectUse);
      var dst = document.getElementById(b.dataset.target);
      if (src && dst) { dst.value = src.textContent.trim(); dst.focus(); }
    });
  });

  // Compose: "Add to To / Cc" types a suggested address into the free To / Cc field (once; the server validates it).
  document.querySelectorAll("button[data-mail-add]").forEach(function (b) {
    b.addEventListener("click", function () {
      var dst = document.getElementById(b.dataset.mailAdd);
      var addr = (b.dataset.address || "").trim();
      if (!dst || !addr) { return; }
      var have = dst.value.split(/[,;\s]+/).filter(function (v) { return v; });
      if (have.map(function (v) { return v.toLowerCase(); }).indexOf(addr.toLowerCase()) < 0) { have.push(addr); }
      dst.value = have.join(", ");
      dst.dispatchEvent(new Event("input", { bubbles: true }));
      dst.focus();
    });
  });

  // Compose: the live preview of the letter text (the server renders it exactly as the e-mail's HTML part:
  // everything escaped, nothing saved) and the character count.
  var body = document.getElementById("mail-body");
  if (body && body.dataset.previewUrl && window.fetch && window.FormData && window.DOMParser) {
    var target = document.getElementById(body.dataset.previewTarget);
    var count = document.getElementById(body.dataset.countTarget);
    var state = document.getElementById("mail-body-preview-state");
    var tokenEl = body.form ? body.form.querySelector("input[name=csrf_token]") : null;
    var timer = null;
    var seq = 0;
    // The server renders with raw HTML disabled; as a second line, only these elements and http(s) / mailto
    // links are copied over (anything else becomes its text), with no other attribute.
    var KEEP = { P: 1, H1: 1, H2: 1, H3: 1, H4: 1, H5: 1, H6: 1, STRONG: 1, EM: 1, UL: 1, OL: 1, LI: 1, A: 1,
                 CODE: 1, PRE: 1, BLOCKQUOTE: 1, HR: 1, BR: 1 };
    var copyNode = function (node) {
      if (node.nodeType === 3) { return document.createTextNode(node.nodeValue); }
      if (node.nodeType !== 1) { return null; }
      if (!KEEP[node.nodeName]) { return document.createTextNode(node.textContent || ""); }
      var el = document.createElement(node.nodeName);
      var href = node.nodeName === "A" ? (node.getAttribute("href") || "") : "";
      if (/^(https?:|mailto:)/i.test(href)) { el.setAttribute("href", href); el.setAttribute("rel", "noopener noreferrer"); }
      node.childNodes.forEach(function (c) { var k = copyNode(c); if (k) { el.appendChild(k); } });
      return el;
    };
    var show = function (el, html) {
      var doc = new window.DOMParser().parseFromString(html, "text/html");  // inert: nothing runs or loads
      var out = document.createDocumentFragment();
      doc.body.childNodes.forEach(function (c) { var k = copyNode(c); if (k) { out.appendChild(k); } });
      while (el.firstChild) { el.removeChild(el.firstChild); }
      el.appendChild(out);
    };
    var render = function () {
      var mine = ++seq;
      var fd = new window.FormData();
      fd.append("csrf_token", tokenEl ? tokenEl.value : "");
      fd.append("body_markdown", body.value);
      if (state) { state.textContent = "updating…"; }
      window.fetch(body.dataset.previewUrl, { method: "POST", body: fd, credentials: "same-origin",
                                              headers: { "Accept": "application/json" } })
        .then(function (r) { if (!r.ok) { throw new Error(String(r.status)); } return r.json(); })
        .then(function (data) {
          if (mine !== seq) { return; }
          if (target) { show(target, data.html || ""); }
          if (state) { state.textContent = ""; }
        })
        .catch(function () { if (mine === seq && state) { state.textContent = "(preview unavailable: Save shows it)"; } });
    };
    body.addEventListener("input", function () {
      if (count) { count.textContent = body.value.length.toLocaleString(); }
      if (timer) { window.clearTimeout(timer); }
      timer = window.setTimeout(render, 400);
    });
  }

  // Compose: a second click on Send now / Prepare / Save does nothing while the first is on its way.
  var composeForm = document.getElementById("mail-compose-form");
  // While the "Send now" confirmation waits (#confirm), the editor is locked by the server (a disabled fieldset).
  // Second line: any edit below disables the confirmation's Send, which would send the earlier, frozen message.
  var confirmPanel = document.getElementById("confirm");
  if (composeForm && confirmPanel) {
    var stale = function () {
      var sendBtn = document.getElementById("mail-send-btn");
      var note = document.getElementById("mail-confirm-stale");
      if (sendBtn) { sendBtn.disabled = true; sendBtn.dataset.stale = "1"; }
      if (note) { note.hidden = false; }
    };
    composeForm.addEventListener("input", stale);
    composeForm.addEventListener("change", stale);
    var sendForm = document.getElementById("mail-send-form");
    if (sendForm) {
      sendForm.addEventListener("submit", function (ev) {  // the confirmation boxes re-enable the button: refuse here
        var sendBtn = document.getElementById("mail-send-btn");
        if (sendBtn && sendBtn.dataset.stale === "1") { ev.preventDefault(); ev.stopImmediatePropagation(); }
      }, true);
    }
  }
  if (composeForm) {
    composeForm.addEventListener("submit", function () {
      window.setTimeout(function () {
        composeForm.querySelectorAll("button[type=submit][name=action]").forEach(function (b) { b.disabled = true; });
      }, 0);
    });
    window.addEventListener("pageshow", function () {  // back from the next page (bfcache): usable again
      composeForm.querySelectorAll("button[type=submit][name=action]").forEach(function (b) { b.disabled = false; });
    });
  }

  // Guided send: the hourglass while the Send request is on its way (the server answers once the mailbox has).
  var waitForm = document.getElementById("mail-send-form");
  var waitBox = waitForm && waitForm.dataset.mailWait ? document.getElementById(waitForm.dataset.mailWait) : null;
  if (waitForm && waitBox) {
    waitForm.addEventListener("submit", function (ev) {  // after the stale-confirmation check (capture phase above)
      if (!ev.defaultPrevented) { waitBox.hidden = false; }
    });
    window.addEventListener("pageshow", function () { waitBox.hidden = true; });  // back from the next page
  }

  // Guided send: the stepper (1 Recipients → 2 Letter → 3 Attachments → 4 Review & send) follows the edits. Display
  // only: the server checks every field again. A step's state changes only on an edit inside its own section.
  var STATE_TEXT = { done: "done", todo: "to do", error: "fix this", warn: "check", current: "now", locked: "locked" };
  var stepper = document.getElementById("mail-stepper");
  if (stepper && composeForm) {
    var stepEl = function (key) { return stepper.querySelector('[data-step="' + key + '"]'); };
    var setStep = function (key, state, text) {
      var li = stepEl(key);
      if (!li) { return; }
      li.className = "mail-step is-" + state;
      var n = li.querySelector(".mail-step-n");
      if (n) { n.textContent = state === "done" ? "✓" : String(["recipients", "letter", "attachments", "send"].indexOf(key) + 1); }
      var st = li.querySelector("[data-step-state]");
      if (st) { st.textContent = STATE_TEXT[state] || state; }
      var sum = li.querySelector("[data-step-sum]");
      if (sum && text !== null) { sum.textContent = text; }
    };
    var words = function (id) {
      var el = document.getElementById(id);
      return el ? el.value.split(/[,;\s]+/).filter(function (v) { return v; }).length : 0;
    };
    var ticked = function (sel) { return composeForm.querySelectorAll(sel).length; };
    var steps = {
      recipients: function () {
        var to = ticked("input[name=to]:checked") + words("mail-to-other");
        var cc = ticked("input[name=cc]:checked") + words("mail-cc-other") + ticked("input[name=cc_add]:checked:not(:disabled)");
        var bcc = words("mail-bcc-other");
        setStep("recipients", to ? "done" : "todo",
                to ? to + " To · " + cc + " Cc" + (bcc ? " · " + bcc + " Bcc" : "") : "choose at least one To");
      },
      letter: function () {
        var subj = document.getElementById("mail-subject");
        var text = document.getElementById("mail-body");
        var li = stepEl("letter");
        var full = subj && text && subj.value.trim() && text.value.trim();
        if (!full) { setStep("letter", "todo", "a subject and the text"); return; }
        if (li && li.classList.contains("is-warn")) { return; }  // the sender-of-record check is the server's
        setStep("letter", "done", text.value.length.toLocaleString() + " characters");
      },
      attachments: function () {
        var n = ticked("input[name=attach]:checked:not(:disabled)");
        setStep("attachments", "done", n + " file" + (n === 1 ? "" : "s") + " attached");
      }
    };
    var sections = { "step-recipients": "recipients", "step-letter": "letter", "editor": "letter", "attachments": "attachments" };
    var onEdit = function (ev) {
      var t = ev.target;
      var keys = Object.keys(sections).filter(function (id) {
        var sec = document.getElementById(id);
        return sec && t && sec.contains(t);
      });
      if (t && t.name === "cc_add") { keys.push("step-recipients"); }
      keys.forEach(function (id) { steps[sections[id]](); });
      var send = stepEl("send");
      if (send && send.classList.contains("is-todo") && send.dataset.ready) {
        var ready = ["recipients", "letter", "attachments"].every(function (k) {
          var li = stepEl(k);
          return li && (li.classList.contains("is-done") || li.classList.contains("is-warn"));
        });
        setStep("send", "todo", ready ? send.dataset.ready : "finish the steps above");
      }
    };
    composeForm.addEventListener("change", onEdit);
    composeForm.addEventListener("input", onEdit);
  }

  // Guided send: the "Sending…" screen polls the e-mail's status, then goes on (back to the page the editor was opened
  // from, with the success banner; to the editor with the error; or to the e-mail to check the mailbox).
  var sending = document.getElementById("mail-sending");
  if (sending && sending.dataset.statusUrl && sending.dataset.nextUrl && window.fetch) {
    var nextUrl = sending.dataset.nextUrl;
    var started = Date.now();
    var TEXT = {
      sent: ["Sent ✓", "The mailbox confirmed it. Taking you back…"],
      failed: ["Not sent", "The mailbox refused it. Taking you back to the editor…"],
      unknown: ["Not confirmed", "The mailbox could not confirm it. Opening the e-mail to check the mailbox…"],
      other: ["Nothing on its way", "Opening the e-mail…"]
    };
    var finish = function (state) {
      var t = TEXT[state] || TEXT.other;
      sending.className = "panel mail-sending is-" + state;
      var h = document.getElementById("mail-sending-h");
      var msg = document.getElementById("mail-sending-msg");
      if (h) { h.textContent = t[0]; }
      if (msg) { msg.textContent = t[1]; }
      var step4 = document.querySelector('#mail-stepper [data-step="send"]');
      if (step4) {
        var st4 = { sent: "done", failed: "error", unknown: "warn" }[state] || "todo";
        step4.className = "mail-step is-" + st4;
        var n4 = step4.querySelector(".mail-step-n");
        var s4 = step4.querySelector("[data-step-state]");
        var sum4 = step4.querySelector("[data-step-sum]");
        if (n4) { n4.textContent = st4 === "done" ? "✓" : "4"; }
        if (s4) { s4.textContent = STATE_TEXT[st4] || st4; }
        if (sum4) { sum4.textContent = { sent: "sent", failed: "not sent", unknown: "not confirmed" }[state] || "nothing on its way"; }
      }
      window.setTimeout(function () { window.location.replace(nextUrl); }, state === "sent" ? 900 : 1600);
    };
    var poll;
    var again = function () {
      var waited = Date.now() - started;
      if (waited > 15000) { var slow = document.getElementById("mail-sending-slow"); if (slow) { slow.hidden = false; } }
      if (waited > 180000) { window.location.replace(nextUrl); return; }  // the e-mail's page shows where it stands
      window.setTimeout(poll, waited > 15000 ? 3000 : 1000);
    };
    poll = function () {
      window.fetch(sending.dataset.statusUrl, { credentials: "same-origin", cache: "no-store",
                                                 headers: { "Accept": "application/json" } })
        .then(function (r) { if (!r.ok) { throw new Error(String(r.status)); } return r.json(); })
        .then(function (d) { if (d && d.done) { finish(d.state); } else { again(); } })
        .catch(again);
    };
    if (sending.dataset.state && sending.dataset.state !== "pending") { finish(sending.dataset.state); } else { poll(); }
  }

  // Manual mode ("Send it yourself"): copy To / Cc / subject / body to the clipboard.
  var dataEl = document.getElementById("mail-manual-data");
  if (!dataEl) { return; }
  var data;
  try { data = JSON.parse(dataEl.textContent || "{}"); } catch (e) { return; }
  var status = document.getElementById("mail-copy-status");
  var say = function (text) { if (status) { status.textContent = text; } };

  // last resort (no Clipboard API, e.g. plain http): a hidden textarea and execCommand("copy")
  var fallback = function (text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "mail-copy-scratch";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok ? Promise.resolve() : Promise.reject(new Error("copy refused"));
  };
  var copyText = function (text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () { return fallback(text); });
    }
    return fallback(text);
  };
  // the body: rich HTML (keeps headings, bold and lists in Outlook) with the plain text alongside
  var copyRich = function (html, text) {
    if (html && navigator.clipboard && navigator.clipboard.write && window.ClipboardItem) {
      var item = new window.ClipboardItem({
        "text/html": new Blob([html], { type: "text/html" }),
        "text/plain": new Blob([text], { type: "text/plain" })
      });
      return navigator.clipboard.write([item]).then(function () { return "formatted"; })
        .catch(function () { return copyText(text).then(function () { return "plain"; }); });
    }
    return copyText(text).then(function () { return "plain"; });
  };
  var labels = { to: "To addresses", cc: "Cc addresses", bcc: "Bcc addresses", subject: "Subject", body: "Body" };

  document.querySelectorAll("button[data-mail-copy]").forEach(function (b) {
    var label = b.textContent;
    b.addEventListener("click", function () {
      var what = b.dataset.mailCopy;
      var job = what === "body" ? copyRich(data.html || "", data.text || "")
        : copyText(data[what] || "").then(function () { return "plain"; });
      job.then(function (kind) {
        b.textContent = "Copied ✓";
        window.setTimeout(function () { b.textContent = label; }, 1600);
        var how = what !== "body" ? "." : (kind === "formatted" ? " (formatted, with a plain-text fallback)." :
          " as plain text.");
        say(labels[what] + " copied" + how + " Paste it into the Outlook message.");
      }).catch(function () {
        say("The browser refused the copy: select the text on the page and copy it by hand.");
      });
    });
  });
})();
