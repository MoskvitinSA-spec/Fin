/* Fin static shell: decrypts AES-GCM page blobs with a passphrase-derived key. */
(function () {
  "use strict";
  var PAGE = document.documentElement.getAttribute("data-page") || "index";
  var KEY_LS = "fin_key_v1";
  var SUB_LS = "fin_sub_sent_v1";
  var NTFY = "https://ntfy.sh/";
  var te = new TextEncoder(), td = new TextDecoder();
  var cfgPub = null, cfg = null, aesKey = null, curVersion = null;

  function b64e(buf) { var b = new Uint8Array(buf), s = ""; for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
  function b64d(str) { var s = atob(str), b = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; }
  function bust(u) { return u + (u.indexOf("?") < 0 ? "?" : "&") + "t=" + Date.now(); }
  function getJSON(u) { return fetch(bust(u), { cache: "no-store" }).then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.json(); }); }
  function getBin(u) { return fetch(bust(u), { cache: "no-store" }).then(function (r) { if (!r.ok) throw new Error("http " + r.status); return r.arrayBuffer(); }); }

  function normPass(p) { return String(p || "").trim().toLowerCase().replace(/\s+/g, "-"); }

  function deriveRaw(pass) {
    return crypto.subtle.importKey("raw", te.encode(normPass(pass)), "PBKDF2", false, ["deriveBits"]).then(function (k) {
      return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: b64d(cfgPub.salt), iterations: cfgPub.iter }, k, 256);
    });
  }
  function importAes(raw) { return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]); }
  function decrypt(buf) {
    var b = new Uint8Array(buf);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: b.slice(0, 12) }, aesKey, b.slice(12)).then(function (p) { return td.decode(p); });
  }
  function encryptStr(s) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    return crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, te.encode(s)).then(function (ct) {
      var out = new Uint8Array(12 + ct.byteLength); out.set(iv, 0); out.set(new Uint8Array(ct), 12); return b64e(out);
    });
  }

  function toast(msg, ms) {
    var t = document.getElementById("fin-toast");
    if (!t) {
      t = document.createElement("div"); t.id = "fin-toast";
      t.style.cssText = "position:fixed;left:50%;top:calc(12px + env(safe-area-inset-top,0px));transform:translateX(-50%);z-index:10001;background:#16171c;color:#f4efe6;border:1px solid rgba(242,236,224,0.16);border-radius:4px;padding:10px 14px;font:600 13px 'Avenir Next','Segoe UI',system-ui,sans-serif;max-width:90%;text-align:center;";
      document.body.appendChild(t);
    }
    t.textContent = msg; t.hidden = false;
    clearTimeout(t._h); t._h = setTimeout(function () { t.hidden = true; }, ms || 4000);
  }

  function showLogin(err) {
    var box = document.getElementById("fin-login");
    box.hidden = false;
    document.getElementById("fin-loading").hidden = true;
    var e = document.getElementById("fin-err"); e.textContent = err || "";
    var f = box, inp = document.getElementById("fin-pass"), btn = document.getElementById("fin-go");
    f.onsubmit = function (ev) {
      ev.preventDefault();
      btn.disabled = true; e.textContent = "Проверка…";
      deriveRaw(inp.value).then(function (raw) {
        return importAes(raw).then(function (k) {
          aesKey = k;
          return getBin("enc/cfg.bin").then(decrypt).then(function (txt) {
            cfg = JSON.parse(txt);
            try { localStorage.setItem(KEY_LS, b64e(raw)); } catch (x) {}
          });
        });
      }).then(function () { box.hidden = true; return loadPage(); })
        .catch(function () { aesKey = null; btn.disabled = false; e.textContent = "Неверная фраза"; });
    };
    setTimeout(function () { try { inp.focus(); } catch (x) {} }, 50);
  }

  function render(html) {
    var doc = new DOMParser().parseFromString(html, "text/html");
    document.title = doc.title || document.title;
    Array.prototype.forEach.call(document.head.querySelectorAll("[data-fin-imp]"), function (n) { n.remove(); });
    Array.prototype.forEach.call(doc.head.querySelectorAll("style,link[rel=stylesheet],meta[name=theme-color]"), function (n) {
      var c = document.importNode(n, true); c.setAttribute("data-fin-imp", "1");
      document.head.appendChild(c);
    });
    var nb = document.importNode(doc.body, true);
    document.body.replaceWith(nb);
    Array.prototype.forEach.call(nb.querySelectorAll("script"), function (old) {
      var ty = (old.getAttribute("type") || "").toLowerCase();
      if (ty && ty !== "text/javascript" && ty !== "module") return;
      var s = document.createElement("script");
      for (var i = 0; i < old.attributes.length; i++) s.setAttribute(old.attributes[i].name, old.attributes[i].value);
      s.textContent = old.textContent;
      old.replaceWith(s);
    });
  }

  function binVersion(buf) {
    return crypto.subtle.digest("SHA-256", buf).then(function (h) {
      var b = new Uint8Array(h), s = "";
      for (var i = 0; i < 6; i++) s += (b[i] < 16 ? "0" : "") + b[i].toString(16);
      return s;
    });
  }
  var inited = false;
  function loadPage() {
    return getBin("enc/" + PAGE + ".bin").then(function (buf) {
      return Promise.all([decrypt(buf), binVersion(buf).catch(function () { return null; })]);
    }).then(function (r) {
      var y = window.scrollY || 0;
      curVersion = r[1];
      render(r[0]);
      afterRender();
      if (inited) window.scrollTo(0, y);
      inited = true;
    });
  }

  /* ---------- optimistic updates (Расходы): instant UI, persisted until the site catches up ---------- */
  var PEND_LS = "fin_pending_v1", PEND_TTL = 12 * 3600e3;
  function loadPend() { try { var a = JSON.parse(localStorage.getItem(PEND_LS) || "[]"); return Array.isArray(a) ? a : []; } catch (x) { return []; } }
  function savePend(a) { try { localStorage.setItem(PEND_LS, JSON.stringify(a)); } catch (x) {} }
  function jsonEl(id) { var e = document.getElementById(id); if (!e) return null; try { return JSON.parse(e.textContent); } catch (x) { return null; } }
  function num(raw) { var v = parseFloat(String(raw == null ? "" : raw).replace(/\s/g, "").replace(",", ".")); return isFinite(v) ? v : null; }
  function fmtRub(n) {
    var a = Math.round(Math.abs(n)).toString().replace(/\B(?=(\d{3})+(?!\d))/g, " ");
    return (n < 0 ? "\u2212" : "") + a + " \u20bd";
  }
  function reconcile() {
    var acks = jsonEl("fin-acks") || {}, now = Date.now(), keep = [], failed = 0;
    loadPend().forEach(function (p) {
      if (!p || !p.nonce) return;
      if (Object.prototype.hasOwnProperty.call(acks, p.nonce)) { if (!acks[p.nonce]) failed++; return; }
      if (now - (p.ts || 0) > PEND_TTL) return;
      keep.push(p);
    });
    savePend(keep);
    if (failed) toast("Действие не применилось — проверь и повтори", 7000);
    return keep;
  }
  function applyRec() {
    if (PAGE !== "recurring") return;
    var st = jsonEl("rec-state");
    if (!st) return;
    var pend = reconcile();
    if (!pend.length) return;  // published page is authoritative
    var paid = {}, pendKeys = {};
    (st.applied || []).forEach(function (k) { paid[k] = 1; });
    var bal = (typeof st.rub_balance === "number") ? st.rub_balance : null;
    var rows = Array.prototype.slice.call(document.querySelectorAll("#view-panel tr.cal-row[data-id]"));
    var info = {};
    rows.forEach(function (r) { info[r.getAttribute("data-id") + ":" + r.getAttribute("data-due")] = { amt: num(r.getAttribute("data-amt")) || 0, cur: r.getAttribute("data-cur") || "RUB" }; });
    var balTouched = false;
    pend.forEach(function (p) {
      if (p.kind === "pay") {
        var k = p.id + ":" + p.due, it = info[k] || { amt: p.amt || 0, cur: p.cur || "RUB" };
        pendKeys[k] = 1;
        var rub = it.cur === "RUB" && bal !== null && it.amt > 0;
        if (p.paid && !paid[k]) { paid[k] = 1; if (rub) { bal -= it.amt; balTouched = true; } }
        else if (!p.paid && paid[k]) { delete paid[k]; if (rub) { bal += it.amt; balTouched = true; } }
      } else if (p.kind === "set") { bal = p.amount; balTouched = true; }
      else if (p.kind === "adj") { bal = (bal || 0) + p.amount; balTouched = true; }
    });
    var hero = document.getElementById("rub-hero"), meta = document.getElementById("rub-hero-meta");
    if (hero && balTouched) {
      hero.textContent = bal === null ? "\u2014" : fmtRub(bal);
      hero.classList.toggle("is-empty", bal === null);
      if (meta) meta.textContent = "только что \u00b7 синхронизация\u2026";
    }
    var running = bal, rate = num(st.rate), keep = num(st.fx_keep) || 0.92;
    rows.forEach(function (r) {
      var k = r.getAttribute("data-id") + ":" + r.getAttribute("data-due"), it = info[k], isPaid = !!paid[k];
      var cb = r.querySelector('input[type="checkbox"]'), flag = r.querySelector(".paid-flag"), cell = r.querySelector(".col-st");
      if (cb) cb.checked = isPaid;
      if (flag) flag.value = isPaid ? "1" : "0";
      r.classList.toggle("is-paid", isPaid);
      if (pendKeys[k]) r.classList.add("is-pending"); else r.classList.remove("is-pending");
      var html;
      if (isPaid) html = '<span class="paid-dash" title="оплачено">\u2014</span>';
      else if (it.cur !== "RUB") html = '<span class="aed-mark" title="не с рублевого счёта">AED</span>';
      else if (running === null) html = '<span class="no" title="не хватит">\u2715</span>';
      else if (running + 1e-9 >= it.amt) { running -= it.amt; html = '<span class="ok" title="хватает">\u2713</span>'; }
      else {
        running -= it.amt;
        var deficit = Math.max(0, -running), kk = null;
        if (deficit > 0 && rate && rate > 0) kk = Math.max(1, Math.ceil(deficit / (rate * keep) / 1000));
        html = kk !== null ? '<span class="no short-k" title="недостаток, тыс. AED (курс ЦБ + комиссия 8%)">' + kk + "</span>"
          : '<span class="no" title="не хватит">\u2715</span>';
      }
      if (cell) cell.innerHTML = html;
    });
  }
  function addPending(form, action, nonce) {
    if (PAGE !== "recurring") return null;
    var fd = new FormData(form), p = null;
    if (action === "/recurring-pay") {
      var id = String(fd.get("id") || ""), due = String(fd.get("due") || "");
      if (!id || !due) return null;
      var flag = String(fd.get("paid") || "").toLowerCase();
      var tr = form.closest ? form.closest("tr") : null;
      p = { kind: "pay", id: id, due: due, paid: /^(1|on|true|yes)$/.test(flag),
            amt: tr ? num(tr.getAttribute("data-amt")) : null, cur: tr ? tr.getAttribute("data-cur") : null };
    } else if (action === "/rub-set") {
      var a = num(fd.get("amount")); if (a === null) return null;
      p = { kind: "set", amount: a };
    } else if (action === "/rub-adjust") {
      var d = num(fd.get("amount")); if (d === null || d === 0) return null;
      p = { kind: "adj", amount: d };
    }
    if (!p) return null;
    p.nonce = nonce; p.ts = Date.now();
    var a2 = loadPend(); a2.push(p); savePend(a2);
    applyRec();
    return p;
  }
  function dropPending(nonce) {
    savePend(loadPend().filter(function (p) { return p && p.nonce !== nonce; }));
  }

  /* ---------- actions (Расходы forms) via ntfy ---------- */
  function sendToBox(obj) {
    obj.ts = Date.now();
    obj.nonce = obj.nonce || b64e(crypto.getRandomValues(new Uint8Array(9)));
    return encryptStr(JSON.stringify(obj)).then(function (body) {
      if (body.length > 3900) throw new Error("too big");
      return fetch(NTFY + cfg.topic, { method: "POST", body: body, headers: { "Content-Type": "text/plain" } });
    }).then(function (r) { if (!r.ok) throw new Error("ntfy " + r.status); });
  }
  function submitForm(form) {
    var action = form.getAttribute("action") || "";
    var body = new URLSearchParams(new FormData(form)).toString();
    var nonce = b64e(crypto.getRandomValues(new Uint8Array(9)));
    var opt = null;
    try { opt = addPending(form, action, nonce); } catch (x) { opt = null; }
    if (opt && opt.kind !== "pay") { try { form.reset(); } catch (x) {} }
    toast(opt ? "Готово" : "Отправка…", opt ? 2000 : 10000);
    fastPollUntil = Date.now() + 5 * 60000;
    sendToBox({ t: "action", path: action, body: body, nonce: nonce }).then(function () {
      if (!opt) toast("Сохранено · обновится примерно через минуту", 6000);
      if (form.closest && form.closest("#edit-panel")) {
        var c = document.getElementById("btn-cancel"); if (c) c.click();
      }
    }).catch(function () {
      var say = function () { toast("Не отправлено — проверь интернет", 6000); };
      if (opt) {
        dropPending(nonce);
        loadPage().then(say, say);  // roll the optimistic change back
      } else say();
    });
  }
  HTMLFormElement.prototype.submit = function () { submitForm(this); };

  /* ---------- auto refresh ---------- */
  var fastPollUntil = 0, lastPoll = 0;
  function busy() {
    var a = document.activeElement;
    if (a && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName) && a.type !== "checkbox") return true;
    var ep = document.getElementById("edit-panel");
    return !!(ep && !ep.hidden);
  }
  var refreshing = false;
  function pollVersion() {
    var now = Date.now(), fast = now < fastPollUntil || (PAGE === "recurring" && loadPend().length > 0);
    var every = fast ? 10000 : 25000;
    if (now - lastPoll < every || document.hidden || refreshing) return;
    lastPoll = now;
    getJSON("version.json").then(function (v) {
      var nv = v && v.files ? v.files[PAGE] : null;
      if (nv && nv !== curVersion && !busy()) {
        refreshing = true;  // re-render in place, no manual reload needed
        return loadPage().catch(function () {}).then(function () { refreshing = false; });
      }
    }).catch(function () {});
  }

  /* ---------- web push ---------- */
  var swReadyP = null;
  function pushBar() {
    if (document.getElementById("dash-push-bar")) return;
    var canSW = "serviceWorker" in navigator;
    var canPush = canSW && "PushManager" in window && "Notification" in window;
    var st = document.createElement("style");
    st.textContent = "body{padding-bottom:calc(76px + env(safe-area-inset-bottom,0px))!important;}" +
      "#dash-push-bar{position:fixed;left:0;right:0;bottom:0;z-index:10000;padding:8px 16px calc(8px + env(safe-area-inset-bottom,0px));background:#0e0f12;border-top:1px solid rgba(242,236,224,0.16);box-sizing:border-box;}" +
      "#dash-push-btn{display:block;width:100%;max-width:980px;margin:0 auto;appearance:none;-webkit-appearance:none;border:1px solid rgba(242,236,224,0.16);background:#16171c;color:#f4efe6;font-family:\"Avenir Next\",\"Segoe UI\",system-ui,sans-serif;font-size:14px;font-weight:600;letter-spacing:0.04em;line-height:1.25;padding:12px 14px;border-radius:4px;min-height:44px;cursor:pointer;}" +
      "#dash-push-btn.is-granted{color:#8fbf9a;border-color:rgba(143,191,154,0.4);cursor:default;}#dash-push-btn.is-denied,#dash-push-btn.is-missing{color:#9a958b;cursor:default;}#dash-push-btn:disabled{opacity:1;cursor:default;}";
    st.setAttribute("data-fin-imp", "1");
    document.head.appendChild(st);
    var bar = document.createElement("div"); bar.id = "dash-push-bar";
    var btn = document.createElement("button"); btn.type = "button"; btn.id = "dash-push-btn";
    bar.appendChild(btn); document.body.appendChild(bar);
    function paint(kind, label, en) { btn.className = kind ? "is-" + kind : ""; btn.textContent = label; btn.disabled = !en; }
    function paintPerm() {
      if (!canPush) { paint("missing", "Добавь на экран Домой в Safari", false); return; }
      var p = Notification.permission;
      if (p === "granted") paint("granted", "Уведомления включены", false);
      else if (p === "denied") paint("denied", "Уведомления запрещены", false);
      else paint("", "Включить уведомления", true);
    }
    function u8(k) { var pad = "=".repeat((4 - k.length % 4) % 4); return b64d((k + pad).replace(/-/g, "+").replace(/_/g, "/")); }
    function subscribe(reg, force) {
      return reg.pushManager.getSubscription().then(function (s) {
        return s || reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: u8(cfg.vapid) });
      }).then(function (s) {
        var j = s.toJSON(), mark = j.endpoint + "|" + Math.floor(Date.now() / (7 * 864e5));
        if (!force && localStorage.getItem(SUB_LS) === mark) return;
        return sendToBox({ t: "sub", sub: j }).then(function () { localStorage.setItem(SUB_LS, mark); });
      });
    }
    paintPerm();
    var firstTime = !swReadyP;
    if (!swReadyP) swReadyP = canSW ? navigator.serviceWorker.register("sw.js", { scope: "./" }).catch(function () { return null; }) : Promise.resolve(null);
    var swReady = swReadyP;
    if (firstTime && canPush && Notification.permission === "granted") swReady.then(function (r) { if (r) return subscribe(r, false); }).catch(function () {});
    btn.addEventListener("click", function () {
      if (!canPush || Notification.permission === "denied") return;
      var go = function (state) {
        paintPerm(); if (state !== "granted") return;
        return swReady.then(function (r) { return navigator.serviceWorker.ready; }).then(function (r) { return subscribe(r, true); })
          .then(function () { paintPerm(); toast("Уведомления включены", 3000); })
          .catch(function () { paintPerm(); toast("Не удалось подписаться", 4000); });
      };
      if (Notification.permission === "granted") { go("granted"); return; }
      var q = Notification.requestPermission();
      if (q && q.then) q.then(go).catch(paintPerm); else go(Notification.permission);
    });
  }

  var listening = false;
  function afterRender() {
    try { applyRec(); } catch (x) {}
    pushBar();
    if (listening) return;
    listening = true;
    document.addEventListener("submit", function (ev) { ev.preventDefault(); submitForm(ev.target); }, true);
    setInterval(pollVersion, 5000);
    var wake = function () { if (!document.hidden) { lastPoll = 0; pollVersion(); } };
    document.addEventListener("visibilitychange", wake);
    window.addEventListener("pageshow", wake);
    window.addEventListener("focus", wake);
    window.addEventListener("storage", function (e) { if (e.key === PEND_LS) { try { applyRec(); } catch (x) {} } });
  }

  getJSON("config.json").then(function (c) {
    cfgPub = c;
    var stored = null; try { stored = localStorage.getItem(KEY_LS); } catch (x) {}
    if (!stored) return showLogin("");
    return importAes(b64d(stored)).then(function (k) {
      aesKey = k;
      return getBin("enc/cfg.bin").then(decrypt).then(function (t) { cfg = JSON.parse(t); });
    }).then(loadPage, function () {
      try { localStorage.removeItem(KEY_LS); } catch (x) {}
      aesKey = null; showLogin("Фраза изменилась — введи заново");
    });
  }).catch(function () {
    var l = document.getElementById("fin-loading"); l.textContent = "Нет связи. Повтор…";
    setTimeout(function () { location.reload(); }, 15000);
  });
})();
