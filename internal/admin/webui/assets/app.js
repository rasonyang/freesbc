// FreeSBC admin SPA. Plain ES5-compatible script, no build step, served
// from the embedded FS under a CSP that forbids inline script and style:
// set styles through the CSSOM (el.style.x = ...), never via markup.
(function () {
  "use strict";

  var STATUS_URL = "/api/status";
  var CALLS_URL = "/api/calls";
  var CONFIG_RAW_URL = "/api/config/raw";
  var CONFIG_VALIDATE_URL = "/api/config/validate";

  var POLL_MS = 5000;
  // A dashboard request that has not answered by now is abandoned, so one
  // hung endpoint cannot hold the next poll back or pile requests up.
  // Keep it below POLL_MS.
  var FETCH_TIMEOUT_MS = 4000;
  // Port-pool utilisation thresholds for the meter. A full pool fails new
  // calls (media_port_allocation_failure_total), so warn well before it.
  var PORTS_WARN = 0.8;
  var PORTS_CRIT = 0.95;

  var sessionExpired = false;

  function $(id) { return document.getElementById(id); }

  // ---- views (hash-routed so a reload keeps the tab) ----

  var links = document.querySelectorAll(".nav-link[data-view]");
  var VIEWS = ["dashboard", "config"];

  function show(name) {
    if (VIEWS.indexOf(name) < 0) name = "dashboard";
    VIEWS.forEach(function (v) { $("view-" + v).hidden = v !== name; });
    links.forEach(function (a) {
      if (a.dataset.view === name) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    // First time the Config tab is opened, fetch the running config
    // automatically instead of showing an empty editor.
    if (name === "config") loadConfigIfEmpty();
  }

  window.addEventListener("hashchange", function () { show(location.hash.slice(1)); });

  // ---- session-expired handling ----

  function showSessionExpired() {
    if (sessionExpired) return;
    sessionExpired = true;
    $("session-banner").hidden = false;
    setLive("expired", "Signed out");
  }

  // Any successful response proves the browser holds working credentials
  // again (for example after it re-prompted), so the expired state ends.
  function clearSessionExpired() {
    if (!sessionExpired) return;
    sessionExpired = false;
    $("session-banner").hidden = true;
  }

  // fetchJSON performs a same-origin GET and parses JSON, abandoning it
  // after FETCH_TIMEOUT_MS. Basic Auth credentials are already attached by
  // the browser (same-origin reuse). On 401 it flags the session as
  // expired; on other failures it rejects so the caller can keep
  // last-known-good data on screen.
  function fetchJSON(url) {
    var ctl = typeof AbortController === "function" ? new AbortController() : null;
    var timer = ctl ? setTimeout(function () { ctl.abort(); }, FETCH_TIMEOUT_MS) : null;
    var opts = { credentials: "same-origin" };
    if (ctl) opts.signal = ctl.signal;
    return fetch(url, opts).then(function (res) {
      if (res.status === 401) {
        showSessionExpired();
        throw new Error("unauthorized");
      }
      if (!res.ok) {
        throw new Error(url + ": " + res.status);
      }
      clearSessionExpired();
      return res.json();
    }).then(function (data) {
      clearTimeout(timer);
      return data;
    }, function (err) {
      clearTimeout(timer);
      throw err;
    });
  }

  // ---- formatting ----

  function fmtDuration(sec) {
    sec = Math.max(0, sec | 0);
    var d = Math.floor(sec / 86400);
    var h = Math.floor((sec % 86400) / 3600);
    var m = Math.floor((sec % 3600) / 60);
    var s = sec % 60;
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + s + "s";
    return s + "s";
  }

  function fmtClock(date) {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
  }

  function fmtInt(n) {
    return n == null ? "—" : Number(n).toLocaleString("en-US");
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ---- live indicator ----

  function setLive(state, text) {
    $("live").setAttribute("data-state", state);
    $("live-text").textContent = text;
  }

  // ---- dashboard ----

  function renderStatus(data) {
    $("header-version").textContent = "v" + data.version;
    $("stat-version").textContent = data.version;
    $("stat-uptime").textContent = fmtDuration(data.uptime_seconds);
    $("stat-active-calls").textContent = fmtInt(data.active_calls);
    renderPorts(data.ports || {});
    renderListeners(data.listeners || []);
  }

  function renderPorts(ports) {
    var value = $("stat-ports");
    var meter = $("ports-meter");
    var pct = $("ports-pct");
    value.textContent = "";
    if (ports.in_use == null || !ports.total) {
      value.textContent = "—";
      pct.textContent = "—";
      return;
    }
    var ratio = Math.min(1, ports.in_use / ports.total);
    value.appendChild(document.createTextNode(fmtInt(ports.in_use) + " "));
    value.appendChild(el("small", null, "/ " + fmtInt(ports.total)));

    var level = ratio >= PORTS_CRIT ? "critical" : ratio >= PORTS_WARN ? "warning" : "normal";
    var shown = (ratio * 100).toFixed(ratio > 0 && ratio < 0.01 ? 1 : 0);
    meter.firstElementChild.style.width = (ratio * 100) + "%";
    meter.setAttribute("aria-valuenow", shown);
    meter.setAttribute("data-level", level);
    $("ports-foot").setAttribute("data-level", level);
    // The level is spelled out, not carried by colour alone.
    pct.textContent = shown + "% in use" +
      (level === "critical" ? " · pool nearly exhausted" : level === "warning" ? " · high" : "");
  }

  function renderListeners(list) {
    var ul = $("listeners");
    ul.textContent = "";
    if (list.length === 0) {
      ul.appendChild(el("li", "muted", "No listeners reported"));
      return;
    }
    list.forEach(function (l) {
      var m = /^([a-z]+):\/\/(.+)$/i.exec(l);
      var li = el("li");
      li.appendChild(el("span", "badge mono", m ? m[1].toUpperCase() : "SIP")).setAttribute("data-variant", "outline");
      var addr = el("span", "mono", m ? m[2] : l);
      addr.title = l;
      li.appendChild(addr);
      ul.appendChild(li);
    });
  }

  function renderCalls(calls) {
    var body = $("calls-body");
    body.textContent = "";
    calls = calls || [];
    $("calls-count").textContent = fmtInt(calls.length);
    $("calls-empty").hidden = calls.length > 0;
    body.parentNode.hidden = calls.length === 0;
    calls.forEach(function (c) {
      var tr = document.createElement("tr");

      var id = el("td", "mono truncate", c.call_id || c.id || "");
      id.title = c.call_id ? c.call_id + " (admin id " + c.id + ")" : (c.id || "");
      tr.appendChild(id);
      tr.appendChild(el("td", "mono", c.from == null ? "" : c.from));
      tr.appendChild(el("td", "mono", c.to == null ? "" : c.to));

      var started = el("td", "muted num", "");
      if (c.started) {
        var d = new Date(c.started);
        if (!isNaN(d)) { started.textContent = fmtClock(d); started.title = c.started; }
      }
      tr.appendChild(started);
      tr.appendChild(el("td", "num", fmtDuration(c.duration_seconds)));
      body.appendChild(tr);
    });
  }

  // pollDashboard fetches both endpoints and renders each on its own, so one
  // failing endpoint leaves the other half current. A failed half keeps its
  // last-good data and gets a "stale" badge. It resolves when both settle.
  function pollDashboard() {
    return Promise.allSettled([
      fetchJSON(STATUS_URL),
      fetchJSON(CALLS_URL)
    ]).then(function (results) {
      var st = results[0], ca = results[1];
      if (st.status === "fulfilled") renderStatus(st.value);
      if (ca.status === "fulfilled") renderCalls(ca.value);
      $("status-stale").hidden = st.status === "fulfilled";
      $("calls-stale").hidden = ca.status === "fulfilled";
      var failed = (st.status === "rejected") + (ca.status === "rejected");
      if (sessionExpired) return; // showSessionExpired already set the indicator
      if (failed === 0) setLive("live", "Live · " + fmtClock(new Date()));
      else if (failed === 1) setLive("stale", "Partial update, retrying…");
      else setLive("stale", "Connection lost, retrying…");
    });
  }

  // The next poll is scheduled when the previous one has finished, so polls
  // never overlap, however slow the server is.
  function schedulePoll() {
    setTimeout(function () {
      pollDashboard().then(schedulePoll, schedulePoll);
    }, POLL_MS);
  }

  // ---- config: read-only view, candidate validation, diff ----

  var btnLoad = $("btn-load");
  var btnDownload = $("btn-download");
  var btnValidate = $("btn-validate");
  var btnCopy = $("btn-copy-current");
  var configText = $("config-text");
  var candidateText = $("config-candidate");
  var configStatus = $("config-status");
  var validateStatus = $("validate-status");
  var validateErrors = $("validate-errors");
  var validateRestart = $("validate-restart");
  var configDiff = $("config-diff");

  // setStatus fills a toolbar status element: an icon for ok/err states plus
  // text, always set through textContent / text nodes.
  function setStatus(el, msg, kind) {
    el.textContent = "";
    if (kind) {
      var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "icon");
      svg.setAttribute("aria-hidden", "true");
      var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttribute("href", kind === "ok" ? "#i-check" : "#i-error");
      svg.appendChild(use);
      el.appendChild(svg);
    }
    el.appendChild(document.createTextNode(msg));
    if (kind) el.setAttribute("data-kind", kind);
    else el.removeAttribute("data-kind");
  }

  function setConfigStatus(msg, kind) { setStatus(configStatus, msg, kind); }

  // ---- line diff ----

  var DIFF_CONTEXT = 3;
  var DIFF_MAX_CELLS = 4000000;

  function zeros(n) {
    var z = [];
    for (var i = 0; i < n; i++) z.push(0);
    return z;
  }

  function splitLines(text) {
    if (text === "") return [];
    var lines = text.replace(/\r\n/g, "\n").split("\n");
    if (lines[lines.length - 1] === "") lines.pop();
    return lines;
  }

  // diffLines returns [{op: "eq"|"add"|"del", text}] turning a into b. It
  // trims the common head and tail, then runs an LCS table over the middle.
  // A middle too large for the table (n*m > DIFF_MAX_CELLS) comes back as one
  // delete block and one add block rather than freezing the tab.
  function diffLines(a, b) {
    var head = 0;
    while (head < a.length && head < b.length && a[head] === b[head]) head++;
    var tail = 0;
    while (tail < a.length - head && tail < b.length - head &&
           a[a.length - 1 - tail] === b[b.length - 1 - tail]) tail++;
    var am = a.slice(head, a.length - tail);
    var bm = b.slice(head, b.length - tail);
    var out = [];
    var i;
    for (i = 0; i < head; i++) out.push({ op: "eq", text: a[i] });

    var n = am.length, m = bm.length;
    if (n * m > DIFF_MAX_CELLS) {
      for (i = 0; i < n; i++) out.push({ op: "del", text: am[i] });
      for (i = 0; i < m; i++) out.push({ op: "add", text: bm[i] });
    } else {
      // lcs[i][j]: LCS length of am[i:] and bm[j:].
      var lcs = [];
      var j;
      for (i = 0; i <= n; i++) {
        lcs.push(zeros(m + 1));
      }
      for (i = n - 1; i >= 0; i--) {
        for (j = m - 1; j >= 0; j--) {
          lcs[i][j] = am[i] === bm[j] ? lcs[i + 1][j + 1] + 1
            : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
        }
      }
      i = 0; j = 0;
      while (i < n && j < m) {
        if (am[i] === bm[j]) { out.push({ op: "eq", text: am[i] }); i++; j++; }
        else if (lcs[i + 1][j] >= lcs[i][j + 1]) { out.push({ op: "del", text: am[i] }); i++; }
        else { out.push({ op: "add", text: bm[j] }); j++; }
      }
      for (; i < n; i++) out.push({ op: "del", text: am[i] });
      for (; j < m; j++) out.push({ op: "add", text: bm[j] });
    }

    for (i = a.length - tail; i < a.length; i++) out.push({ op: "eq", text: a[i] });
    return out;
  }

  // unifiedRows turns diffLines output into display rows: changed lines with
  // DIFF_CONTEXT lines of context, and a skip row for each elided run.
  function unifiedRows(ops) {
    var keep = [];
    var i, k;
    for (i = 0; i < ops.length; i++) keep.push(false);
    for (i = 0; i < ops.length; i++) {
      if (ops[i].op === "eq") continue;
      for (k = Math.max(0, i - DIFF_CONTEXT); k <= Math.min(ops.length - 1, i + DIFF_CONTEXT); k++) keep[k] = true;
    }
    var rows = [];
    var skipped = 0;
    for (i = 0; i < ops.length; i++) {
      if (!keep[i]) { skipped++; continue; }
      if (skipped) { rows.push({ op: "skip", text: "… " + skipped + " unchanged line" + (skipped === 1 ? "" : "s") }); skipped = 0; }
      var mark = ops[i].op === "add" ? "+ " : ops[i].op === "del" ? "- " : "  ";
      rows.push({ op: ops[i].op === "eq" ? "ctx" : ops[i].op, text: mark + ops[i].text });
    }
    if (skipped) rows.push({ op: "skip", text: "… " + skipped + " unchanged line" + (skipped === 1 ? "" : "s") });
    return rows;
  }

  function renderDiff() {
    var cur = splitLines(configText.value);
    var cand = splitLines(candidateText.value);
    configDiff.textContent = "";
    function row(op, text) {
      var span = document.createElement("span");
      span.className = "diff-line";
      span.setAttribute("data-op", op);
      span.textContent = text === "" ? " " : text;
      configDiff.appendChild(span);
    }
    if (!candidateText.value) { row("note", "Enter a candidate to see the diff."); return; }
    var ops = diffLines(cur, cand);
    var changed = ops.some(function (o) { return o.op !== "eq"; });
    if (!changed) { row("note", "No differences."); return; }
    unifiedRows(ops).forEach(function (r) { row(r.op, r.text); });
  }

  // ---- validate ----

  function clearValidateResult() {
    validateErrors.hidden = true;
    $("validate-errors-text").textContent = "";
    validateRestart.hidden = true;
    $("validate-restart-keys").textContent = "";
    candidateText.removeAttribute("aria-invalid");
    setStatus(validateStatus, "");
  }

  function showValidateResult(res) {
    clearValidateResult();
    if (res.valid) {
      setStatus(validateStatus, "Valid", "ok");
      if (res.restart_required && res.restart_required.length) {
        $("validate-restart-keys").textContent = res.restart_required.join(", ");
        validateRestart.hidden = false;
      }
      return;
    }
    setStatus(validateStatus, "Not valid", "err");
    $("validate-errors-text").textContent = (res.errors || []).join("\n");
    validateErrors.hidden = false;
    candidateText.setAttribute("aria-invalid", "true");
    // The alert can sit below the fold on a short viewport: bring it into
    // view and move focus to it so the reason is not one scroll away.
    validateErrors.scrollIntoView({ block: "nearest" });
    validateErrors.focus({ preventScroll: true });
  }

  var validating = false;

  btnValidate.addEventListener("click", function () {
    if (validating) return;
    validating = true;
    btnValidate.disabled = true;
    clearValidateResult();
    setStatus(validateStatus, "Validating…");
    fetch(CONFIG_VALIDATE_URL, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/x-yaml" },
      body: candidateText.value
    }).then(function (res) {
      if (res.status === 401) {
        showSessionExpired();
        throw new Error("unauthorized");
      }
      if (res.status === 413) throw new Error("Candidate too large (limit 1 MiB)");
      if (!res.ok) throw new Error("Validate failed (" + res.status + ")");
      clearSessionExpired();
      return res.json();
    }).then(showValidateResult).catch(function (err) {
      if (String(err.message || err) !== "unauthorized") {
        setStatus(validateStatus, String(err.message || err), "err");
      }
    }).then(function () {
      validating = false;
      btnValidate.disabled = false;
    });
  });

  candidateText.addEventListener("input", function () {
    clearValidateResult();
    renderDiff();
  });

  btnCopy.addEventListener("click", function () {
    candidateText.value = configText.value;
    clearValidateResult();
    renderDiff();
  });

  // ---- current file ----

  var configLoading = false;

  function loadConfig() {
    if (configLoading) return;
    configLoading = true;
    setConfigStatus("Loading…");
    fetch(CONFIG_RAW_URL, { credentials: "same-origin", cache: "no-store" }).then(function (res) {
      if (res.status === 401) {
        showSessionExpired();
        throw new Error("unauthorized");
      }
      return res.text().then(function (text) {
        if (!res.ok) {
          throw new Error("load failed: " + res.status);
        }
        clearSessionExpired();
        configText.value = text;
        renderDiff();
        setConfigStatus("Loaded", "ok");
      });
    }).catch(function (err) {
      if (String(err.message || err) !== "unauthorized") {
        setConfigStatus("Load failed", "err");
      }
    }).then(function () {
      configLoading = false;
    });
  }

  // Auto-load on first open of the Config tab; Reload re-fetches after the
  // file changes on disk.
  function loadConfigIfEmpty() {
    if (!configText.value) loadConfig();
  }

  btnLoad.addEventListener("click", loadConfig);
  renderDiff();

  // ---- download ----

  // downloadName is freesbc-<host>-<UTC timestamp>.yaml. The host is
  // location.host, so IPv6 brackets, colons and ports must not reach the
  // file system: anything outside [A-Za-z0-9.-] becomes "-".
  function downloadName(host, now) {
    var ts = now.toISOString().replace(/\.\d+Z$/, "Z").replace(/[-:]/g, "");
    return "freesbc-" + host.replace(/[^A-Za-z0-9.-]/g, "-") + "-" + ts + ".yaml";
  }

  var downloading = false;

  // Fetches the file fresh, never the textarea, and saves the exact response bytes: a Blob, not re-encoded text.
  function downloadConfig() {
    if (downloading) return;
    downloading = true;
    btnDownload.disabled = true;
    setConfigStatus("Downloading…");
    fetch(CONFIG_RAW_URL, { credentials: "same-origin", cache: "no-store" }).then(function (res) {
      if (res.status === 401) {
        showSessionExpired();
        throw new Error("unauthorized");
      }
      if (!res.ok) throw new Error("download failed: " + res.status);
      clearSessionExpired();
      return res.blob();
    }).then(function (blob) {
      var url = URL.createObjectURL(new Blob([blob], { type: "application/x-yaml" }));
      var a = document.createElement("a");
      a.href = url;
      a.download = downloadName(location.host, new Date());
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 0);
      setConfigStatus("Downloaded " + a.download, "ok");
    }).catch(function (err) {
      if (String(err.message || err) !== "unauthorized") {
        setConfigStatus("Download failed", "err");
      }
    }).then(function () {
      downloading = false;
      btnDownload.disabled = false;
    });
  }

  btnDownload.addEventListener("click", downloadConfig);

  // ---- start ----

  show(location.hash.slice(1));
  pollDashboard().then(schedulePoll, schedulePoll);
})();
