// FreeSBC admin SPA. Plain ES5-compatible script, no build step, served
// from the embedded FS under a CSP that forbids inline script and style:
// set styles through the CSSOM (el.style.x = ...), never via markup.
(function () {
  "use strict";

  var STATUS_URL = "/api/status";
  var CALLS_URL = "/api/calls";
  var CONFIG_RAW_URL = "/api/config/raw";
  var CONFIG_URL = "/api/config";

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
  var configEtag = null;

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

  // ---- config editor ----

  var btnLoad = $("btn-load");
  var btnSave = $("btn-save");
  var configText = $("config-text");
  var configStatus = $("config-status");
  var configError = $("config-error");

  function setConfigStatus(msg, kind) {
    configStatus.textContent = "";
    if (kind) {
      var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("class", "icon");
      svg.setAttribute("aria-hidden", "true");
      var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
      use.setAttribute("href", kind === "ok" ? "#i-check" : "#i-error");
      svg.appendChild(use);
      configStatus.appendChild(svg);
    }
    configStatus.appendChild(document.createTextNode(msg));
    if (kind) configStatus.setAttribute("data-kind", kind);
    else configStatus.removeAttribute("data-kind");
  }

  function clearConfigError() {
    $("config-error-text").textContent = "";
    configError.hidden = true;
    configText.removeAttribute("aria-invalid");
  }

  function showConfigError(text) {
    $("config-error-text").textContent = text;
    configError.hidden = false;
    configText.setAttribute("aria-invalid", "true");
    // The alert can sit below the fold on a short viewport: bring it into
    // view and move focus to it so the reason is not one scroll away.
    configError.scrollIntoView({ block: "nearest" });
    configError.focus({ preventScroll: true });
  }

  var configLoading = false;

  function loadConfig() {
    if (configLoading) return;
    configLoading = true;
    setConfigStatus("Loading…");
    clearConfigError();
    fetch(CONFIG_RAW_URL, { credentials: "same-origin" }).then(function (res) {
      if (res.status === 401) {
        showSessionExpired();
        throw new Error("unauthorized");
      }
      return res.text().then(function (text) {
        if (!res.ok) {
          throw new Error("load failed: " + res.status + " " + text);
        }
        clearSessionExpired();
        configEtag = res.headers.get("ETag");
        configText.value = text;
        btnSave.disabled = false;
        setConfigStatus("Loaded", "ok");
      });
    }).catch(function (err) {
      setConfigStatus("Load failed", "err");
      showConfigError(String(err.message || err));
    }).then(function () {
      configLoading = false;
    });
  }

  // Auto-load on first open of the Config tab; the Load button stays as a
  // manual refresh (e.g. after a 409 "changed on disk").
  function loadConfigIfEmpty() {
    if (!configText.value) loadConfig();
  }

  btnLoad.addEventListener("click", loadConfig);

  btnSave.addEventListener("click", function () {
    setConfigStatus("Saving…");
    clearConfigError();
    var headers = { "Content-Type": "application/x-yaml" };
    if (configEtag) headers["If-Match"] = configEtag;
    fetch(CONFIG_URL, {
      method: "PUT",
      credentials: "same-origin",
      headers: headers,
      body: configText.value
    }).then(function (res) {
      if (res.status === 401) {
        showSessionExpired();
        throw new Error("unauthorized");
      }
      return res.text().then(function (text) {
        if (res.status === 200) {
          clearSessionExpired();
          configEtag = res.headers.get("ETag") || configEtag;
          setConfigStatus("Saved", "ok");
          return;
        }
        if (res.status === 400) {
          setConfigStatus("Validation error", "err");
          showConfigError(text);
          return;
        }
        if (res.status === 409) {
          setConfigStatus("Config changed on disk — click Load to refresh", "err");
          return;
        }
        if (res.status === 413) {
          setConfigStatus("Config too large", "err");
          return;
        }
        setConfigStatus("Save failed (" + res.status + ")", "err");
        showConfigError(text);
      });
    }).catch(function (err) {
      if (String(err.message || err) !== "unauthorized") {
        setConfigStatus("Save failed", "err");
        showConfigError(String(err.message || err));
      }
    });
  });

  // ---- start ----

  show(location.hash.slice(1));
  pollDashboard().then(schedulePoll, schedulePoll);
})();
