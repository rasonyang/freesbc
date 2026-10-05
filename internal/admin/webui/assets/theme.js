// Theme selection. Loaded synchronously in <head> so a pinned theme applies
// before first paint. tokens.css already follows the OS through
// color-scheme; this script only pins light or dark when the operator chose
// one, and stores that choice per browser. Storage is a convenience: when it
// is unavailable the page simply follows the OS.
(function () {
  "use strict";

  var KEY = "freesbc-theme";
  var ORDER = ["system", "light", "dark"];
  var LABEL = { system: "System", light: "Light", dark: "Dark" };
  var root = document.documentElement;

  function read() {
    try {
      var v = localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : "system";
    } catch (e) {
      return "system";
    }
  }

  function apply(mode) {
    if (mode === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", mode);
  }

  function save(mode) {
    try {
      if (mode === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, mode);
    } catch (e) { /* follow the OS next time */ }
  }

  var mode = read();
  apply(mode);

  // Wire every [data-theme-toggle] button once the DOM exists. The button
  // shows the icon of the current mode and cycles system → light → dark.
  function sync(btn) {
    btn.setAttribute("data-mode", mode);
    btn.setAttribute("aria-label", "Theme: " + LABEL[mode] + " (click to change)");
    btn.title = "Theme: " + LABEL[mode];
    var use = btn.querySelector("use");
    if (use) use.setAttribute("href", "#i-theme-" + mode);
  }

  document.addEventListener("DOMContentLoaded", function () {
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    buttons.forEach(function (btn) {
      sync(btn);
      btn.addEventListener("click", function () {
        mode = ORDER[(ORDER.indexOf(mode) + 1) % ORDER.length];
        apply(mode);
        save(mode);
        buttons.forEach(sync);
      });
    });
  });
})();
