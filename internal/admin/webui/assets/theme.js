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

  // Make a scheme change with transitions off (ui.css,
  // [data-theme-switching]), so buttons and links switch at once instead of
  // fading from the old colours. Reading a computed style flushes the new
  // scheme while the attribute is set; it comes off two frames later, after
  // that style has been painted.
  function suppress(change) {
    root.setAttribute("data-theme-switching", "");
    if (change) change();
    void window.getComputedStyle(root).color;
    window.requestAnimationFrame(function () {
      window.requestAnimationFrame(function () {
        root.removeAttribute("data-theme-switching");
      });
    });
  }

  function save(mode) {
    try {
      if (mode === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, mode);
    } catch (e) { /* follow the OS next time */ }
  }

  // The first apply runs before first paint, so nothing can transition yet.
  var mode = read();
  apply(mode);

  // Following the OS, a change of its scheme repaints the page too.
  if (window.matchMedia) {
    var dark = window.matchMedia("(prefers-color-scheme: dark)");
    if (dark.addEventListener) {
      dark.addEventListener("change", function () {
        if (mode === "system") suppress();
      });
    }
  }

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
        suppress(function () { apply(mode); });
        save(mode);
        buttons.forEach(sync);
      });
    });
  });
})();
