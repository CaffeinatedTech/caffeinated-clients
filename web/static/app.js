/* App glue: theme toggle and PWA registration (see REQUIREMENTS F10, F9.6).
   The click is delegated so it survives htmx body swaps; the guard stops htmx
   from re-binding listeners when it re-executes the head script on boost. */
(function () {
  if (window.__ccAppInit) return;
  window.__ccAppInit = true;

  var root = document.documentElement;

  function syncToggles() {
    var dark = root.classList.contains("dark");
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      btn.setAttribute("aria-pressed", String(dark));
    });
  }

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || typeof target.closest !== "function") return;
    var btn = target.closest("[data-theme-toggle]");
    if (!btn) return;
    var dark = !root.classList.contains("dark");
    root.classList.toggle("dark", dark);
    try {
      localStorage.setItem("cc-theme", dark ? "dark" : "light");
    } catch (e) {
      /* storage unavailable: the toggle still works for this visit */
    }
    syncToggles();
  });

  syncToggles();
  document.addEventListener("htmx:afterSettle", syncToggles);

  // Service worker registration is HTTPS-only; *not* registering on plain
  // HTTP keeps local dev functional without install/offline (F9.6). The dev
  // build is also skipped: its stable ?v=dev URLs would let a cache-first
  // worker pin stale assets, whereas real builds change the version per deploy.
  var build = document.body ? document.body.getAttribute("data-build") : "";
  if (build && build !== "dev" && "serviceWorker" in navigator && window.isSecureContext) {
    window.addEventListener("load", function () {
      navigator.serviceWorker.register("/sw.js").catch(function () {});
    });
  }
})();
