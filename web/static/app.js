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

  // Secret reveal: a revealed body re-masks after 5 minutes (F5.3). The timer
  // and controls are delegated to the swapped fragment, and nothing is written
  // outside the DOM except the clipboard on explicit copy (F5.8).
  var REVEAL_HIDE_MS = 300000;

  function clearRevealTimer(el) {
    if (el.__ccRevealTimer) {
      clearTimeout(el.__ccRevealTimer);
      el.__ccRevealTimer = null;
    }
  }

  function hideSecret(el) {
    var shown = el.querySelector("[data-revealed]");
    var masked = el.querySelector("[data-masked]");
    if (shown) shown.hidden = true;
    if (masked) masked.hidden = false;
    clearRevealTimer(el);
    el.removeAttribute("data-secret-reveal");
  }

  // An open edit form keeps the reveal visible: auto-hide is suspended until
  // Save submits or Cancel/close collapses it, at which point the timer resets.
  function autoHide(el) {
    var edit = el.querySelector("[data-secret-edit]");
    if (edit && edit.open) return;
    hideSecret(el);
  }

  function scheduleHide(el) {
    clearRevealTimer(el);
    el.__ccRevealTimer = setTimeout(function () { autoHide(el); }, REVEAL_HIDE_MS);
  }

  function armSecret(el) {
    if (!el || el.__ccArmed) return;
    el.__ccArmed = true;
    var hide = el.querySelector("[data-secret-hide]");
    if (hide) hide.addEventListener("click", function () { hideSecret(el); });
    var copy = el.querySelector("[data-secret-copy]");
    if (copy) {
      copy.addEventListener("click", function () {
        var pre = el.querySelector("pre");
        if (pre && navigator.clipboard) {
          navigator.clipboard.writeText(pre.textContent).catch(function () {});
        }
      });
    }
    var edit = el.querySelector("[data-secret-edit]");
    if (edit) {
      edit.addEventListener("toggle", function () {
        if (edit.open) clearRevealTimer(el);
        else if (el.hasAttribute("data-secret-reveal")) scheduleHide(el);
      });
      var cancel = edit.querySelector("[data-secret-cancel]");
      if (cancel) cancel.addEventListener("click", function () { edit.open = false; });
    }
    scheduleHide(el);
  }

  function armReveals(scope) {
    var root = scope && scope.querySelectorAll ? scope : document;
    if (root.matches && root.matches("[data-secret-reveal]")) armSecret(root);
    root.querySelectorAll("[data-secret-reveal]").forEach(armSecret);
  }

  document.addEventListener("htmx:afterSwap", function (event) { armReveals(event.target); });
  armReveals(document);

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
