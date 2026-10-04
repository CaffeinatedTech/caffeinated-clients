/* Theme bootstrap. External (not inline) so the CSP stays strict.
   Runs before first paint to avoid a flash of the wrong theme. */
(function () {
  try {
    var stored = localStorage.getItem("cc-theme");
    var dark = stored
      ? stored === "dark"
      : window.matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.classList.toggle("dark", dark);
  } catch (e) {
    /* private mode / storage unavailable: fall back to the light theme */
  }
})();
