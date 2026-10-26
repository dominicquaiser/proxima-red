/**
 * @fileoverview Optional enhancements for the base.html mobile menu.
 *
 * The menu itself is a native <details>/<summary> disclosure (see .mobile-menu
 * in main.css) and works with no JavaScript. This only layers on the niceties
 * <details> lacks: close on Escape (refocusing the toggle) and close when
 * clicking outside the panel. No-op on pages without the menu markup.
 */
(function () {
  "use strict";

  const DESKTOP_BREAKPOINT = 768;

  const menu = document.getElementById("mobile-menu");
  if (!menu) {
    return;
  }
  const summary = menu.querySelector("summary");

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.open) {
      menu.open = false;
      if (summary) {
        summary.focus();
      }
    }
  });

  // Clicking the summary toggles natively and stays inside .mobile-menu, so the
  // open click never trips this; only genuine outside clicks close the panel.
  document.addEventListener("click", (event) => {
    if (menu.open && !menu.contains(event.target)) {
      menu.open = false;
    }
  });

  // Collapse if the viewport grows to desktop, where the footer takes over.
  window.addEventListener("resize", () => {
    if (menu.open && window.innerWidth > DESKTOP_BREAKPOINT) {
      menu.open = false;
    }
  });
})();
