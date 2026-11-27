/**
 * @fileoverview Animate the shared mobile menu and dismiss it on Escape,
 * outside clicks, or a resize to desktop.
 *
 * The native <details>/<summary> disclosure also works without JavaScript.
 */
(function () {
  "use strict";

  const MOBILE_MAX_WIDTH = 768;
  const ANIMATED_CLASS = "mobile-menu--animated";
  const CLOSING_CLASS = "mobile-menu--closing";
  const CLOSED_PANEL_FRAME = { opacity: 0, transform: "translateY(-8px)" };
  const OPEN_PANEL_FRAME = { opacity: 1, transform: "translateY(0)" };
  const PANEL_ANIMATION_TIMING = { duration: 200, easing: "cubic-bezier(0.2, 0, 0, 1)" };

  const menu = document.getElementById("mobile-menu");
  if (!menu) {
    return;
  }
  const summary = menu.querySelector("summary");
  const panel = menu.querySelector(".mobile-menu__panel");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let panelAnimation = null;
  let isClosing = false;

  if (summary && panel && panel.animate) {
    menu.classList.add(ANIMATED_CLASS);
  }

  /**
   * Open or close the disclosure, reversing an in-progress animation when needed.
   *
   * @param {boolean} open Desired disclosure state.
   * @param {boolean} [immediate=false] Apply the state without animating.
   * @returns {void}
   */
  function setOpen(open, immediate = false) {
    const shouldClose = !open;
    if (panelAnimation && !immediate && !reducedMotion.matches) {
      if (isClosing === shouldClose) return;
      isClosing = shouldClose;
      menu.classList.toggle(CLOSING_CLASS, isClosing);
      panelAnimation.reverse();
      return;
    }

    panelAnimation?.cancel();
    panelAnimation = null;
    menu.classList.toggle(CLOSING_CLASS, shouldClose && !immediate);

    if (immediate || reducedMotion.matches || !panel?.animate) {
      menu.open = open;
      isClosing = false;
      menu.classList.remove(CLOSING_CLASS);
      return;
    }

    if (menu.open !== open) animatePanel(open);
  }

  /**
   * Animate the exposed panel. Keep the disclosure open until an exit finishes.
   *
   * @param {boolean} open Whether the panel is entering.
   * @returns {void}
   */
  function animatePanel(open) {
    if (open) menu.open = true;
    isClosing = !open;
    const keyframes = open
      ? [CLOSED_PANEL_FRAME, OPEN_PANEL_FRAME]
      : [OPEN_PANEL_FRAME, CLOSED_PANEL_FRAME];

    panelAnimation = panel.animate(keyframes, PANEL_ANIMATION_TIMING);
    panelAnimation.onfinish = () => {
      if (isClosing) menu.open = false;
      panelAnimation = null;
      isClosing = false;
      menu.classList.remove(CLOSING_CLASS);
    };
  }

  if (menu.classList.contains(ANIMATED_CLASS)) {
    summary.addEventListener("click", (event) => {
      event.preventDefault();
      setOpen(!menu.open || isClosing);
    });
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.open) {
      setOpen(false);
      if (summary) {
        summary.focus();
      }
    }
  });

  document.addEventListener("click", (event) => {
    if (menu.open && !menu.contains(event.target)) {
      setOpen(false);
    }
  });

  // Collapse if the viewport grows to desktop, where the footer takes over.
  window.addEventListener("resize", () => {
    if (menu.open && window.innerWidth > MOBILE_MAX_WIDTH) {
      setOpen(false, true);
    }
  });
})();
