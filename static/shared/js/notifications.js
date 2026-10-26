/**
 * @fileoverview Shared notification utility exposed as window.Notify.
 *
 * Renders non-blocking, auto-dismissing toasts into #notification-container so
 * pages don't reimplement the create/show/dismiss lifecycle. Namespaced like
 * the other shared modules (e.g. window.Http / window.FormUi).
 */
(function () {
  "use strict";

  const DISMISS_TIMEOUT_MS = 6000;

  /**
   * Displays a non-blocking, auto-dismissing notification.
   *
   * Requires a `#notification-container` element in the DOM.
   * Falls back to `alert()` if the container is absent.
   *
   * @param {string} message Text to display
   * @param {('success'|'error'|'info')} [type='info'] Visual style variant
   */
  function showNotification(message, type = "info") {
    const container = document.getElementById("notification-container");
    if (!container) {
      console.error("Notification container not found. Falling back to alert.");
      alert(message);
      return;
    }

    const notification = document.createElement("div");
    notification.className = `notification notification--${type}`;
    notification.setAttribute("role", "alert"); // implies aria-live="assertive"

    const messageP = document.createElement("p");
    messageP.textContent = message;
    notification.appendChild(messageP);

    const closeButton = document.createElement("button");
    closeButton.className = "notification__close";
    closeButton.setAttribute("aria-label", "Close notification");
    notification.appendChild(closeButton);

    // Declared before timer so the closure captures the const once it's initialised.
    function dismiss() {
      clearTimeout(timer);
      notification.classList.add("notification--hiding");
      // Wait for the CSS hide animation before removing the element.
      notification.addEventListener("animationend", () => {
        if (container.contains(notification)) {
          container.removeChild(notification);
        }
      });
    }

    const timer = setTimeout(dismiss, DISMISS_TIMEOUT_MS);
    closeButton.addEventListener("click", dismiss);
    container.appendChild(notification);
  }

  window.Notify = { show: showNotification };
})();
