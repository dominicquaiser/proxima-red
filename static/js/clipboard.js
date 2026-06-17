/**
 * @fileoverview Shared clipboard utilities exposed as window.ClipboardUtil.
 *
 * Provides copy-to-clipboard helpers with availability checks and "flash"
 * feedback so pages don't repeat navigator.clipboard + try/catch + setTimeout
 * boilerplate. Named ClipboardUtil rather than Clipboard to avoid shadowing
 * the built-in Clipboard DOM interface.
 */
(function () {
  "use strict";

  /**
   * @returns {boolean} True if the async Clipboard write API is available.
   */
  const isSupported = () => !!(navigator.clipboard && navigator.clipboard.writeText);

  /**
   * Copy text to the clipboard. Resolves to whether it succeeded and never
   * throws, so callers can branch on a simple boolean.
   * @param {string} text
   * @returns {Promise<boolean>}
   */
  const copy = async (text) => {
    if (!isSupported()) {
      return false;
    }
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (error) {
      console.error("Clipboard write failed:", error);
      return false;
    }
  };

  /**
   * Briefly add a feedback class to an element, then remove it. No-op while the
   * feedback is already showing, which also debounces rapid repeat clicks.
   * @param {HTMLElement} el
   * @param {string} [className="copied"]
   * @param {number} [duration=1400]
   */
  const flash = (el, className = "copied", duration = 1400) => {
    if (!el || el.classList.contains(className)) {
      return;
    }
    el.classList.add(className);
    setTimeout(() => el.classList.remove(className), duration);
  };

  /**
   * Wire the common "click a button to copy fixed text and flash a class"
   * pattern. `text` may be a string or a function returning the (possibly
   * dynamic) string to copy.
   * @param {HTMLElement|null} button
   * @param {string|(() => string)} text
   * @param {{flashClass?: string, onSuccess?: () => void, onError?: () => void}} [options]
   */
  const setupButton = (button, text, options = {}) => {
    if (!button) {
      return;
    }
    const { flashClass = "copied", onSuccess, onError } = options;

    button.addEventListener("click", async (event) => {
      event.preventDefault();
      // Ignore repeat clicks while the previous feedback is still showing.
      if (button.classList.contains(flashClass)) {
        return;
      }

      const value = typeof text === "function" ? text() : text;
      const ok = await copy(value);

      if (ok) {
        flash(button, flashClass);
        if (onSuccess) onSuccess();
      } else if (onError) {
        onError();
      }
    });
  };

  window.ClipboardUtil = { isSupported, copy, flash, setupButton };
})();
