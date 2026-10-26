/**
 * @fileoverview Auth page entry point. Wires up the shared password-visibility
 * toggles from forms.js on DOMContentLoaded.
 */
document.addEventListener("DOMContentLoaded", () => {
  window.FormUi.initPasswordToggles();
});
