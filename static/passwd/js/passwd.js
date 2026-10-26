/**
 * @fileoverview Logic for the share create and success pages.
 * Wrapped in an IIFE so helpers stay private (matching forms.js / crypto.js).
 */
(function () {
  "use strict";

  function handleCreatePage() {
    const form = document.getElementById("createForm");
    if (!form) return;

    const shareForm = window.FormUi.setupShareForm(form);
    if (!shareForm) return;

    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const password = shareForm.readPlaintext();
      if (!password) {
        console.error("Form submitted with no password value.");
        return;
      }

      shareForm.setBusy(true, "Encrypting...");

      try {
        // The key travels in the URL fragment, not the form. Stash it for the
        // success page to read.
        const key = await shareForm.encrypt();
        sessionStorage.setItem("shareKey", key);
        form.submit();
      } catch (error) {
        console.error("Encryption failed:", error);
        window.Notify.show(
          "A critical error occurred during encryption. Please refresh the page and try again.",
          "error",
        );
        shareForm.setBusy(false, "Create Secure Link");
      }
    });
  }

  function handleSuccessPage() {
    const shareInfo = document.getElementById("share-info");
    if (!shareInfo) return;

    const shareId = document.getElementById("share-id")?.textContent;
    const shareLinkInput = document.getElementById("share-link");
    const retrievalUrlBase = shareInfo.dataset.retrievalUrlBase;
    // Server embeds a placeholder UUID in retrievalUrlBase; swap in the real share ID.
    const dummyShareId = shareInfo.dataset.dummyShareId;
    const shareKey = sessionStorage.getItem("shareKey");

    if (shareId && shareKey && shareLinkInput && retrievalUrlBase && dummyShareId) {
      const shareableUrl = `${retrievalUrlBase.replace(dummyShareId, shareId)}#${shareKey}`;
      // The decryption key lives in the URL fragment. Mask it by default so it
      // isn't shoulder-surfed; the copy button always copies the real URL.
      const maskedUrl = `${shareableUrl.split("#")[0]}#${"*".repeat(32)}`;

      let keyRevealed = false;
      shareLinkInput.value = maskedUrl;

      const revealToggle = document.getElementById("reveal-key-toggle");
      const revealCheckbox = document.getElementById("toggleKey");
      if (revealToggle && revealCheckbox) {
        revealToggle.addEventListener("click", (event) => {
          event.preventDefault();
          keyRevealed = !keyRevealed;
          revealCheckbox.checked = keyRevealed;
          shareLinkInput.value = keyRevealed ? shareableUrl : maskedUrl;
        });
      }

      window.ClipboardUtil.setupButton(document.getElementById("copy-link-btn"), shareableUrl, {
        onSuccess: () => window.Notify.show("Link copied to clipboard.", "success"),
        onError: () => window.Notify.show("Failed to copy to clipboard.", "error"),
      });
      sessionStorage.removeItem("shareKey");
    } else {
      if (shareLinkInput) shareLinkInput.value = "Error: Could not generate the secure link.";
      console.error("Could not generate link. Missing one of: shareId, key, or URL base.");
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    handleCreatePage();
    handleSuccessPage();
  });
})();
