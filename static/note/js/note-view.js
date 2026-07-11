/**
 * @fileoverview Controller for the note retrieve page ([note·] /view).
 *
 * Reads the note payload from the #note-data json_script. Encrypted notes are
 * decrypted with the AES key from the URL fragment and the fragment is scrubbed
 * from the address bar afterwards; plain-text notes render directly. Markdown
 * always renders through NoteMarkdown (marked + DOMPurify, client-side only).
 *
 * Load order (all deferred): shared utils, shared/js/crypto.js,
 * vendor/marked.min.js, vendor/purify.min.js, markdown.js, then this file.
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", async function () {
    const dataElement = document.getElementById("note-data");
    if (!dataElement) return;

    const noteData = JSON.parse(dataElement.textContent);

    const renderingState = document.getElementById("rendering-state");
    const errorState = document.getElementById("error-state");
    const errorMessage = document.getElementById("error-message");
    const doc = document.getElementById("note-document");
    const expiryNotice = document.getElementById("expiry-notice");
    const expiryCountdown = document.getElementById("expiry-countdown");
    const downloadBtn = document.getElementById("download-note-btn");
    const copyBtn = document.getElementById("copy-note-btn");
    const actions = document.getElementById("note-actions");

    let markdownSource = "";
    let countdownInterval = null;

    function showError(message) {
      renderingState.classList.add("hidden");
      doc.classList.add("hidden");
      if (actions) actions.classList.add("hidden");
      errorMessage.textContent = message;
      errorState.classList.remove("hidden");
    }

    function showDocument(source) {
      markdownSource = source;
      window.NoteMarkdown.renderInto(doc, source);
      renderingState.classList.add("hidden");
      doc.classList.remove("hidden");
      if (actions) actions.classList.remove("hidden");
    }

    if (noteData.is_encrypted) {
      const keyBase64 = window.location.hash.slice(1);

      // Scrub the key from the address bar as early as possible; it stays in
      // memory only. (Same posture as the passwd retrieve page.)
      if (keyBase64) {
        history.replaceState(null, document.title, window.location.pathname);
      }

      if (!keyBase64) {
        showError(
          "The decryption key is missing from the link. Make sure you open " +
            "the complete link, including everything after the # character.",
        );
        return;
      }

      try {
        const plaintext = await window.PasswordCrypto.decryptPassword(
          noteData.content,
          noteData.iv,
          decodeURIComponent(keyBase64),
        );
        showDocument(plaintext);
      } catch (error) {
        if (error && error.code === "AUTHENTICATION_FAILED") {
          showError(
            "This link's key does not match the stored note. The link may be " +
              "incomplete, or the data may have been tampered with.",
          );
        } else {
          showError("Decryption failed: " + (error.message || "unknown error"));
        }
        return;
      }
    } else {
      showDocument(noteData.content);
    }

    if (downloadBtn) {
      downloadBtn.addEventListener("click", function () {
        const blob = new Blob([markdownSource], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement("a");
        anchor.href = url;
        anchor.download = window.NoteMarkdown.titleSlug(markdownSource) + ".md";
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
      });
    }

    window.ClipboardUtil.setupButton(copyBtn, () => markdownSource, {
      onSuccess: () => window.Notify.show("Markdown copied to clipboard.", "success"),
      onError: () => window.Notify.show("Copy failed.", "error"),
    });

    const expiresAtMs = Date.parse(noteData.expires_at);

    function updateExpiryCountdown() {
      const remainingMs = expiresAtMs - Date.now();
      if (Number.isNaN(remainingMs)) {
        expiryNotice.classList.add("hidden");
        if (countdownInterval) clearInterval(countdownInterval);
        return;
      }
      if (remainingMs <= 0) {
        expiryCountdown.textContent = "expired";
        if (countdownInterval) clearInterval(countdownInterval);
        return;
      }
      const { days, hours, minutes, seconds } = window.TimeFmt.breakdown(remainingMs);
      const parts = [];
      if (days > 0) parts.push(days + "d");
      if (days > 0 || hours > 0) parts.push(hours + "h");
      parts.push(minutes + "m", seconds + "s");
      expiryCountdown.textContent = parts.join(" ");
    }

    updateExpiryCountdown();
    countdownInterval = setInterval(updateExpiryCountdown, 1000);
  });
})();
