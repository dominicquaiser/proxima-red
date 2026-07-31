/**
 * @fileoverview Controller for the note retrieve page ([note·] /view).
 *
 * Reads #note-data, decrypts fragment-key notes, then renders through
 * NoteMarkdown.
 */
(function () {
  "use strict";

  const HIDDEN_CLASS = "hidden";
  const COUNTDOWN_INTERVAL_MS = 1000;

  function hide(element) {
    element.classList.add(HIDDEN_CLASS);
  }

  function show(element) {
    element.classList.remove(HIDDEN_CLASS);
  }

  function downloadMarkdown(source) {
    const markdownBlob = new Blob([source], { type: "text/markdown" });
    const objectUrl = URL.createObjectURL(markdownBlob);
    const anchor = document.createElement("a");

    anchor.href = objectUrl;
    anchor.download = window.NoteMarkdown.titleSlug(source) + ".md";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
  }

  function expiryText(remainingMs) {
    const { days, hours, minutes, seconds } = window.TimeFmt.breakdown(remainingMs);
    const parts = [];

    if (days > 0) parts.push(days + "d");
    if (days > 0 || hours > 0) parts.push(hours + "h");
    parts.push(minutes + "m", seconds + "s");

    return parts.join(" ");
  }

  async function initNoteView() {
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
      hide(renderingState);
      hide(doc);
      if (actions) hide(actions);
      errorMessage.textContent = message;
      show(errorState);
    }

    function showDocument(source) {
      markdownSource = source;
      window.NoteMarkdown.renderInto(doc, source);
      hide(renderingState);
      show(doc);
      if (actions) show(actions);
    }

    async function renderNote() {
      if (!noteData.is_encrypted) {
        showDocument(noteData.content);
        return true;
      }

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
        return false;
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
        return false;
      }
      return true;
    }

    if (!(await renderNote())) return;

    if (downloadBtn) {
      downloadBtn.addEventListener("click", function () {
        downloadMarkdown(markdownSource);
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
        hide(expiryNotice);
        if (countdownInterval) clearInterval(countdownInterval);
        return;
      }
      if (remainingMs <= 0) {
        expiryCountdown.textContent = "expired";
        if (countdownInterval) clearInterval(countdownInterval);
        return;
      }
      expiryCountdown.textContent = expiryText(remainingMs);
    }

    updateExpiryCountdown();
    countdownInterval = setInterval(updateExpiryCountdown, COUNTDOWN_INTERVAL_MS);
  }

  document.addEventListener("DOMContentLoaded", initNoteView);
})();
