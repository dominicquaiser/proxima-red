/**
 * @fileoverview Logic for the share retrieve page (/<uuid>/).
 * Decrypts the secret on demand using the key from the URL fragment.
 */
(function () {
  "use strict";

  // Fixed-width mask shown when the revealed secret is hidden again. Its length
  // is deliberately constant so it never hints at the real secret's length.
  const MASKED_SECRET = "*".repeat(32);

  document.addEventListener("DOMContentLoaded", () => {
    // --- State ---
    let decryptedText = null;
    let isDecrypted = false;
    let isRevealed = false;
    let countdownInterval = null;

    // --- DOM elements ---
    const lockedState = document.getElementById("locked-state");
    const decryptingState = document.getElementById("decrypting-state");
    const errorState = document.getElementById("error-state");

    const titleElement = document.getElementById("retrieved-title");
    const passwordInput = document.getElementById("retrieved-password");
    const passwordMulti = document.getElementById("retrieved-password-multi");
    const expiryCountdown = document.getElementById("expiry-countdown");
    const errorMessage = document.getElementById("error-message");

    const copyBtn = document.getElementById("copy-btn");
    const revealToggle = document.getElementById("reveal-toggle");
    const revealCheckbox = document.getElementById("togglePassword");

    // --- Data from Django template ---
    const shareDataElement = document.getElementById("share-data");
    if (!shareDataElement) {
      errorMessage.textContent = "Critical error: Share data not found on the page.";
      showState("error");
      return;
    }
    const shareData = JSON.parse(shareDataElement.textContent);
    const { ciphertext, iv, encrypted_title, title_iv, expires_at } = shareData;

    // The key lives only in the URL fragment. Capture it once up front so it is
    // still available after decryptSecret() strips the fragment from the URL.
    const keyBase64 = window.location.hash.slice(1);

    /**
     * Shows one UI state ('locked', 'decrypting', 'error') and hides the others.
     * @param {string} state
     */
    function showState(state) {
      lockedState.classList.add("hidden");
      decryptingState.classList.add("hidden");
      errorState.classList.add("hidden");

      if (state === "locked") lockedState.classList.remove("hidden");
      else if (state === "decrypting") decryptingState.classList.remove("hidden");
      else if (state === "error") errorState.classList.remove("hidden");
    }

    /**
     * Decrypts the secret via crypto.js and caches the result. Subsequent calls
     * return the cached plaintext immediately without re-decrypting.
     * @returns {Promise<string|null>} Plaintext, or null if decryption fails.
     */
    const decryptSecret = async () => {
      if (isDecrypted) return decryptedText;

      showState("decrypting");
      try {
        if (!keyBase64) throw new Error("No decryption key found in URL.");
        if (!ciphertext || !iv) throw new Error("Encrypted data is missing.");

        const plaintext = await window.PasswordCrypto.decryptPassword(ciphertext, iv, keyBase64);
        decryptedText = plaintext;
        isDecrypted = true;

        history.replaceState(null, document.title, window.location.pathname);

        showState("locked");
        return plaintext;
      } catch (err) {
        const message =
          err.code === "AUTHENTICATION_FAILED" || err.code === "KEY_IMPORT_FAILED"
            ? "Decryption failed. The key is incorrect or the data was tampered with."
            : err.message;
        errorMessage.textContent = message;
        showState("error");
        if (countdownInterval) clearInterval(countdownInterval);
        return null;
      }
    };

    /**
     * Decrypts the optional title and shows it, providing context before the
     * secret is revealed. Falls back to a generic heading on failure or absence.
     * A decryption error here is intentionally ignored, since a wrong key or
     * tampered data will surface when the secret itself is decrypted.
     */
    const initTitle = async () => {
      if (encrypted_title && title_iv && keyBase64) {
        try {
          const decryptedTitle = await window.PasswordCrypto.decryptPassword(
            encrypted_title,
            title_iv,
            keyBase64,
          );
          if (decryptedTitle) {
            titleElement.textContent = decryptedTitle;
            return;
          }
        } catch (_) {
          // fall through to default heading
        }
      }
      titleElement.textContent = "Ready to Decrypt";
    };

    const updateExpiryCountdown = () => {
      const remainingMs = new Date(expires_at) - new Date();

      if (remainingMs <= 0) {
        expiryCountdown.textContent = "now";
        if (countdownInterval) clearInterval(countdownInterval);
        if (!isDecrypted) {
          errorMessage.textContent = "This link has expired and the secret has been deleted.";
          showState("error");
        }
        return;
      }

      const { days, hours, minutes, seconds } = window.TimeFmt.breakdown(remainingMs);

      const parts = [];
      if (days > 0) parts.push(`${days}d`);
      if (hours > 0) parts.push(`${hours}h`);
      if (minutes > 0) parts.push(`${minutes}m`);
      if (parts.length < 2) parts.push(`${seconds}s`);

      expiryCountdown.textContent = parts.join(" ");
    };

    // --- Event listeners ---

    revealToggle.addEventListener("click", async (e) => {
      e.preventDefault();

      if (!isDecrypted) {
        const plaintext = await decryptSecret();
        if (plaintext === null) return;
      }

      // Keys span multiple lines and can't be masked in a single-line input, so
      // render them in the readonly textarea instead. The reveal/mask toggle only
      // makes sense for single-line secrets, so hide it in that case.
      const isMultiline = decryptedText.includes("\n");
      if (isMultiline) {
        passwordInput.classList.add("hidden");
        revealToggle.classList.add("hidden");
        passwordMulti.value = decryptedText;
        passwordMulti.classList.remove("hidden");
        passwordInput.closest(".res__field")?.classList.add("res__field--multi");
        return;
      }

      isRevealed = !isRevealed;
      revealCheckbox.checked = isRevealed;
      passwordInput.value = isRevealed ? decryptedText : MASKED_SECRET;
    });

    copyBtn.addEventListener("click", async (e) => {
      e.preventDefault();

      const plaintext = await decryptSecret();
      if (plaintext === null) return;

      if (await window.ClipboardUtil.copy(plaintext)) {
        window.ClipboardUtil.flash(copyBtn);
      } else {
        window.Notify.show("Failed to copy to clipboard.", "error");
      }
    });

    // --- Initial setup ---
    initTitle();
    updateExpiryCountdown();
    countdownInterval = setInterval(updateExpiryCountdown, 1000);
  });
})();
