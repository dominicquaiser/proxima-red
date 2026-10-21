/**
 * In-place password verification for a missing key or expired tool grant.
 * The shared account session must still be valid. Reauthentication renews only
 * this modal's tool and produces a key handoff bound to the current session.
 */
(function () {
  "use strict";

  const overlay = document.getElementById("unlock-modal");
  if (!overlay) return;

  const form = overlay.querySelector("#unlock-form");
  const passwordInput = overlay.querySelector("#unlock-password");
  const submitButton = overlay.querySelector("#unlock-btn");

  const userId = (overlay.dataset.userId || "").replace(/\D/g, "").slice(0, 8);
  const saltsUrl = overlay.dataset.saltsUrl || "/auth/salts/";
  const reauthUrl = overlay.dataset.reauthUrl || "/auth/reauth/";

  // Resolver for the in-flight ensureSecureSession() promise, set while the modal
  // is open so the form submit handler can settle it once the tab is unlocked.
  let pendingResolve = null;
  let pendingPromise = null;

  const show = () => {
    overlay.classList.remove("hidden");
    passwordInput?.focus();
  };

  // Hide the modal and resolve the pending ensureSecureSession() promise. Only
  // reached on a successful unlock: the overlay has no dismiss path (no close
  // button), so it always resolves true. The only non-unlock exit is the
  // sign-out form, which navigates away instead of settling.
  const settle = () => {
    const resolve = pendingResolve;
    pendingResolve = null;
    pendingPromise = null;
    overlay.classList.add("hidden");
    if (passwordInput) passwordInput.value = "";
    if (resolve) resolve(true);
  };

  // Verify the password against the server and re-derive + store the vault key
  // for this tab. Fetch the public salts, derive the auth secret, and post it to
  // the reauth endpoint, which confirms it matches the logged-in account (the
  // user is already signed in, so this checks the password without starting a
  // new session). On success, establish the secure session from the authoritative
  // vault salt the server returns. Returns "ok" on success, "changed" when the
  // session now belongs to another account (409: no password will work here),
  // or "invalid" on a bad password (throws are left to the caller's error
  // handler for unexpected I/O).
  const deriveAndStoreKey = async (password) => {
    const { response: saltsResponse, result: salts } = await window.Http.postForm(
      saltsUrl,
      new URLSearchParams({ user_id: userId }),
    );
    if (!saltsResponse.ok || !salts.success || !salts.auth_salt || !salts.vault_salt) {
      return "invalid";
    }

    const authSecret = await window.AuthCrypto.deriveAuthSecret(password, salts.auth_salt);
    const { response: reauthResponse, result } = await window.Http.postForm(
      reauthUrl,
      new URLSearchParams({
        auth_secret: authSecret,
        tool: overlay.dataset.tool || "pass",
        expected_user: userId,
      }),
    );
    if (reauthResponse.status === 409) return "changed";
    if (!reauthResponse.ok || !result.success || !result.vault_salt) {
      return "invalid";
    }

    await window.AuthCrypto.establishSecureSession(password, result.vault_salt, result.state);
    return "ok";
  };

  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const password = window.FormUi.getMaskedInputValue(passwordInput);
      if (!password) {
        window.Notify.show("Please enter your password.", "error");
        return;
      }
      if (!userId || userId.length !== 8) {
        window.Notify.show("Couldn't determine your User ID. Please sign in again.", "error");
        return;
      }

      await window.FormUi.submitWithBusy(
        submitButton,
        async () => {
          const outcome = await deriveAndStoreKey(password);
          if (outcome === "ok") {
            window.Notify.show("Unlocked.", "success");
            settle();
          } else if (outcome === "changed") {
            if (passwordInput) passwordInput.value = "";
            window.Notify.show(
              "You signed in to a different account in another tab. Reload this page to continue.",
              "error",
            );
          } else {
            window.Notify.show("Incorrect password. Please try again.", "error");
          }
        },
        {
          onError: (error) => {
            console.error("Unlock failed:", error);
            window.Notify.show("Unable to unlock. Please try again.", "error");
          },
        },
      );
    });
  }

  /**
   * Resolve true when this tab has a usable vault key, prompting the user to
   * unlock (re-enter their password) when it doesn't. The prompt can't be
   * dismissed, so this only resolves once the tab is unlocked; the user's other
   * option is the modal's sign-out, which navigates away instead of resolving.
   * @returns {Promise<boolean>}
   */
  const ensureSecureSession = ({ force = false } = {}) => {
    if (pendingPromise) return pendingPromise;
    if (!force && sessionStorage.getItem(window.AuthCrypto.STORAGE_KEYS.masterKey)) {
      return Promise.resolve(true);
    }
    pendingPromise = new Promise((resolve) => {
      pendingResolve = resolve;
      show();
    });
    return pendingPromise;
  };

  const dismiss = () => {
    overlay.classList.add("hidden");
    if (passwordInput) passwordInput.value = "";
    const resolve = pendingResolve;
    pendingResolve = null;
    pendingPromise = null;
    if (resolve) resolve(false);
  };

  window.SecureSessionUnlock = { ensureSecureSession, dismiss };
})();
