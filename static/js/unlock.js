/**
 * @fileoverview In-place secure-session unlock, exposed as
 * window.SecureSessionUnlock.
 *
 * The vault's AES key is derived from the password at sign-in and held in
 * sessionStorage, which is scoped to a single tab and cannot be shared across
 * tabs or subdomains. A tab that has a valid login but no key (a second tab, or
 * one opened after the original sign-in tab closed) therefore can't decrypt the
 * vault. Rather than dead-ending with "sign in again", this re-derives the key
 * from a small modal: it verifies the password server-side via the reauth
 * endpoint (so a wrong password is rejected instead of silently storing a bad
 * key, which matters for an empty vault) and re-derives the key into THIS tab's
 * sessionStorage - without creating a new session, since one already exists.
 *
 * Loaded with `defer` after crypto.js/auth-crypto.js, http.js, and forms.js, so
 * the DOM is parsed and window.{AuthCrypto,Http,FormUi,Notify} are available
 * when this runs; ensureSecureSession is then ready before page controllers
 * (vault.js/account.js) run their own DOMContentLoaded handlers.
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
    overlay.classList.add("hidden");
    if (passwordInput) passwordInput.value = "";
    if (resolve) resolve(true);
  };

  // Verify the password against the server and re-derive + store the vault key
  // for this tab. Fetch the public salts, derive the auth secret, and post it to
  // the reauth endpoint, which confirms it matches the logged-in account (the
  // user is already signed in, so this checks the password without starting a
  // new session). On success, establish the secure session from the authoritative
  // vault salt the server returns. Returns true on success, false on a bad
  // password (throws are left to the caller's error handler for unexpected I/O).
  const deriveAndStoreKey = async (password) => {
    const { response: saltsResponse, result: salts } = await window.Http.postForm(
      saltsUrl,
      new URLSearchParams({ user_id: userId }),
    );
    if (!saltsResponse.ok || !salts.success || !salts.auth_salt || !salts.vault_salt) {
      return false;
    }

    const authSecret = await window.AuthCrypto.deriveAuthSecret(password, salts.auth_salt);
    const { response: reauthResponse, result } = await window.Http.postForm(
      reauthUrl,
      new URLSearchParams({ auth_secret: authSecret }),
    );
    if (!reauthResponse.ok || !result.success || !result.vault_salt) {
      return false;
    }

    await window.AuthCrypto.establishSecureSession(password, result.vault_salt);
    return true;
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
          if (await deriveAndStoreKey(password)) {
            window.Notify.show("Unlocked.", "success");
            settle();
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
  const ensureSecureSession = () => {
    if (sessionStorage.getItem(window.AuthCrypto.STORAGE_KEYS.masterKey)) {
      return Promise.resolve(true);
    }
    return new Promise((resolve) => {
      pendingResolve = resolve;
      show();
    });
  };

  window.SecureSessionUnlock = { ensureSecureSession };
})();
