/**
 * @fileoverview Signin form: user ID formatting, AJAX submission, and
 * secure-session establishment via auth-crypto.js before redirecting to /vault/.
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("signin-form");
    if (!form) return;

    const userIdInput = document.getElementById("id_user_id");
    const passwordInput = document.getElementById("id_password");
    const authSecretInput = document.getElementById("id_auth_secret");
    const submitButton = document.getElementById("signin-btn");

    if (userIdInput) {
      userIdInput.addEventListener("input", () => {
        const digits = userIdInput.value.replace(/\D/g, "").substring(0, 8);
        userIdInput.value = digits.length > 4 ? `${digits.slice(0, 4)}-${digits.slice(4)}` : digits;
      });
    }

    form.addEventListener("submit", async (e) => {
      e.preventDefault();

      const userId = userIdInput.value.replace(/-/g, "");
      const password = window.FormUi.getMaskedInputValue(passwordInput);

      window.AuthCrypto.clearSecureSession();

      if (!userId || userId.length !== 8) {
        window.Notify.show("Please enter a valid 8-digit User ID.", "error");
        return;
      }

      if (!password) {
        window.Notify.show("Please enter your password.", "error");
        return;
      }

      await window.FormUi.submitWithBusy(
        submitButton,
        async () => {
          const { response: saltsResponse, result: salts } = await window.Http.postForm(
            form.dataset.saltsUrl || "/auth/salts/",
            new URLSearchParams({ user_id: userId }),
          );

          if (!saltsResponse.ok || !salts.success || !salts.auth_salt || !salts.vault_salt) {
            window.Notify.show("Sign in failed: Invalid credentials", "error");
            return;
          }

          authSecretInput.value = await window.AuthCrypto.deriveAuthSecret(
            password,
            salts.auth_salt,
          );

          const signInData = new FormData(form);
          signInData.set("user_id", userId);
          const { result } = await window.Http.postForm(form.action, signInData);

          if (!result.success) {
            window.Notify.show(
              "Sign in failed: " + (result.error || "Invalid credentials"),
              "error",
            );
            return;
          }

          try {
            await window.AuthCrypto.establishSecureSession(password, result.vault_salt);
          } catch (cryptoError) {
            console.error("Failed to establish secure session:", cryptoError);
            window.Notify.show(
              "Unable to initialise secure storage. Please try signing in again.",
              "error",
            );
            return;
          }

          // Offer the (user_id, password) pair to the browser's password
          // manager before navigating away (no-op outside Chromium).
          await window.FormUi.saveCredential(userId, password);

          window.Notify.show(result.message || "Signed in successfully! Redirecting...", "success");

          setTimeout(() => {
            window.location.href = result.redirect_url || "/vault/";
          }, 1000);
        },
        {
          onError: (error) => {
            console.error("Signin error:", error);
            window.Notify.show("An unexpected error occurred. Please try again.", "error");
          },
          cleanup: () => {
            if (authSecretInput) authSecretInput.value = "";
          },
        },
      );
    });
  });
})();
