/**
 * @fileoverview Signup form: client-side password validation, AJAX submission,
 * and success state display (user ID reveal + copy button).
 */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("signup-form");
    if (!form) return;

    const passwordInput = document.getElementById("id_password");
    const confirmInput = document.getElementById("id_password_confirm");
    const authSecretInput = document.getElementById("id_auth_secret");
    const authSaltInput = document.getElementById("id_auth_salt");
    const vaultSaltInput = document.getElementById("id_vault_salt");
    const submitButton = document.getElementById("signup-btn");
    const signupCard = document.getElementById("signup-card");
    const successContainer = document.getElementById("success-container");
    const userIdDisplay = document.getElementById("user-id-display");

    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      clearFieldErrors();

      const password = window.FormUi.getMaskedInputValue(passwordInput);
      const confirm = window.FormUi.getMaskedInputValue(confirmInput);

      if (password !== confirm) {
        window.Notify.show("Passwords do not match.", "error");
        return;
      }

      const validation = window.AuthCrypto.validatePassword(password);
      if (!validation.isValid) {
        window.Notify.show(validation.messages.join(" "), "error");
        return;
      }

      await window.FormUi.submitWithBusy(
        submitButton,
        async () => {
          const authSalt = window.AuthCrypto.generateSalt();
          const vaultSalt = window.AuthCrypto.generateSalt();
          authSecretInput.value = await window.AuthCrypto.deriveAuthSecret(password, authSalt);
          authSaltInput.value = authSalt;
          vaultSaltInput.value = vaultSalt;

          const { result } = await window.Http.postForm(form.action, form);

          if (!result.success) {
            if (result.errors) handleFormErrors(result.errors);
            window.Notify.show(result.error || window.Http.firstError(result), "error");
            return;
          }

          if (userIdDisplay)
            userIdDisplay.value = `${result.user_id.slice(0, 4)}-${result.user_id.slice(4)}`;
          if (signupCard) signupCard.style.display = "none";
          if (successContainer) successContainer.style.display = "block";

          window.ClipboardUtil.setupButton(document.getElementById("copy-id-btn"), result.user_id, {
            onSuccess: () => window.Notify.show("User ID copied!", "success"),
            onError: () => window.Notify.show("Failed to copy. Please copy manually.", "error"),
          });

          // Offer the new (user_id, password) pair to the browser's password
          // manager so it can autofill at sign in (no-op outside Chromium).
          await window.FormUi.saveCredential(result.user_id, password);

          window.Notify.show(result.message || "Account created successfully!", "success");
        },
        {
          onError: (error) => {
            console.error("Signup error:", error);
            window.Notify.show("An unexpected error occurred. Please try again.", "error");
          },
          cleanup: () => {
            if (authSecretInput) authSecretInput.value = "";
          },
          // Keep the button busy once the success card has replaced the form;
          // only restore it while the form is still visible (incl. errors).
          keepBusy: () => !signupCard || signupCard.style.display === "none",
        },
      );
    });

    function handleFormErrors(errors) {
      clearFieldErrors();
      for (const [fieldName, messages] of Object.entries(errors)) {
        if (fieldName === "non_field_errors" || fieldName === "__all__") continue;
        const field = document.getElementById(`id_${fieldName}`);
        if (!field) continue;
        field.classList.add("error");
        const errorEl = document.createElement("div");
        errorEl.className = "field-error";
        errorEl.textContent = messages[0];
        field.parentNode.appendChild(errorEl);
      }
    }

    function clearFieldErrors() {
      document.querySelectorAll(".field__input.error").forEach((f) => f.classList.remove("error"));
      document.querySelectorAll(".field-error").forEach((el) => el.remove());
    }
  });
})();
