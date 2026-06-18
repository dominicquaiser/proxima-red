/**
 * @fileoverview Account page: floating label sync, AJAX password change with
 * session re-derivation, export animation, and AJAX account deletion.
 */
(function () {
  "use strict";

  // Fallback endpoints for reading and writing the encrypted vault blob; the
  // change-password form normally carries the URLconf-defined URLs in its
  // data-vault-data-url / data-update-data-url attributes (cf. data-salts-url
  // in signin.html).
  const VAULT_DATA_ENDPOINT = "/vault-data/";
  const SAVE_ENDPOINT = "/update-data/";

  // Read a password field honouring the '*' masking convention shared with the
  // signin/signup pages (FormUi.getMaskedInputValue); returns "" for a missing
  // field. The account-page fields are currently unmasked, so this matches the
  // other auth pages and stays correct if they ever adopt the masked toggle.
  const readPasswordField = (input) => (input ? window.FormUi.getMaskedInputValue(input) : "");

  const clearSensitiveInputs = (form) => {
    form.querySelectorAll('input[type="password"], input[name$="auth_secret"]').forEach((input) => {
      input.value = "";
    });
  };

  // GET the current user's encrypted vault blob. Throws on network/HTTP error.
  const fetchVaultBlob = async (vaultDataUrl) => {
    const response = await fetch(vaultDataUrl, {
      headers: { "X-Requested-With": "XMLHttpRequest" },
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return response.json();
  };

  const resolveCurrentVaultKey = async (currentPassword, currentVaultSalt) => {
    const storedKeyBase64 = sessionStorage.getItem(window.AuthCrypto.STORAGE_KEYS.masterKey);
    if (storedKeyBase64) {
      return window.AuthCrypto.importKeyFromBase64(storedKeyBase64);
    }
    if (!currentPassword || !currentVaultSalt) {
      throw new Error("No session key available and cannot derive one to read existing vault data.");
    }
    return window.AuthCrypto.deriveKeyFromPassword(currentPassword, currentVaultSalt);
  };

  const recoverCurrentVaultData = async (vaultDataUrl, currentPassword, currentVaultSalt) => {
    const blob = await fetchVaultBlob(vaultDataUrl);
    if (!blob || !blob.success || !blob.encrypted_data || !blob.iv) {
      return null;
    }

    const oldKey = await resolveCurrentVaultKey(currentPassword, currentVaultSalt);
    return window.AuthCrypto.decryptAccountData(blob.encrypted_data, blob.iv, oldKey);
  };

  // Re-encrypt recovered vault data under the new password's vault key and save
  // it. Derives the new key from the rotated salt (the same key signin/the vault
  // will derive), so /vault/ can read the blob afterwards. Throws on failure.
  const reencryptAndSaveVault = async (vaultData, newPassword, newVaultSalt, saveUrl) => {
    const newKey = await window.AuthCrypto.deriveKeyFromPassword(newPassword, newVaultSalt);
    const encrypted = await window.AuthCrypto.encryptAccountData(vaultData, newKey);

    const { response, result } = await window.Http.postForm(saveUrl, {
      encrypted_data: encrypted.encryptedData,
      iv: encrypted.iv,
    });
    if (!response.ok || !result.success) {
      throw new Error(result.error || `HTTP ${response.status}`);
    }
  };

  // Pre-submit check of the new password pair (match + strength rules). Shows
  // a notification and returns false when the change must not proceed.
  const validateNewPasswordPair = (newPassword, confirmPassword) => {
    if (!newPassword || newPassword !== confirmPassword) {
      window.Notify.show("New passwords must match.", "error");
      return false;
    }

    const validation = window.AuthCrypto.validatePassword(newPassword);
    if (!validation.isValid) {
      window.Notify.show(validation.messages.join(" "), "error");
      return false;
    }

    return true;
  };

  // Phase 1: recover the existing vault under the CURRENT key before rotating
  // anything. Rotating the password derives a new vault key, so the stored blob
  // (encrypted under the old key) must be re-encrypted or it becomes unreadable.
  // If a blob exists but can't be read, fail (ok: false) before the change so
  // the data isn't orphaned (the change is retryable; the saved links are not).
  const recoverVaultBeforeChange = async (vaultDataUrl, currentPassword, currentVaultSalt) => {
    try {
      return {
        ok: true,
        vaultData: await recoverCurrentVaultData(vaultDataUrl, currentPassword, currentVaultSalt),
      };
    } catch (recoveryError) {
      console.error("Could not read existing vault before password change:", recoveryError);
      window.Notify.show(
        "We couldn't access your saved links to re-secure them. " +
          "Please check your current password and try again.",
        "error",
      );
      return { ok: false, vaultData: null };
    }
  };

  // Phase 2: generate fresh salts, derive the current and new auth secrets, and
  // write all four values into the change form's hidden fields for submission.
  const fillDerivedSecretFields = async (currentPassword, newPassword, currentAuthSalt) => {
    const newAuthSalt = window.AuthCrypto.generateSalt();
    const newVaultSalt = window.AuthCrypto.generateSalt();

    document.getElementById("id_current_auth_secret").value =
      await window.AuthCrypto.deriveAuthSecret(currentPassword, currentAuthSalt);
    document.getElementById("id_new_auth_secret").value = await window.AuthCrypto.deriveAuthSecret(
      newPassword,
      newAuthSalt,
    );
    document.getElementById("id_auth_salt").value = newAuthSalt;
    document.getElementById("id_vault_salt").value = newVaultSalt;
  };

  // Phase 3 (after the server accepted the change): re-secure the recovered
  // vault under the new key BEFORE the caller swaps the session key, so that if
  // saving fails the old key stays active and the vault remains readable this
  // session (the user can re-save manually). No-op without stored vault data.
  const resecureVaultAfterChange = async (vaultData, newPassword, newVaultSalt, saveUrl) => {
    if (vaultData === null) return true;
    try {
      await reencryptAndSaveVault(vaultData, newPassword, newVaultSalt, saveUrl);
      return true;
    } catch (migrateError) {
      console.error("Failed to re-secure vault after password change:", migrateError);
      window.Notify.show(
        "Your password was changed, but your saved links could not be re-secured. " +
          "Open your vault now and re-save them before signing out.",
        "error",
      );
      return false;
    }
  };

  // Phase 4: swap the session key to the new password's derived key, so the
  // vault remains accessible without signing out and back in. Best-effort: the
  // password change itself already succeeded, so a failure here only logs.
  const refreshSessionKey = async (newPassword, newVaultSalt) => {
    try {
      await window.AuthCrypto.establishSecureSession(newPassword, newVaultSalt);
      return true;
    } catch (cryptoError) {
      console.error("Failed to refresh derived key after password change:", cryptoError);
      return false;
    }
  };

  document.addEventListener("DOMContentLoaded", () => {
    const changePasswordForm = document.getElementById("change-password-form");
    const deleteAccountForm = document.getElementById("delete-account-form");
    const authDataScript = document.getElementById("auth-data");
    let authData = {};

    if (authDataScript) {
      try {
        authData = JSON.parse(authDataScript.textContent);
      } catch (error) {
        console.error("Failed to read auth derivation data:", error);
      }
    }

    if (changePasswordForm) {
      // Vault blob endpoints, defined by the URLconf via the form's data attributes.
      const vaultDataUrl = changePasswordForm.dataset.vaultDataUrl || VAULT_DATA_ENDPOINT;
      const updateDataUrl = changePasswordForm.dataset.updateDataUrl || SAVE_ENDPOINT;

      changePasswordForm.addEventListener("submit", async (event) => {
        if (!window.fetch) return; // allow default form submission as fallback
        event.preventDefault();

        const currentPassword = readPasswordField(document.getElementById("id_current_password"));
        const newPassword = readPasswordField(document.getElementById("id_new_password"));
        const confirmPassword = readPasswordField(
          document.getElementById("id_confirm_new_password"),
        );

        if (!validateNewPasswordPair(newPassword, confirmPassword)) return;

        if (!currentPassword || !authData.auth_salt) {
          window.Notify.show("Secure account data missing. Please sign in again.", "error");
          return;
        }

        const submitButton = changePasswordForm.querySelector('button[type="submit"]');

        await window.FormUi.submitWithBusy(
          submitButton,
          async () => {
            const recovery = await recoverVaultBeforeChange(
              vaultDataUrl,
              currentPassword,
              authData.vault_salt,
            );
            if (!recovery.ok) return;

            await fillDerivedSecretFields(currentPassword, newPassword, authData.auth_salt);

            const { response, result } = await window.Http.postForm(
              changePasswordForm.action,
              changePasswordForm,
            );

            if (!response.ok || !result.success) {
              window.Notify.show(window.Http.firstError(result), "error");
              return;
            }

            // Password is now rotated server-side; re-secure the vault, then
            // swap the session key (see the phase helpers for the ordering
            // rationale).
            if (
              !(await resecureVaultAfterChange(
                recovery.vaultData,
                newPassword,
                result.vault_salt,
                updateDataUrl,
              ))
            ) {
              clearSensitiveInputs(changePasswordForm);
              return;
            }

            if (await refreshSessionKey(newPassword, result.vault_salt)) {
              authData = { auth_salt: result.auth_salt, vault_salt: result.vault_salt };
            }

            clearSensitiveInputs(changePasswordForm);
            window.Notify.show(result.message || "Password updated.", "success");
          },
          {
            onError: (error) => {
              console.error("Password update failed:", error);
              window.Notify.show("Unable to update password. Please try again.", "error");
            },
          },
        );
      });
    }

    const exportAction = document.querySelector(".export-action");
    if (exportAction) {
      exportAction.addEventListener("click", () => {
        const icon = exportAction.querySelector(".export-action__icon");
        const arrow = exportAction.querySelector(".export-action__arrow");
        if (!icon || !arrow || icon.classList.contains("is-downloading")) return;
        icon.classList.add("is-downloading");
        arrow.addEventListener("animationend", () => icon.classList.remove("is-downloading"), {
          once: true,
        });
      });
    }

    if (deleteAccountForm) {
      deleteAccountForm.addEventListener("submit", async (event) => {
        if (!window.fetch) return; // allow default form submission as fallback
        event.preventDefault();

        if (!window.confirm("Deleting your account is permanent. Continue?")) return;

        const submitButton = deleteAccountForm.querySelector('button[type="submit"]');

        await window.FormUi.submitWithBusy(
          submitButton,
          async () => {
            const deletePassword = readPasswordField(document.getElementById("id_delete_password"));
            if (!deletePassword || !authData.auth_salt) {
              window.Notify.show("Secure account data missing. Please sign in again.", "error");
              return;
            }

            document.getElementById("id_delete_auth_secret").value =
              await window.AuthCrypto.deriveAuthSecret(deletePassword, authData.auth_salt);

            const { response, result } = await window.Http.postForm(
              deleteAccountForm.action,
              deleteAccountForm,
            );

            if (!response.ok || !result.success) {
              window.Notify.show(window.Http.firstError(result), "error");
              return;
            }

            window.AuthCrypto.clearSecureSession();
            clearSensitiveInputs(deleteAccountForm);
            window.Notify.show(result.message || "Account deleted.", "success");

            setTimeout(() => {
              window.location.href = result.redirect_url || "/";
            }, 1200);
          },
          {
            onError: (error) => {
              console.error("Account deletion failed:", error);
              window.Notify.show("Unable to delete account right now. Please try again.", "error");
            },
          },
        );
      });
    }
  });
})();
