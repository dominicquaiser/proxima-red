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

  // Fallback endpoints for the note vault (index + per-note rows); normally
  // carried in data-note-index-url / data-note-list-url / data-note-migrate-url.
  const NOTE_INDEX_ENDPOINT = "/vault/index/";
  const NOTE_LIST_ENDPOINT = "/vault/notes/";
  const NOTE_MIGRATE_ENDPOINT = "/vault/migrate/";

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

  const resolveCurrentVaultKey = async (currentPassword, currentVaultSalt) => {
    const storedKeyBase64 = sessionStorage.getItem(window.AuthCrypto.STORAGE_KEYS.masterKey);
    if (storedKeyBase64 && !currentPassword) {
      return window.AuthCrypto.importKeyFromBase64(storedKeyBase64);
    }
    if (!currentPassword || !currentVaultSalt) {
      throw new Error(
        "No session key available and cannot derive one to read existing vault data.",
      );
    }
    return window.AuthCrypto.deriveKeyFromPassword(currentPassword, currentVaultSalt);
  };

  // A successful HTTP response can still carry {success: false}. Treat that as
  // unreadable data, not an empty vault, or a password rotation could strand
  // ciphertext that the recovery phase silently skipped.
  const readVaultJson = async (url, fallbackError) => {
    const { response, result } = await window.Http.getJson(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    if (!result.success) throw new Error(result.error || fallbackError);
    return result;
  };

  const recoverCurrentVaultData = async (vaultDataUrl, currentPassword, currentVaultSalt) => {
    // A failed read must throw (not return null): the caller aborts the password
    // change on a throw, but treats null as "no vault to migrate". Silently
    // mapping an HTTP error to null would let the change proceed and orphan the
    // existing blob under the new key.
    const blob = await readVaultJson(vaultDataUrl, "Could not read the vault blob.");
    if (!blob.encrypted_data || !blob.iv) {
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

  // Read and decrypt the note vault (encrypted index + every note row) under
  // the CURRENT key. Same fail-closed contract as recoverCurrentVaultData: any
  // fetch or decrypt failure throws so the password change aborts before
  // anything is rotated. Returns { index: Object|null, notes: [{id, text}] }.
  const recoverCurrentNoteVault = async (
    noteIndexUrl,
    noteListUrl,
    currentPassword,
    currentVaultSalt,
  ) => {
    const oldKey = await resolveCurrentVaultKey(currentPassword, currentVaultSalt);

    const indexBlob = await readVaultJson(noteIndexUrl, "Could not read the note index.");
    let index = null;
    if (indexBlob.encrypted_data && indexBlob.iv) {
      index = await window.AuthCrypto.decryptAccountData(
        indexBlob.encrypted_data,
        indexBlob.iv,
        oldKey,
      );
    }

    // An unreadable list must throw rather than look like zero notes: rotating
    // on that false empty state would strand all existing note rows.
    const listResult = await readVaultJson(
      `${noteListUrl}?content=1`,
      "Could not list the vault notes.",
    );
    const notes = [];
    for (const row of listResult.notes || []) {
      notes.push({
        id: row.id,
        text: await window.PasswordCrypto.decryptPassword(row.content, row.iv, oldKey),
      });
    }

    return { index, notes };
  };

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // Shown once when a migration batch is throttled. The submit button is
  // already in its busy state, but a multi-second stall with no explanation
  // reads as a hang on the one flow the user must not interrupt.
  const notifyMigrationThrottled = () => {
    window.Notify.show(
      "Re-securing your notes is taking a moment. Please keep this tab open.",
      "info",
    );
  };

  // POST one migration batch, waiting out a rate limit rather than failing on
  // it. Only 429 is retried: the endpoint answers block=False specifically so
  // this is distinguishable from a rejected CSRF token or a real error, both
  // of which retrying would not fix. Throws once the delays are exhausted.
  const postMigrationBatch = async (migrateUrl, payload, onThrottled) => {
    const delays = window.VaultMigration.RETRY_DELAYS_MS;
    for (let attempt = 0; ; attempt++) {
      const { response, result } = await window.Http.postForm(migrateUrl, payload);
      if (response.ok && result.success) return;
      if (
        !window.VaultMigration.isRetryableMigrationStatus(response.status) ||
        attempt >= delays.length
      ) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }
      if (attempt === 0 && onThrottled) onThrottled();
      await sleep(delays[attempt]);
    }
  };

  // Re-encrypt the recovered note vault under the new key and save it through
  // the transactional migrate endpoint. Note rows go first (in batches); the
  // re-encrypted index travels in the FINAL batch because it is the client's
  // commit marker (rows before index, always). Throws on failure.
  const remigrateNoteVault = async (noteVault, newKey, migrateUrl) => {
    const items = [];
    for (const note of noteVault.notes) {
      const encrypted = await window.CryptoCore.encryptWithKey(note.text, newKey);
      items.push({ id: note.id, content: encrypted.encryptedData, iv: encrypted.iv });
    }

    let indexPayload = null;
    if (noteVault.index !== null) {
      const encryptedIndex = await window.AuthCrypto.encryptAccountData(noteVault.index, newKey);
      indexPayload = { encrypted_data: encryptedIndex.encryptedData, iv: encryptedIndex.iv };
    }

    const batches = window.VaultMigration.batchNotePayloads(items);
    for (let i = 0; i < batches.length; i++) {
      const isLast = i === batches.length - 1;
      if (batches[i].length === 0 && !(isLast && indexPayload)) continue;

      const payload = { notes: batches[i] };
      if (isLast && indexPayload) payload.index = indexPayload;

      await postMigrationBatch(migrateUrl, payload, notifyMigrationThrottled);
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

  // Phase 1: recover the existing vaults under the CURRENT key before rotating
  // anything. Rotating the password derives a new vault key, so everything
  // encrypted under the old key (the pass-vault blob, the note-vault index and
  // every note row) must be re-encrypted or it becomes unreadable. If any of it
  // exists but can't be read, fail (ok: false) before the change so the data
  // isn't orphaned (the change is retryable; the stored ciphertext is not).
  const recoverVaultBeforeChange = async (endpoints, currentPassword, currentVaultSalt) => {
    try {
      return {
        ok: true,
        vaultData: await recoverCurrentVaultData(
          endpoints.vaultDataUrl,
          currentPassword,
          currentVaultSalt,
        ),
        noteVault: await recoverCurrentNoteVault(
          endpoints.noteIndexUrl,
          endpoints.noteListUrl,
          currentPassword,
          currentVaultSalt,
        ),
      };
    } catch (recoveryError) {
      console.error("Could not read existing vault before password change:", recoveryError);
      window.Notify.show(
        "We couldn't access your saved links and notes to re-secure them. " +
          "Please check your current password and try again.",
        "error",
      );
      return { ok: false, vaultData: null, noteVault: null };
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
  // vault under the new key BEFORE the caller swaps the session key. If saving
  // fails, the decrypted copy held by this page is the recovery: the caller
  // offers it as a download. No-op without stored vault data.
  const resecureVaultAfterChange = async (vaultData, newPassword, newVaultSalt, saveUrl) => {
    if (vaultData === null) return true;
    try {
      await reencryptAndSaveVault(vaultData, newPassword, newVaultSalt, saveUrl);
      return true;
    } catch (migrateError) {
      console.error("Failed to re-secure vault after password change:", migrateError);
      window.Notify.show(
        "Your password was changed, but your saved links could not be re-secured. " +
          "Download the recovery copy below before signing out.",
        "error",
      );
      return false;
    }
  };

  // Phase 3b: same contract as resecureVaultAfterChange, for the note vault
  // (re-secured through the transactional migrate endpoint). No-op when the
  // user has no notes.
  const resecureNoteVaultAfterChange = async (noteVault, newPassword, newVaultSalt, migrateUrl) => {
    if (!noteVault || (noteVault.index === null && noteVault.notes.length === 0)) return true;
    try {
      const newKey = await window.AuthCrypto.deriveKeyFromPassword(newPassword, newVaultSalt);
      await remigrateNoteVault(noteVault, newKey, migrateUrl);
      return true;
    } catch (migrateError) {
      console.error("Failed to re-secure note vault after password change:", migrateError);
      // Deliberately not "re-save them": re-saving is not the recovery, and
      // some notes will not open at all. Whichever batches did land are now
      // under the new key while the rest (and the index) are still under the
      // old one, and the rotated cache context refuses every cached old key.
      // The decrypted copy this page still holds, offered as a download, is
      // the whole of the recovery.
      window.Notify.show(
        "Your password was changed, but your notes could not all be re-secured. " +
          "Download the recovery copy below before signing out.",
        "error",
      );
      return false;
    }
  };

  // Phase 4: swap the session key to the new password's derived key, so the
  // vault remains accessible without signing out and back in. The key is stamped
  // with the post-change session state: VaultSession only adopts a handoff whose
  // cache context matches, and the change rotated that context. Best-effort: the
  // password change itself already succeeded, so a failure here only logs.
  const refreshSessionKey = async (newPassword, newVaultSalt, sessionState) => {
    try {
      await window.AuthCrypto.establishSecureSession(newPassword, newVaultSalt, sessionState);
      return true;
    } catch (cryptoError) {
      console.error("Failed to refresh derived key after password change:", cryptoError);
      return false;
    }
  };

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('form[action*="/auth/signout/"]').forEach((form) => {
      form.addEventListener("submit", () => window.AuthCrypto.clearAllVaultKeys());
    });
    const changePasswordForm = document.getElementById("change-password-form");
    const deleteAccountForm = document.getElementById("delete-account-form");
    const recoveryPanel = document.getElementById("vault-recovery");
    const recoveryButton = document.getElementById("download-vault-recovery");
    let recoveryCopy = null;
    recoveryButton?.addEventListener("click", () => {
      if (!recoveryCopy) return;
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(recoveryCopy, null, 2)], { type: "application/json" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = "proxima-vault-recovery.json";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
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
      // Vault endpoints, defined by the URLconf via the form's data attributes.
      const endpoints = {
        vaultDataUrl: changePasswordForm.dataset.vaultDataUrl || VAULT_DATA_ENDPOINT,
        updateDataUrl: changePasswordForm.dataset.updateDataUrl || SAVE_ENDPOINT,
        noteIndexUrl: changePasswordForm.dataset.noteIndexUrl || NOTE_INDEX_ENDPOINT,
        noteListUrl: changePasswordForm.dataset.noteListUrl || NOTE_LIST_ENDPOINT,
        noteMigrateUrl: changePasswordForm.dataset.noteMigrateUrl || NOTE_MIGRATE_ENDPOINT,
      };

      const resecureVaultsAfterChange = async (recovery, newPassword, newVaultSalt) => {
        if (
          !(await resecureVaultAfterChange(
            recovery.vaultData,
            newPassword,
            newVaultSalt,
            endpoints.updateDataUrl,
          ))
        ) {
          return false;
        }
        return resecureNoteVaultAfterChange(
          recovery.noteVault,
          newPassword,
          newVaultSalt,
          endpoints.noteMigrateUrl,
        );
      };

      // Before the server accepts the change, failures leave the old account
      // untouched. Afterwards, migration can only move forward; the session key
      // is swapped only once both vaults are re-secured, and a failure leaves
      // the decrypted recovery copy as the way out.
      const submitPasswordChange = async (currentPassword, newPassword) => {
        // Both vault reads must be authorized before rotation. Reuse the
        // password already entered in this form, rather than a second prompt.
        const authSecret = await window.AuthCrypto.deriveAuthSecret(
          currentPassword,
          authData.auth_salt,
        );
        const verified = await window.Http.postForm(
          "/auth/reauth/",
          new URLSearchParams({
            auth_secret: authSecret,
            tool: "account",
            expected_user: authData.user_id || "",
          }),
        );
        if (!verified.response.ok || !verified.result.success) {
          window.Notify.show(window.Http.firstError(verified.result), "error");
          return;
        }
        window.Http.setVaultIdentity(verified.result.state.identity);
        const recovery = await recoverVaultBeforeChange(
          endpoints,
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

        window.Http.setVaultIdentity(result.state.identity);
        // The server has rotated the salts whatever happens next; later forms on
        // this page (account deletion, another change) must derive from them.
        authData = { ...authData, auth_salt: result.auth_salt, vault_salt: result.vault_salt };

        if (!(await resecureVaultsAfterChange(recovery, newPassword, result.vault_salt))) {
          // Rotated credentials invalidate cached keys in other tabs. Keep an
          // explicit recovery download here, where both decrypted vaults still
          // exist, instead of relying on opening an old key in a new vault tab.
          recoveryCopy = { passwords: recovery.vaultData, notes: recovery.noteVault };
          recoveryPanel?.classList.remove("hidden");
          clearSensitiveInputs(changePasswordForm);
          return;
        }
        recoveryCopy = null;
        recoveryPanel?.classList.add("hidden");
        await refreshSessionKey(newPassword, result.vault_salt, result.state);

        clearSensitiveInputs(changePasswordForm);
        window.Notify.show(result.message || "Password updated.", "success");
      };

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
          () => submitPasswordChange(currentPassword, newPassword),
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
      exportAction.addEventListener("click", async (event) => {
        event.preventDefault();
        try {
          // The export carries both vaults, so the server requires both grants.
          // This page's unlock modal (tool "account") renews both at once.
          const replies = await Promise.all(
            ["pass", "note"].map((tool) => window.Http.getJson(`/auth/vault-session/?tool=${tool}`)),
          );
          if (replies.some(({ response }) => response.status === 401)) {
            window.location.href = "/auth/signin/?tool=pass";
            return;
          }
          if (
            replies.some(
              ({ response, result }) =>
                !response.ok || !result.success || result.state.user_id !== authData.user_id,
            )
          ) {
            window.Notify.show("Reload the account page before exporting.", "error");
            return;
          }
          if (
            replies.some(({ result }) => !result.state.unlocked) &&
            !(await window.SecureSessionUnlock.ensureSecureSession({ force: true }))
          )
            return;
          window.location.href = exportAction.href;
        } catch {
          window.Notify.show("Unable to export. Check your connection and try again.", "error");
          return;
        }
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

            window.AuthCrypto.clearAllVaultKeys();
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
