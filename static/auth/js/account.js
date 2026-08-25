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

  // Collaboration keypair endpoint (read the vault-key-encrypted private blob
  // to re-encrypt it under the new key); normally carried in data-keypair-url.
  const KEYPAIR_ENDPOINT = "/auth/keypair/";

  // Migration batch bounds: each POST must stay under Django's default
  // DATA_UPLOAD_MAX_MEMORY_SIZE (2.5MB). Note ciphertexts are capped at
  // 200,000 chars server-side, so 8 notes / ~1.5M chars leaves ample headroom.
  const NOTE_MIGRATE_BATCH_MAX_NOTES = 8;
  const NOTE_MIGRATE_BATCH_MAX_CHARS = 1500000;

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
    if (storedKeyBase64) {
      return window.AuthCrypto.importKeyFromBase64(storedKeyBase64);
    }
    if (!currentPassword || !currentVaultSalt) {
      throw new Error("No session key available and cannot derive one to read existing vault data.");
    }
    return window.AuthCrypto.deriveKeyFromPassword(currentPassword, currentVaultSalt);
  };

  const recoverCurrentVaultData = async (vaultDataUrl, currentPassword, currentVaultSalt) => {
    // A failed read must throw (not return null): the caller aborts the password
    // change on a throw, but treats null as "no vault to migrate". Silently
    // mapping an HTTP error to null would let the change proceed and orphan the
    // existing blob under the new key.
    const { response, result: blob } = await window.Http.getJson(vaultDataUrl);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    // `success` is checked separately from the data fields: an unreadable
    // reply must throw, while a successful-but-empty one is a user with no
    // vault yet. Both used to arrive here as a rejected JSON parse; Http now
    // hands back {success: false}, so the distinction has to be made here.
    if (!blob.success) {
      throw new Error(blob.error || "Could not read the vault blob.");
    }
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

    const { response: indexResponse, result: indexBlob } = await window.Http.getJson(noteIndexUrl);
    if (!indexResponse.ok) {
      throw new Error(`HTTP ${indexResponse.status}`);
    }
    // Same fail-closed split as recoverCurrentVaultData: unreadable throws,
    // successful-but-empty means the user has no note index yet.
    if (!indexBlob.success) {
      throw new Error(indexBlob.error || "Could not read the note index.");
    }
    let index = null;
    if (indexBlob.encrypted_data && indexBlob.iv) {
      index = await window.AuthCrypto.decryptAccountData(
        indexBlob.encrypted_data,
        indexBlob.iv,
        oldKey,
      );
    }

    const { response: listResponse, result: listResult } = await window.Http.getJson(
      `${noteListUrl}?content=1`,
    );
    if (!listResponse.ok) {
      throw new Error(`HTTP ${listResponse.status}`);
    }
    // Must throw rather than fall through to an empty list: migrating zero
    // notes "successfully" would rotate the password and strand every note
    // under the old key.
    if (!listResult.success) {
      throw new Error(listResult.error || "Could not list the vault notes.");
    }
    const notes = [];
    for (const row of listResult.notes || []) {
      notes.push({
        id: row.id,
        text: await window.PasswordCrypto.decryptPassword(row.content, row.iv, oldKey),
      });
    }

    return { index, notes };
  };

  // Read and decrypt the collaboration private-key blob under the CURRENT key.
  // Same fail-closed contract as the vault recoveries: a blob that exists but
  // can't be read throws, aborting the change before any key is rotated (a
  // partially-migrated keypair would strand every wrapped document key).
  // Returns the raw PKCS8 bytes to re-encrypt, or null when the account has no
  // keypair. The bytes never re-import as a key, only the ciphertext moves
  // between vault keys.
  const recoverCurrentKeypair = async (keypairUrl, currentPassword, currentVaultSalt) => {
    const { response, result: blob } = await window.Http.getJson(keypairUrl);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    // Unreadable throws; {success: true, exists: false} is an account that
    // never generated a collaboration keypair.
    if (!blob.success) {
      throw new Error(blob.error || "Could not read the account keypair.");
    }
    if (!blob.exists) {
      return null;
    }
    const oldKey = await resolveCurrentVaultKey(currentPassword, currentVaultSalt);
    const pkcs8 = await window.CryptoCore.decryptBytes(
      blob.encrypted_private_key,
      blob.private_key_iv,
      oldKey,
    );
    return { pkcs8 };
  };

  // Split re-encrypted note payloads into POST-sized batches (see the
  // NOTE_MIGRATE_BATCH_* bounds). Always returns at least one batch so the
  // index payload has a final batch to ride in.
  const batchNotePayloads = (items) => {
    const batches = [[]];
    let chars = 0;
    for (const item of items) {
      const last = batches[batches.length - 1];
      if (
        last.length >= NOTE_MIGRATE_BATCH_MAX_NOTES ||
        (last.length > 0 && chars + item.content.length > NOTE_MIGRATE_BATCH_MAX_CHARS)
      ) {
        batches.push([]);
        chars = 0;
      }
      batches[batches.length - 1].push(item);
      chars += item.content.length;
    }
    return batches;
  };

  // Re-encrypt the recovered note vault under the new key and save it through
  // the transactional migrate endpoint. Note rows go first (in batches); the
  // re-encrypted index and keypair blob travel in the FINAL batch because the
  // index is the client's commit marker (rows before index, always) and the
  // keypair must land in the same transaction as it. Throws on failure.
  const remigrateNoteVault = async (noteVault, keypair, newKey, migrateUrl) => {
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

    let keypairPayload = null;
    if (keypair) {
      const rewrapped = await window.CryptoCore.encryptBytesWithKey(keypair.pkcs8, newKey);
      keypairPayload = { encrypted_private_key: rewrapped.encryptedData, iv: rewrapped.iv };
    }

    const batches = batchNotePayloads(items);
    for (let i = 0; i < batches.length; i++) {
      const isLast = i === batches.length - 1;
      const carriesFinal = isLast && (indexPayload || keypairPayload);
      if (batches[i].length === 0 && !carriesFinal) continue;

      const payload = { notes: batches[i] };
      if (isLast && indexPayload) payload.index = indexPayload;
      if (isLast && keypairPayload) payload.keypair = keypairPayload;

      const { response, result } = await window.Http.postForm(migrateUrl, payload);
      if (!response.ok || !result.success) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }
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
        keypair: await recoverCurrentKeypair(
          endpoints.keypairUrl,
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
      return { ok: false, vaultData: null, noteVault: null, keypair: null };
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

  // Phase 3b: same contract as resecureVaultAfterChange, for the note vault
  // and the collaboration keypair (both re-secured through the transactional
  // migrate endpoint). No-op when the user has neither notes nor a keypair.
  const resecureNoteVaultAfterChange = async (
    noteVault,
    keypair,
    newPassword,
    newVaultSalt,
    migrateUrl,
  ) => {
    const noNotes = !noteVault || (noteVault.index === null && noteVault.notes.length === 0);
    if (noNotes && !keypair) return true;
    try {
      const newKey = await window.AuthCrypto.deriveKeyFromPassword(newPassword, newVaultSalt);
      await remigrateNoteVault(noteVault || { index: null, notes: [] }, keypair, newKey, migrateUrl);
      return true;
    } catch (migrateError) {
      console.error("Failed to re-secure note vault after password change:", migrateError);
      window.Notify.show(
        "Your password was changed, but your notes could not be re-secured. " +
          "Open your note vault now and re-save them before signing out.",
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
      // Vault endpoints, defined by the URLconf via the form's data attributes.
      const vaultDataUrl = changePasswordForm.dataset.vaultDataUrl || VAULT_DATA_ENDPOINT;
      const updateDataUrl = changePasswordForm.dataset.updateDataUrl || SAVE_ENDPOINT;
      const noteIndexUrl = changePasswordForm.dataset.noteIndexUrl || NOTE_INDEX_ENDPOINT;
      const noteListUrl = changePasswordForm.dataset.noteListUrl || NOTE_LIST_ENDPOINT;
      const noteMigrateUrl = changePasswordForm.dataset.noteMigrateUrl || NOTE_MIGRATE_ENDPOINT;
      const keypairUrl = changePasswordForm.dataset.keypairUrl || KEYPAIR_ENDPOINT;

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
              { vaultDataUrl, noteIndexUrl, noteListUrl, keypairUrl },
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

            // Password is now rotated server-side; re-secure both vaults, then
            // swap the session key (see the phase helpers for the ordering
            // rationale). The session key is refreshed only when everything
            // was re-secured, so a failure leaves the old key active.
            const passVaultOk = await resecureVaultAfterChange(
              recovery.vaultData,
              newPassword,
              result.vault_salt,
              updateDataUrl,
            );
            const noteVaultOk =
              passVaultOk &&
              (await resecureNoteVaultAfterChange(
                recovery.noteVault,
                recovery.keypair,
                newPassword,
                result.vault_salt,
                noteMigrateUrl,
              ));
            if (!passVaultOk || !noteVaultOk) {
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
