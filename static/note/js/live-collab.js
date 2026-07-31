/**
 * @fileoverview Named-collaborator management for live notes: owner
 * restrict/invite/revoke actions and wrapped-key recovery for invited users.
 *
 * Document keys are never sent raw: each collaborator gets a client-side
 * public-key wrap. Revocation rotates the document key and re-wraps survivors.
 */
(function () {
  "use strict";

  // Same localStorage slot the note vault uses, so a key unlocked in either
  // place is reused here without re-prompting.
  const NOTE_VAULT_KEY_STORAGE = "noteVaultMasterKey";
  const USER_ID_RE = /^[0-9]{8}$/;

  /**
   * Assemble the POST body for a re-key.
   *
   * @param {Object} params
   * @returns {Object}
   */
  function assembleRekeyPayload(params) {
    return {
      snapshot: params.snapshot.snapshot,
      snapshot_iv: params.snapshot.snapshot_iv,
      covers_seq: params.coversSeq,
      key_epoch: params.epoch,
      remove_user_id: params.removeUserId || null,
      wraps: params.wraps,
    };
  }

  /**
   * User ids that must be re-wrapped after removing one collaborator.
   *
   * @param {Array<{user_id: string}>} collaborators
   * @param {?string} removeUserId
   * @returns {string[]}
   */
  function survivorIds(collaborators, removeUserId) {
    return collaborators
      .map(function (collaborator) {
        return collaborator.user_id;
      })
      .filter(function (id) {
        return id !== removeUserId;
      });
  }

  // Auth endpoints read request.POST; note collaboration endpoints read JSON.
  function form(fields) {
    return new URLSearchParams(fields);
  }

  function create(opts) {
    const { doc, urls, context, getDocKeyBase64, setDocKey, panel, onTerminal } = opts;
    // Late-bound because sync/presence are created after key resolution.
    const refs = opts.refs;
    const sync = () => refs.sync;
    const presence = () => refs.presence;

    // --- Vault key + account private key ---

    /** @returns {Promise<string|null>} Base64 vault key, or null if locked. */
    function resolveVaultKeyBase64() {
      // Same cross-tab (localStorage-mirrored) resolution the note vault uses.
      return window.AuthCrypto.resolveVaultKeyBase64({
        localStorageKey: NOTE_VAULT_KEY_STORAGE,
      });
    }

    /**
     * Decrypt/import the account ECDH keypair, creating one lazily if needed.
     *
     * @returns {Promise<{privateKey: CryptoKey, publicKey: string}>}
     */
    async function getAccountKeys() {
      const vaultKeyBase64 = await resolveVaultKeyBase64();
      if (!vaultKeyBase64) throw new Error("locked");
      const vaultKey = await window.AuthCrypto.importKeyFromBase64(vaultKeyBase64);

      const { response, result } = await window.Http.getJson(urls.keypair);
      if (!response.ok || !result.success) throw new Error("keypair fetch failed");

      if (result.exists) {
        const privateKey = await window.KeyWrap.decryptPrivateKeyBlob(
          result.encrypted_private_key,
          result.private_key_iv,
          vaultKey,
        );
        return { privateKey: privateKey, publicKey: result.public_key };
      }

      // Lazily create one, encrypting the private key under the vault key.
      const pair = await window.KeyWrap.generateKeyPair();
      const blob = await window.KeyWrap.encryptPrivateKeyBlob(pair.privateKey, vaultKey);
      const { response: createResponse, result: createResult } = await window.Http.postForm(
        urls.keypair,
        form({
          public_key: pair.publicKeyBase64,
          encrypted_private_key: blob.encryptedPrivateKey,
          private_key_iv: blob.iv,
        }),
      );
      if (!createResponse.ok || !createResult.success) {
        // A 409 means another tab created it first; re-fetch and use that.
        if (createResponse.status === 409) return getAccountKeys();
        throw new Error("keypair create failed");
      }
      return { privateKey: pair.privateKey, publicKey: pair.publicKeyBase64 };
    }

    // --- Invited-user boot: recover the doc key from a wrap ---

    /** @returns {Promise<{key: CryptoKey, keyBase64: string, epoch: number}|null>} */
    async function resolveDocKeyFromWrap() {
      const { privateKey } = await getAccountKeys();
      const { response, result } = await window.Http.getJson(urls.key);
      if (response.status === 404) return null; // not a collaborator / revoked
      if (!response.ok || !result.success) throw new Error("key fetch failed");

      const unwrapped = await window.KeyWrap.unwrapDocKey(
        {
          wrappedKey: result.wrapped_key,
          wrapIv: result.wrap_iv,
          ephemeralPublicKey: result.ephemeral_public_key,
        },
        privateKey,
      );
      return { key: unwrapped.key, keyBase64: unwrapped.keyBase64, epoch: result.key_epoch };
    }

    // onStaleEpoch handler: survivors adopt the new key; revoked users stop.
    async function recoverAfterRekey() {
      const recovered = await resolveDocKeyFromWrap();
      if (!recovered) {
        onTerminal("error", "Your access to this note was revoked.");
        return;
      }
      setDocKey(recovered.key, recovered.keyBase64);
      sync().adoptRekey(recovered.key, recovered.epoch);
      if (presence()) presence().setKey(recovered.key);
    }

    // --- Owner actions ---

    async function wrapDocKeyTo(publicKeyBase64) {
      const rawDocKey = new Uint8Array(window.CryptoCore.base64ToBuffer(getDocKeyBase64()));
      return window.KeyWrap.wrapDocKey(rawDocKey, publicKeyBase64);
    }

    async function restrictNote() {
      const { publicKey } = await getAccountKeys();
      const wrap = await wrapDocKeyTo(publicKey);
      const { response, result } = await window.Http.postForm(urls.access, {
        restrict: true,
        wrapped_key: wrap.wrappedKey,
        wrap_iv: wrap.wrapIv,
        ephemeral_public_key: wrap.ephemeralPublicKey,
      });
      if (!response.ok || !result.success) {
        throw new Error(window.Http.firstError(result));
      }
      context.accessMode = "restricted";
    }

    async function inviteCollaborator(inviteeUserId) {
      // Ensure our own vault is unlocked (needed later for revocation too).
      await getAccountKeys();
      const { response: pkResponse, result: pkResult } = await window.Http.postForm(
        urls.pubkey,
        form({ user_id: inviteeUserId }),
      );
      if (pkResponse.status === 404) {
        throw new Error(pkResult.error || "That user cannot receive invites yet.");
      }
      if (!pkResponse.ok || !pkResult.success) throw new Error("Lookup failed.");

      const wrap = await wrapDocKeyTo(pkResult.public_key);
      const { response, result } = await window.Http.postForm(urls.collaborators, {
        user_id: inviteeUserId,
        wrapped_key: wrap.wrappedKey,
        wrap_iv: wrap.wrapIv,
        ephemeral_public_key: wrap.ephemeralPublicKey,
      });
      if (!response.ok || !result.success) throw new Error(window.Http.firstError(result));
      return result.collaborators;
    }

    // Client-orchestrated rekey for revocation; retries on a stale tail race.
    async function revokeCollaborator(removeUserId, collaborators, attempt) {
      attempt = attempt || 0;
      const { privateKey, publicKey } = await getAccountKeys();

      await sync().flushNow();
      const ctx = sync().rekeyContext();
      const survivors = survivorIds(collaborators, removeUserId);

      // Fresh document key plus a snapshot of the full current Yjs state.
      const newKey = await window.CryptoCore.generateEncryptionKey();
      const newKeyBase64 = await window.CryptoCore.exportKeyToBase64(newKey);
      const newKeyBytes = new Uint8Array(window.CryptoCore.base64ToBuffer(newKeyBase64));
      const stateBytes = window.Y.encodeStateAsUpdate(doc);
      const snap = await window.CryptoCore.encryptBytesWithKey(stateBytes, newKey);

      // Re-wrap the new key to every survivor; the owner uses its local pubkey.
      const wraps = [];
      for (const userId of survivors) {
        let publicKeyBase64;
        if (userId === context.userId) {
          publicKeyBase64 = publicKey;
        } else {
          const { response, result } = await window.Http.postForm(
            urls.pubkey,
            form({ user_id: userId }),
          );
          if (!response.ok || !result.success) throw new Error("A survivor has no key.");
          publicKeyBase64 = result.public_key;
        }
        const wrap = await window.KeyWrap.wrapDocKey(newKeyBytes, publicKeyBase64);
        wraps.push({
          user_id: userId,
          wrapped_key: wrap.wrappedKey,
          wrap_iv: wrap.wrapIv,
          ephemeral_public_key: wrap.ephemeralPublicKey,
        });
      }

      const body = assembleRekeyPayload({
        coversSeq: ctx.cursor,
        epoch: ctx.epoch + 1,
        removeUserId: removeUserId,
        snapshot: { snapshot: snap.encryptedData, snapshot_iv: snap.iv },
        wraps: wraps,
      });
      const { response, result } = await window.Http.postForm(urls.rekey, body);

      if (response.status === 409 && attempt < 2) {
        // A concurrent append moved the tail; re-flush and retry.
        return revokeCollaborator(removeUserId, collaborators, attempt + 1);
      }
      if (!response.ok || !result.success) throw new Error(window.Http.firstError(result));

      // Adopt the new key locally so our own edits continue seamlessly.
      setDocKey(newKey, newKeyBase64);
      sync().adoptRekey(newKey, result.key_epoch);
      if (presence()) presence().setKey(newKey);
      return result.collaborators;
    }

    async function listCollaborators() {
      const { response, result } = await window.Http.getJson(urls.collaborators);
      if (!response.ok || !result.success) throw new Error("Could not load collaborators.");
      return result.collaborators;
    }

    // --- Panel wiring (owner UI) ---

    let currentCollaborators = [];

    function wirePanel() {
      if (!panel || !context.isOwner) return;

      const restrictBtn = panel.querySelector("#collab-restrict-btn");
      const manageSection = panel.querySelector("[data-collab-manage]");
      const restrictSection = panel.querySelector("[data-collab-restrict]");
      const inviteInput = panel.querySelector("#collab-invite-input");
      const inviteBtn = panel.querySelector("#collab-invite-btn");
      const listEl = panel.querySelector("#collab-list");

      function showManage(isRestricted) {
        if (restrictSection) restrictSection.classList.toggle("hidden", isRestricted);
        if (manageSection) manageSection.classList.toggle("hidden", !isRestricted);
      }
      showManage(context.accessMode === "restricted");

      function renderList() {
        if (!listEl) return;
        listEl.replaceChildren();
        for (const collaborator of currentCollaborators) {
          const item = document.createElement("li");
          item.className = "collab-list__item";
          const label = document.createElement("span");
          label.className = "collab-list__id";
          label.textContent =
            collaborator.user_id.slice(0, 4) + "-" + collaborator.user_id.slice(4);
          if (collaborator.role === "owner") label.textContent += " (owner)";
          item.appendChild(label);
          if (collaborator.role !== "owner") {
            const revoke = document.createElement("button");
            revoke.type = "button";
            revoke.className = "collab-list__revoke";
            revoke.textContent = "Revoke";
            revoke.addEventListener("click", function () {
              runAction(revoke, async function () {
                currentCollaborators = await revokeCollaborator(
                  collaborator.user_id,
                  currentCollaborators,
                );
                renderList();
                window.Notify.show("Access revoked and the note re-keyed.", "success");
              });
            });
            item.appendChild(revoke);
          }
          listEl.appendChild(item);
        }
      }

      async function refreshList() {
        try {
          currentCollaborators = await listCollaborators();
          renderList();
        } catch (error) {
          /* leave the last-known list on a transient failure */
        }
      }

      if (restrictBtn) {
        restrictBtn.addEventListener("click", function () {
          runAction(restrictBtn, async function () {
            await restrictNote();
            showManage(true);
            await refreshList();
            window.Notify.show("This note is now collaborator-only.", "success");
          });
        });
      }

      if (inviteBtn && inviteInput) {
        inviteBtn.addEventListener("click", function () {
          const userId = (inviteInput.value || "").trim();
          if (!USER_ID_RE.test(userId)) {
            window.Notify.show("Enter the collaborator's 8-digit User ID.", "error");
            return;
          }
          runAction(inviteBtn, async function () {
            currentCollaborators = await inviteCollaborator(userId);
            inviteInput.value = "";
            renderList();
            window.Notify.show("Collaborator invited.", "success");
          });
        });
      }

      if (context.accessMode === "restricted") refreshList();
    }

    /** Run a panel action with a busy button and error notification. */
    async function runAction(button, action) {
      const previous = button.disabled;
      button.disabled = true;
      try {
        await action();
      } catch (error) {
        console.error("Collaboration action failed:", error);
        window.Notify.show(
          error && error.message ? error.message : "That action could not be completed.",
          "error",
        );
      } finally {
        button.disabled = previous;
      }
    }

    return {
      resolveDocKeyFromWrap: resolveDocKeyFromWrap,
      recoverAfterRekey: recoverAfterRekey,
      restrictNote: restrictNote,
      inviteCollaborator: inviteCollaborator,
      revokeCollaborator: revokeCollaborator,
      listCollaborators: listCollaborators,
      wirePanel: wirePanel,
    };
  }

  window.NoteLiveCollab = {
    create: create,
    // Pure helpers, exposed for the Node tests (tests/js/live-collab.test.js).
    assembleRekeyPayload: assembleRekeyPayload,
    survivorIds: survivorIds,
  };
})();
