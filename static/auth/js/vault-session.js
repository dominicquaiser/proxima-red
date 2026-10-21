/** Independent vault timers, foreground note activity, and scoped key caches. */
(function () {
  "use strict";

  const CHECK_INTERVAL = 60 * 1000;

  function create({ tool, userId, onLock, onUnlock, onSignedOut, onIdentityChange }) {
    const storageKey = `vaultKey:${tool}`;
    const NOTE_CACHE = window.AuthCrypto.STORAGE_KEYS.noteMirror;
    const stateUrl = `/auth/vault-session/?tool=${tool}`;
    let state = null;
    let key = null;
    let expectedIdentity = null;
    let deadline = 0;
    let expiryTimer = null;
    let activityTimer = null;
    let lastActivitySent = 0;
    let recovering = null;
    let checking = null;
    let stopped = false;
    let locked = true;
    // Polling continues after a 401 so a sign-in elsewhere can restore access,
    // but onSignedOut fires once per sign-out, not on every periodic check.
    let signedOut = false;

    const read = (storage, name) => {
      try {
        return JSON.parse(storage.getItem(name));
      } catch {
        return null;
      }
    };
    const remove = (storage, name) => {
      try {
        storage.removeItem(name);
      } catch {
        /* Storage may be unavailable. */
      }
    };
    const write = (storage, name, value) => {
      try {
        storage.setItem(name, JSON.stringify(value));
      } catch {
        /* Keep the in-memory key. */
      }
    };
    const clearKeys = (preserveMirror = false) => {
      key = null;
      remove(sessionStorage, storageKey);
      if (tool === "note" && !preserveMirror) remove(localStorage, NOTE_CACHE);
      window.AuthCrypto.clearSecureSession();
    };
    const lock = (preserveMirror = false) => {
      clearKeys(preserveMirror);
      clearTimeout(expiryTimer);
      clearTimeout(activityTimer);
      expiryTimer = null;
      activityTimer = null;
      if (!locked) onLock();
      locked = true;
    };
    const changedIdentity = () => {
      stopped = true;
      lock();
      window.SecureSessionUnlock.dismiss();
      onIdentityChange();
    };
    const remember = () => {
      if (!key || !state?.unlocked) return;
      const entry = {
        key,
        context: state.cache_context,
        identity: state.identity,
        expiresAt: state.expires_at,
      };
      write(sessionStorage, storageKey, entry);
      if (tool === "note") write(localStorage, NOTE_CACHE, entry);
    };
    const cachedKey = () => {
      // Only a handoff carrying this session's context can populate a new cache.
      const transfer = read(sessionStorage, window.AuthCrypto.STORAGE_KEYS.context);
      if (transfer?.cache_context === state.cache_context && transfer.identity === state.identity) {
        const transferred = sessionStorage.getItem(window.AuthCrypto.STORAGE_KEYS.masterKey);
        window.AuthCrypto.clearSecureSession();
        if (transferred) return transferred;
      }
      for (const [storage, name] of [
        [sessionStorage, storageKey],
        ...(tool === "note" ? [[localStorage, NOTE_CACHE]] : []),
      ]) {
        const entry = read(storage, name);
        if (
          entry?.context === state.cache_context &&
          entry.identity === state.identity &&
          entry.expiresAt > state.server_time &&
          typeof entry.key === "string"
        )
          return entry.key;
        remove(storage, name);
      }
      return null;
    };
    const applyState = (next, requestedAt) => {
      if (next.user_id !== userId || (expectedIdentity && next.identity !== expectedIdentity)) {
        changedIdentity();
        return false;
      }
      expectedIdentity = next.identity;
      window.Http.setVaultIdentity(expectedIdentity);
      state = next;
      deadline = requestedAt + Math.max(0, next.expires_at - next.server_time) * 1000;
      if (deadline <= Date.now()) state.unlocked = false;
      clearTimeout(expiryTimer);
      if (state.unlocked)
        expiryTimer = setTimeout(
          () => {
            // Lock immediately, even if the network hangs. A sibling note tab may
            // have renewed its cache; leave that copy for the server-checked recovery.
            lock(true);
            void refresh();
          },
          Math.max(1, deadline - Date.now()),
        );
      return true;
    };
    const fetchState = async (activity = false) => {
      const requestedAt = Date.now();
      const { response, result } = activity
        ? await window.Http.postForm("/auth/vault-session/", new URLSearchParams())
        : await window.Http.getJson(stateUrl);
      if (response.status === 401) {
        lock();
        window.SecureSessionUnlock.dismiss();
        if (!signedOut) {
          signedOut = true;
          onSignedOut();
        }
        return false;
      }
      signedOut = false;
      if (response.status === 409) {
        changedIdentity();
        return false;
      }
      if (response.status === 423) {
        state = { ...state, unlocked: false };
        return true;
      }
      if (!response.ok || !result.success || !result.state)
        throw new Error("Unable to check vault access.");
      return applyState(result.state, requestedAt);
    };
    const obtainKey = async () => {
      if (state.unlocked) key = key || cachedKey();
      if (!state.unlocked || !key) {
        lock();
        const unlocked = await window.SecureSessionUnlock.ensureSecureSession({ force: true });
        if (!unlocked || stopped || !(await fetchState()) || !state.unlocked) return null;
        key = cachedKey();
      }
      if (!key) return null;
      locked = false;
      remember();
      return key;
    };
    const recover = () => {
      if (recovering) return recovering;
      recovering = obtainKey()
        .then(async (resolved) => {
          if (resolved && !stopped) await onUnlock(resolved);
        })
        .catch(() => {
          window.Notify.show("Unable to unlock. Check your connection and try again.", "error");
        })
        .finally(() => {
          recovering = null;
        });
      return recovering;
    };
    const refresh = async (activity = false) => {
      if (stopped) return;
      // Timers may have been suspended while the device slept. Hide expired
      // access before starting (or waiting for) a network request on resume.
      if (!locked && deadline && Date.now() >= deadline) lock(true);
      if (checking) return;
      checking = (async () => {
        try {
          if (!(await fetchState(activity))) return;
          if (!state.unlocked || !key) {
            // Prompting must not hold the status request open: another tab may
            // sign out or rotate credentials while the prompt is visible.
            void recover();
          } else remember();
        } catch {
          // A disconnected tab cannot extend a grant beyond its last deadline.
          if (deadline && Date.now() >= deadline) lock();
        }
      })();
      await checking;
      checking = null;
    };
    const activity = (event) => {
      if (event && event.isTrusted === false) return;
      if (tool !== "note" || stopped || locked || document.visibilityState !== "visible") return;
      if (Date.now() >= deadline) {
        void refresh();
        return;
      }
      if (activityTimer) return;
      const delay = Math.max(0, CHECK_INTERVAL - (Date.now() - lastActivitySent));
      activityTimer = setTimeout(() => {
        activityTimer = null;
        if (locked || document.visibilityState !== "visible") return;
        // Retry a queued user action after a status request, without manufacturing
        // future activity from the periodic status timer.
        if (checking) {
          activityTimer = setTimeout(() => {
            activityTimer = null;
            activity();
          }, 1000);
          return;
        }
        lastActivitySent = Date.now();
        void refresh(true);
      }, delay || 1);
    };
    const start = async () => {
      window.AuthCrypto.consumeVaultKeyFromFragment();
      if (!(await fetchState())) return null;
      const resolved = await obtainKey();
      if (!resolved) return null;
      setInterval(() => {
        if (document.visibilityState === "visible") void refresh();
      }, CHECK_INTERVAL);
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") void refresh();
      });
      window.addEventListener("focus", () => {
        void refresh();
      });
      for (const event of ["pointerdown", "keydown", "input", "wheel", "touchstart"]) {
        document.addEventListener(event, activity, { passive: true });
      }
      window.addEventListener("vault-session-error", ({ detail }) => {
        if (detail.result.code === "vault_identity_changed") changedIdentity();
        else void refresh();
      });
      document.querySelectorAll('form[action*="/auth/signout/"]').forEach((form) => {
        form.addEventListener("submit", () => {
          stopped = true;
          lock();
          window.AuthCrypto.clearAllVaultKeys();
        });
      });
      activity(); // Opening a visible note vault is an explicit visit.
      return resolved;
    };
    return { start, refresh };
  }

  window.VaultSession = { create };
})();
