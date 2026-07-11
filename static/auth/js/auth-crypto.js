/**
 * @fileoverview Zero-knowledge vault cryptography: PBKDF2 key derivation,
 * account-data encryption/decryption, password validation, and secure session
 * management. Extends crypto.js - load that file first.
 *
 * Wrapped in an IIFE; the primitives it builds on are read from
 * window.CryptoCore (published by crypto.js): CryptoError, bufferToBase64,
 * base64ToBuffer, generateIV, exportKeyToBase64, importKeyFromBase64,
 * AES_KEY_LENGTH_BITS, GCM_TAG_LENGTH_BITS.
 */
(function () {
  "use strict";

  const core = window.CryptoCore;
  if (!core) {
    console.error("Base crypto.js must be loaded before auth-crypto.js");
    return;
  }

  const {
    CryptoError,
    bufferToBase64,
    base64ToBuffer,
    generateIV,
    exportKeyToBase64,
    importKeyFromBase64,
    AES_KEY_LENGTH_BITS,
    GCM_TAG_LENGTH_BITS,
  } = core;

  const KDF_ITERATIONS = 100000;
  // Must match SALT_LENGTH_BYTES in apps/auth/constants.py (server-side salt size).
  const KDF_SALT_LENGTH_BYTES = 32;
  const AUTH_SECRET_CONTEXT = "proxima.red/auth/v1";

  /**
   * Generates a cryptographically secure KDF salt. The client generates both the
   * auth and vault salts at signup; the server only ever stores them.
   * @returns {string} Base64-encoded 32-byte salt.
   */
  function generateSalt() {
    try {
      const salt = new Uint8Array(KDF_SALT_LENGTH_BYTES);
      window.crypto.getRandomValues(salt);
      return bufferToBase64(salt);
    } catch (error) {
      throw new CryptoError("Failed to generate salt: " + error.message, "SALT_GENERATION_FAILED");
    }
  }

  /**
   * Prefixes the salt with a context label for PBKDF2 domain separation, so the
   * auth secret and vault key derived from the same password can never collide
   * even if they shared a salt. Only the auth-secret derivation uses this; see
   * AUTH_SECRET_CONTEXT.
   * @param {string} context Domain-separation label.
   * @param {string} saltBase64 Base64-encoded salt.
   * @returns {Uint8Array} `context:` bytes followed by the decoded salt bytes.
   */
  function contextSalt(context, saltBase64) {
    const contextBytes = new TextEncoder().encode(`${context}:`);
    const saltBytes = base64ToBuffer(saltBase64);
    const combined = new Uint8Array(contextBytes.length + saltBytes.length);
    combined.set(contextBytes, 0);
    combined.set(saltBytes, contextBytes.length);
    return combined;
  }

  /**
   * Derives a symmetric AES-256 key from a password using PBKDF2-SHA256.
   * @param {string} password
   * @param {string} saltBase64 Base64-encoded salt.
   * @param {number} [iterations=100000] PBKDF2 iteration count.
   * @param {boolean} [extractable=false] Whether the derived key can be exported.
   *   Pass true when the key must be persisted in sessionStorage across page loads.
   * @returns {Promise<CryptoKey>}
   */
  async function deriveKeyFromPassword(
    password,
    saltBase64,
    iterations = KDF_ITERATIONS,
    extractable = false,
  ) {
    try {
      if (!password || typeof password !== "string") {
        throw new Error("Invalid password: must be a non-empty string");
      }
      if (!saltBase64 || typeof saltBase64 !== "string") {
        throw new Error("Invalid salt: must be a non-empty Base64 string");
      }

      const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"],
      );

      return await window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: base64ToBuffer(saltBase64), iterations, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: AES_KEY_LENGTH_BITS },
        extractable,
        ["encrypt", "decrypt"],
      );
    } catch (error) {
      throw new CryptoError(
        "Failed to derive key from password: " + error.message,
        "KEY_DERIVATION_FAILED",
      );
    }
  }

  /**
   * Derives the authentication secret sent to the server for Argon2 hashing.
   * This is intentionally separate from the vault encryption key; receiving this
   * value does not let the server derive the vault key.
   * @param {string} password
   * @param {string} authSaltBase64
   * @param {number} [iterations=100000]
   * @returns {Promise<string>} Base64-encoded 256-bit authentication secret.
   */
  async function deriveAuthSecret(password, authSaltBase64, iterations = KDF_ITERATIONS) {
    try {
      if (!password || typeof password !== "string") {
        throw new Error("Invalid password: must be a non-empty string");
      }
      if (!authSaltBase64 || typeof authSaltBase64 !== "string") {
        throw new Error("Invalid auth salt: must be a non-empty Base64 string");
      }

      const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveBits"],
      );

      const secretBits = await window.crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: contextSalt(AUTH_SECRET_CONTEXT, authSaltBase64),
          iterations,
          hash: "SHA-256",
        },
        keyMaterial,
        AES_KEY_LENGTH_BITS,
      );

      return bufferToBase64(new Uint8Array(secretBits));
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      throw new CryptoError(
        "Failed to derive authentication secret: " + error.message,
        "AUTH_SECRET_DERIVATION_FAILED",
      );
    }
  }

  /**
   * Imports a Base64-encoded AES-256 vault key. Delegates to crypto.js's
   * importKeyFromBase64 but defaults to both encrypt and decrypt usages, because a
   * vault key must do both (the sharing flow's import is decrypt-only).
   * Exposed as AuthCrypto.importKeyFromBase64.
   * @param {string} base64Key Base64-encoded key material.
   * @param {string[]} [usages=["encrypt","decrypt"]]
   * @returns {Promise<CryptoKey>}
   */
  function importVaultKeyFromBase64(base64Key, usages = ["encrypt", "decrypt"]) {
    return importKeyFromBase64(base64Key, usages);
  }

  /**
   * Encrypts an account data object as JSON under the user's derived key.
   * @param {Object} accountData
   * @param {CryptoKey} key The derived encryption key.
   * @returns {Promise<{encryptedData: string, iv: string}>} Both Base64-encoded.
   */
  async function encryptAccountData(accountData, key) {
    try {
      if (!accountData || typeof accountData !== "object") {
        throw new Error("Invalid account data: must be an object");
      }

      const iv = generateIV();
      const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH_BITS },
        key,
        new TextEncoder().encode(JSON.stringify(accountData)),
      );

      return {
        encryptedData: bufferToBase64(new Uint8Array(encryptedBuffer)),
        iv: bufferToBase64(iv),
      };
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      throw new CryptoError(
        "Failed to encrypt account data: " + error.message,
        "ACCOUNT_ENCRYPTION_FAILED",
      );
    }
  }

  /**
   * Decrypts account data using the user's derived key and parses the JSON.
   * An `OperationError` from the Web Crypto API means the key is wrong or the
   * ciphertext was tampered with.
   * @param {string} encryptedDataBase64 Base64-encoded ciphertext.
   * @param {string} ivBase64 Base64-encoded IV.
   * @param {CryptoKey} key The derived encryption key.
   * @returns {Promise<Object>} The decrypted account data object.
   */
  async function decryptAccountData(encryptedDataBase64, ivBase64, key) {
    try {
      if (!encryptedDataBase64 || !ivBase64) {
        throw new Error("Invalid input: encrypted data and IV are required");
      }

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64ToBuffer(ivBase64), tagLength: GCM_TAG_LENGTH_BITS },
        key,
        base64ToBuffer(encryptedDataBase64),
      );

      return JSON.parse(new TextDecoder().decode(decryptedBuffer));
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      if (error.name === "OperationError") {
        throw new CryptoError(
          "Authentication failed: Invalid password or corrupted data",
          "AUTHENTICATION_FAILED",
        );
      }
      throw new CryptoError(
        "Failed to decrypt account data: " + error.message,
        "ACCOUNT_DECRYPTION_FAILED",
      );
    }
  }

  /**
   * Validates the password client-side.
   *
   * The only requirement is an 8-character minimum. The 256-character cap is a
   * client-side bound on PBKDF2 input; the raw password never reaches the server
   * (only a fixed-size derived auth secret does), so there is no server-side
   * password-length check to mirror.
   * @param {string} password
   * @returns {{isValid: boolean, messages: string[]}}
   */
  function validatePassword(password) {
    const result = { isValid: true, messages: [] };

    if (!password || typeof password !== "string") {
      result.isValid = false;
      result.messages.push("Password is required");
      return result;
    }

    if (password.length < 8) {
      result.isValid = false;
      result.messages.push("Password must be at least 8 characters long");
    }

    if (password.length > 256) {
      result.isValid = false;
      result.messages.push("Password must be no more than 256 characters long");
    }

    return result;
  }

  // sessionStorage keys for the zero-knowledge vault session. The derived master
  // key never leaves the browser; it is kept here for the lifetime of the session
  // so the vault can decrypt data without re-deriving on every request.
  const SECURE_SESSION_STORAGE_KEYS = {
    masterKey: "passwdMasterKey",
  };

  /**
   * Derive the master key from (password, salt) and return it Base64-encoded,
   * WITHOUT persisting it. Used when the key must travel to another origin (the
   * vault subdomain) rather than be stored on the current one - see signin.js.
   * Throws on missing salt or derivation failure.
   * @param {string} password
   * @param {string} salt Base64-encoded salt returned by the server.
   * @returns {Promise<string>} Base64-encoded AES-256 vault key.
   */
  async function deriveVaultKeyBase64(password, salt) {
    if (!salt) {
      throw new CryptoError("Missing salt from authentication response.", "MISSING_SALT");
    }

    const derivedKey = await deriveKeyFromPassword(password, salt, KDF_ITERATIONS, true);
    return exportKeyToBase64(derivedKey);
  }

  /**
   * Persist an already-exported Base64 vault key in this origin's sessionStorage
   * so the vault can decrypt this session's data without re-deriving on every
   * request.
   * @param {string} exportedKey Base64-encoded vault key.
   */
  function storeVaultKey(exportedKey) {
    sessionStorage.setItem(SECURE_SESSION_STORAGE_KEYS.masterKey, exportedKey);
  }

  /**
   * Derive the master key from (password, salt) and persist it in
   * sessionStorage, so the vault can decrypt this session's data. Throws on
   * missing salt or derivation failure.
   * @param {string} password
   * @param {string} salt Base64-encoded salt returned by the server.
   * @returns {Promise<void>}
   */
  async function establishSecureSession(password, salt) {
    storeVaultKey(await deriveVaultKeyBase64(password, salt));
  }

  /**
   * Adopt a vault key handed over in the URL fragment and scrub it from the URL.
   *
   * After sign-in on the main site, the vault key is passed to the vault origin
   * in the redirect fragment (`/vault/#<base64key>`) because sessionStorage is
   * origin-scoped and can't be shared across subdomains. The fragment is never
   * sent to the server (by spec) and is stripped from Referer headers - the same
   * model as the anonymous share links. This validates it is a 32-byte key,
   * stores it for this origin, and replaces the history entry so the key does
   * not linger in the address bar, history, or bookmarks. A non-empty but
   * malformed fragment is still scrubbed (then ignored). No-op without a
   * fragment, or when a key is already stored for this origin.
   * @returns {boolean} True when a valid key was adopted from the fragment.
   */
  function consumeVaultKeyFromFragment() {
    const hash = window.location.hash;
    if (!hash || hash.length < 2) return false;
    if (sessionStorage.getItem(SECURE_SESSION_STORAGE_KEYS.masterKey)) return false;

    const scrub = () =>
      window.history.replaceState(
        null,
        document.title,
        window.location.pathname + window.location.search,
      );

    let adopted = false;
    try {
      const exportedKey = decodeURIComponent(hash.slice(1));
      // A vault key is a Base64-encoded 32-byte (AES-256) value; reject anything
      // else rather than storing a key that will fail to import/decrypt later.
      if (base64ToBuffer(exportedKey).length === AES_KEY_LENGTH_BITS / 8) {
        storeVaultKey(exportedKey);
        adopted = true;
      }
    } catch (error) {
      // Malformed fragment (bad base64/encoding): fall through and just scrub.
    }
    scrub();
    return adopted;
  }

  /**
   * Remove all secure-session material from sessionStorage (sign out, account
   * deletion, or clearing stale state before a fresh sign in).
   */
  function clearSecureSession() {
    sessionStorage.removeItem(SECURE_SESSION_STORAGE_KEYS.masterKey);
  }

  window.AuthCrypto = {
    generateSalt,
    deriveKeyFromPassword,
    deriveAuthSecret,
    encryptAccountData,
    decryptAccountData,
    validatePassword,
    deriveVaultKeyBase64,
    storeVaultKey,
    establishSecureSession,
    consumeVaultKeyFromFragment,
    clearSecureSession,
    STORAGE_KEYS: SECURE_SESSION_STORAGE_KEYS,
    exportKeyToBase64,
    importKeyFromBase64: importVaultKeyFromBase64,
    CryptoError,
  };
})();
