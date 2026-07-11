/**
 * @fileoverview AES-256-GCM encryption for the anonymous sharing flow, using
 * the Web Crypto API. The key travels in the URL fragment and is never sent
 * to the server.
 *
 * Wrapped in an IIFE so its internals stay off the global scope. The public
 * surface is window.PasswordCrypto; the lower-level primitives that
 * auth-crypto.js builds on are shared explicitly via window.CryptoCore. Load
 * this file before auth-crypto.js.
 */
(function () {
  "use strict";

  /** Thrown by all public crypto functions so callers can distinguish crypto
   *  failures from generic JS errors. */
  class CryptoError extends Error {
    constructor(message, code = "CRYPTO_ERROR") {
      super(message);
      this.name = "CryptoError";
      this.code = code;
    }
  }

  // Centralised so key, IV, and tag sizes can't silently drift across the
  // generate / import / encrypt / decrypt paths. The byte lengths are also a
  // cross-runtime contract with the server (see apps/*/constants.py).
  const AES_KEY_LENGTH_BITS = 256;
  const AES_KEY_LENGTH_BYTES = AES_KEY_LENGTH_BITS / 8; // 32 bytes; cf. AUTH_SECRET_LENGTH_BYTES in apps/auth/constants.py
  const GCM_IV_LENGTH_BYTES = 12; // 96-bit IV; must match GCM_IV_LENGTH_BYTES in apps/passwd/constants.py
  const GCM_TAG_LENGTH_BITS = 128; // full-length authentication tag

  // Guard against accidentally huge payloads.
  const MAX_PASSWORD_LENGTH = 10000;

  // --- Base64 / binary helpers ---

  /**
   * @param {Uint8Array} buffer
   * @returns {string} Base64-encoded string.
   */
  function bufferToBase64(buffer) {
    return btoa(Array.from(buffer, (b) => String.fromCharCode(b)).join(""));
  }

  /**
   * @param {string} base64
   * @returns {Uint8Array}
   */
  function base64ToBuffer(base64) {
    return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  }

  // --- Core cryptographic functions ---

  /**
   * Generates a cryptographically secure AES-256-GCM key.
   * The key is extractable so it can be embedded in the URL fragment.
   * @returns {Promise<CryptoKey>}
   */
  async function generateEncryptionKey() {
    try {
      return await window.crypto.subtle.generateKey(
        { name: "AES-GCM", length: AES_KEY_LENGTH_BITS },
        true,
        ["encrypt", "decrypt"],
      );
    } catch (error) {
      throw new CryptoError(
        "Failed to generate encryption key: " + error.message,
        "KEY_GENERATION_FAILED",
      );
    }
  }

  /**
   * Generates a cryptographically secure 96-bit IV for AES-GCM.
   * @returns {Uint8Array}
   */
  function generateIV() {
    try {
      const iv = new Uint8Array(GCM_IV_LENGTH_BYTES);
      window.crypto.getRandomValues(iv);
      return iv;
    } catch (error) {
      throw new CryptoError("Failed to generate IV: " + error.message, "IV_GENERATION_FAILED");
    }
  }

  /**
   * Exports a CryptoKey to a Base64 string. Used for URL-fragment keys (the
   * sharing flow) and for persisting the derived vault key in sessionStorage -
   * auth-crypto.js re-exposes this as AuthCrypto.exportKeyToBase64.
   * @param {CryptoKey} key
   * @returns {Promise<string>}
   */
  async function exportKeyToBase64(key) {
    try {
      if (!(key instanceof CryptoKey)) {
        throw new Error("Key must be a CryptoKey instance");
      }
      const keyBuffer = await window.crypto.subtle.exportKey("raw", key);
      return bufferToBase64(new Uint8Array(keyBuffer));
    } catch (error) {
      throw new CryptoError("Failed to export key: " + error.message, "KEY_EXPORT_FAILED");
    }
  }

  /**
   * Imports a Base64-encoded AES-256 key. The imported key is not extractable -
   * an intentional security constraint. Defaults to decrypt-only, since the
   * sharing flow only ever decrypts with an imported key; auth-crypto.js imports
   * vault keys with ["encrypt", "decrypt"] via AuthCrypto.importKeyFromBase64.
   * @param {string} base64Key
   * @param {string[]} [usages=["decrypt"]]
   * @returns {Promise<CryptoKey>}
   */
  async function importKeyFromBase64(base64Key, usages = ["decrypt"]) {
    try {
      if (!base64Key || typeof base64Key !== "string") {
        throw new Error("Invalid key format: key must be a non-empty string");
      }
      const keyBytes = base64ToBuffer(base64Key);
      if (keyBytes.length !== AES_KEY_LENGTH_BYTES) {
        throw new Error(`Invalid key length: expected ${AES_KEY_LENGTH_BYTES} bytes for AES-256`);
      }
      return await window.crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM", length: AES_KEY_LENGTH_BITS },
        false, // not extractable
        usages,
      );
    } catch (error) {
      throw new CryptoError("Failed to import key: " + error.message, "KEY_IMPORT_FAILED");
    }
  }

  /**
   * Encrypts plaintext with AES-256-GCM under an existing key. A fresh IV is
   * generated per call, so encrypting several values with the same key is safe.
   *
   * This is the size-agnostic primitive: it enforces no length cap, so every
   * caller must apply its own bound (encryptPassword's MAX_PASSWORD_LENGTH,
   * the note editor's MAX_NOTE_PLAINTEXT_BYTES).
   *
   * @param {string} plaintext The text to encrypt (required, non-empty).
   * @param {CryptoKey} key The AES-256-GCM key to encrypt with.
   * @returns {Promise<{encryptedData: string, iv: string}>} Base64-encoded values.
   */
  async function encryptWithKey(plaintext, key) {
    try {
      if (!plaintext || typeof plaintext !== "string") {
        throw new Error("Invalid plaintext: must be a non-empty string");
      }
      const iv = generateIV();

      const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv, tagLength: GCM_TAG_LENGTH_BITS },
        key,
        new TextEncoder().encode(plaintext),
      );

      return {
        encryptedData: bufferToBase64(new Uint8Array(encryptedBuffer)),
        iv: bufferToBase64(iv),
      };
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      throw new CryptoError("Encryption failed: " + error.message, "ENCRYPTION_FAILED");
    }
  }

  /**
   * Encrypts plaintext with AES-256-GCM. A fresh IV is generated per call, so
   * encrypting a secret and its title with the same key is safe.
   * @param {string} password The plaintext to encrypt.
   * @param {CryptoKey} [key] Pre-generated key; a new one is created if omitted.
   * @returns {Promise<{encryptedData: string, iv: string, key: string}>} All values Base64-encoded.
   */
  async function encryptPassword(password, key = null) {
    try {
      if (!password || typeof password !== "string") {
        throw new Error("Invalid password: must be a non-empty string");
      }
      if (password.length > MAX_PASSWORD_LENGTH) {
        throw new Error(
          `Password too long: maximum ${MAX_PASSWORD_LENGTH.toLocaleString()} characters allowed`,
        );
      }

      const encryptionKey = key || (await generateEncryptionKey());
      const { encryptedData, iv } = await encryptWithKey(password, encryptionKey);

      return {
        encryptedData,
        iv,
        key: await exportKeyToBase64(encryptionKey),
      };
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      throw new CryptoError("Encryption failed: " + error.message, "ENCRYPTION_FAILED");
    }
  }

  /**
   * Encrypts a secret and an optional title under one freshly generated key.
   *
   * Both values share the same AES-256 key (so a single URL fragment key unlocks
   * both) but each gets its own IV. Reusing one IV under the same key would break
   * AES-GCM confidentiality; encryptPassword() always generates a fresh one.
   *
   * @param {string} password The plaintext secret (required).
   * @param {string} [title=""] Optional plaintext title; blank titles are skipped.
   * @returns {Promise<{key: string, password: {encryptedData: string, iv: string},
   *                    title: {encryptedData: string, iv: string}|null}>}
   */
  async function encryptShare(password, title = "") {
    const key = await generateEncryptionKey();
    const passwordPayload = await encryptPassword(password, key);

    const trimmedTitle = (title || "").trim();
    const titlePayload = trimmedTitle ? await encryptPassword(trimmedTitle, key) : null;

    return {
      key: passwordPayload.key,
      password: { encryptedData: passwordPayload.encryptedData, iv: passwordPayload.iv },
      title: titlePayload
        ? { encryptedData: titlePayload.encryptedData, iv: titlePayload.iv }
        : null,
    };
  }

  /**
   * Decrypts AES-256-GCM ciphertext. An `OperationError` from the Web Crypto API
   * means the key is wrong or the ciphertext was tampered with.
   * @param {string} encryptedData Base64-encoded ciphertext.
   * @param {string} iv Base64-encoded IV.
   * @param {string|CryptoKey} key Base64 key string or a CryptoKey object.
   * @returns {Promise<string>} Decrypted plaintext.
   */
  async function decryptPassword(encryptedData, iv, key) {
    try {
      if (!encryptedData || !iv || !key) {
        throw new Error("Invalid input: encryptedData, IV, and key are all required.");
      }

      const cryptoKey = typeof key === "string" ? await importKeyFromBase64(key) : key;
      const ivBytes = base64ToBuffer(iv);

      if (ivBytes.length !== GCM_IV_LENGTH_BYTES) {
        throw new Error(`Invalid IV length: expected ${GCM_IV_LENGTH_BYTES} bytes for AES-GCM`);
      }

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes, tagLength: GCM_TAG_LENGTH_BITS },
        cryptoKey,
        base64ToBuffer(encryptedData),
      );

      return new TextDecoder().decode(decryptedBuffer);
    } catch (error) {
      if (error instanceof CryptoError) throw error;
      if (error.name === "OperationError") {
        throw new CryptoError(
          "Authentication failed: the data may have been tampered with, or the key is incorrect.",
          "AUTHENTICATION_FAILED",
        );
      }
      throw new CryptoError("Decryption failed: " + error.message, "DECRYPTION_FAILED");
    }
  }

  // --- Utility ---

  /**
   * Returns true if the Web Crypto API is available in the current browser.
   * @returns {boolean}
   */
  function isCryptoSupported() {
    return !!(window.crypto && window.crypto.subtle && window.crypto.getRandomValues);
  }

  // encryptPassword is intentionally not exported: it is an internal primitive
  // used only by encryptShare. Callers use encryptShare (which pairs the secret
  // and title under one key) or decryptPassword.
  window.PasswordCrypto = {
    encryptShare,
    decryptPassword,
    isCryptoSupported,
    CryptoError,
  };

  // Lower-level primitives shared with auth-crypto.js and the note editor.
  // Exposed on a dedicated namespace (rather than leaked as bare globals) so
  // the cross-file contract is explicit; auth-crypto.js destructures these at
  // load time. encryptWithKey enforces no size cap - callers bring their own
  // bound (see its doc comment).
  window.CryptoCore = {
    CryptoError,
    bufferToBase64,
    base64ToBuffer,
    generateIV,
    generateEncryptionKey,
    encryptWithKey,
    exportKeyToBase64,
    importKeyFromBase64,
    AES_KEY_LENGTH_BITS,
    GCM_TAG_LENGTH_BITS,
  };

  document.addEventListener("DOMContentLoaded", function () {
    if (isCryptoSupported()) return;

    console.error("Web Crypto API is not supported in this browser.");

    const banner = document.createElement("div");
    banner.innerHTML = `
      <div style="background-color:#fff0f0;color:#c00;border:1px solid #fcc;padding:20px;margin:20px auto;border-radius:8px;max-width:800px;font-family:sans-serif;">
        <h3 style="margin-top:0;">Critical Security Feature Missing</h3>
        <p>Your browser does not support the modern cryptographic functions (Web Crypto API) required for this service to operate securely.</p>
        <p>Please update your browser or switch to a modern one like Firefox, Chrome, Safari, or Edge to proceed.</p>
      </div>
    `;
    document.body.insertBefore(banner, document.body.firstChild);

    // Hide the create-share form so it can't be submitted without crypto.
    // Other pages have no such form; getElementById returns null and is a no-op.
    const mainForm = document.getElementById("createForm");
    if (mainForm) mainForm.style.display = "none";
  });
})();
