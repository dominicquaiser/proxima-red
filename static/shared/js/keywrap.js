/**
 * @fileoverview Asymmetric key wrapping for named collaborators
 * (window.KeyWrap): each account holds an ECDH P-256 keypair, and a live
 * document's AES key is "wrapped" to a collaborator by encrypting it under a
 * key agreed between a fresh ephemeral keypair and the collaborator's public
 * key (static-ephemeral ECDH -> HKDF-SHA256 -> AES-256-GCM; ECIES-style).
 *
 * Zero-knowledge split: everything here runs client-side. The server stores
 * the public key, the vault-key-encrypted private key blob, and wrapped doc
 * keys — none of which it can use: unwrapping needs the private key, which
 * only exists in plaintext inside a browser that holds the vault key.
 *
 * Honest limitation (stated in the privacy policy): public keys are
 * distributed by the server, so a malicious server could substitute its own
 * — the classic key-distribution trust gap. Out-of-band fingerprint
 * verification is future work.
 *
 * Scheme notes:
 * - P-256 over RSA-OAEP: same evergreen WebCrypto support, ~90-byte public
 *   keys and ~140-byte private blobs instead of kilobytes, instant keygen.
 * - The HKDF info binds the derived wrap key to both the protocol context
 *   and the ephemeral public key, so a wrap can't be replayed under a
 *   different ephemeral key.
 * - Private keys are imported non-extractable with deriveBits-only usage;
 *   the exportable form exists only inside the vault-key-encrypted blob.
 *
 * Load order (all deferred): shared/js/crypto.js (CryptoCore), then this
 * file, then page controllers (auth signup/account, note live-collab).
 */
(function () {
  "use strict";

  const EC_PARAMS = { name: "ECDH", namedCurve: "P-256" };
  const HKDF_CONTEXT = "proxima.red/live-wrap/v1";

  const CryptoError = window.CryptoCore.CryptoError;

  function toBytes(bufferOrView) {
    return bufferOrView instanceof Uint8Array ? bufferOrView : new Uint8Array(bufferOrView);
  }

  /**
   * Generate a fresh account keypair.
   *
   * @returns {Promise<{privateKey: CryptoKey, publicKeyBase64: string}>} The
   *   private key (extractable, so it can be exported into the encrypted
   *   blob once) and the SPKI public key ready for upload.
   */
  async function generateKeyPair() {
    try {
      const pair = await crypto.subtle.generateKey(EC_PARAMS, true, ["deriveBits"]);
      const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
      // NB: bufferToBase64 needs a byte VIEW; a bare ArrayBuffer silently
      // encodes to "" (same for every call below).
      return {
        privateKey: pair.privateKey,
        publicKeyBase64: window.CryptoCore.bufferToBase64(toBytes(spki)),
      };
    } catch (error) {
      throw new CryptoError("Failed to generate the collaboration keypair.", "KEYGEN_FAILED");
    }
  }

  /**
   * Export and encrypt a private key under the vault key for server storage.
   *
   * @param {CryptoKey} privateKey An extractable ECDH private key.
   * @param {CryptoKey} vaultKey The account's AES-256-GCM vault key.
   * @returns {Promise<{encryptedPrivateKey: string, iv: string}>} Base64
   *   ciphertext + IV, the account's private-key blob.
   */
  async function encryptPrivateKeyBlob(privateKey, vaultKey) {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
    const payload = await window.CryptoCore.encryptBytesWithKey(toBytes(pkcs8), vaultKey);
    return { encryptedPrivateKey: payload.encryptedData, iv: payload.iv };
  }

  /**
   * Decrypt the private-key blob and import it for unwrapping.
   *
   * @param {string} encryptedPrivateKey Base64 ciphertext of the PKCS8 key.
   * @param {string} iv Base64 IV.
   * @param {CryptoKey} vaultKey The account's AES-256-GCM vault key.
   * @returns {Promise<CryptoKey>} The private key, non-extractable,
   *   deriveBits-only.
   */
  async function decryptPrivateKeyBlob(encryptedPrivateKey, iv, vaultKey) {
    const pkcs8 = await window.CryptoCore.decryptBytes(encryptedPrivateKey, iv, vaultKey);
    try {
      return await crypto.subtle.importKey("pkcs8", pkcs8, EC_PARAMS, false, ["deriveBits"]);
    } catch (error) {
      throw new CryptoError("The stored private key is not valid.", "KEY_IMPORT_FAILED");
    }
  }

  /**
   * Derive the AES-GCM wrap key from an ECDH agreement.
   *
   * @param {CryptoKey} privateKey Our side's ECDH private key.
   * @param {CryptoKey} publicKey The other side's ECDH public key.
   * @param {ArrayBuffer|Uint8Array} ephemeralSpki The ephemeral public key
   *   bytes bound into the HKDF info.
   * @returns {Promise<CryptoKey>} A non-extractable AES-256-GCM key.
   */
  async function deriveWrapKey(privateKey, publicKey, ephemeralSpki) {
    const shared = await crypto.subtle.deriveBits(
      { name: "ECDH", public: publicKey },
      privateKey,
      256,
    );
    const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    const context = new TextEncoder().encode(HKDF_CONTEXT);
    const spkiBytes = toBytes(ephemeralSpki);
    const info = new Uint8Array(context.length + spkiBytes.length);
    info.set(context, 0);
    info.set(spkiBytes, context.length);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: info },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async function importPublicKey(publicKeyBase64) {
    try {
      return await crypto.subtle.importKey(
        "spki",
        window.CryptoCore.base64ToBuffer(publicKeyBase64),
        EC_PARAMS,
        false,
        [],
      );
    } catch (error) {
      throw new CryptoError("The public key is not valid.", "KEY_IMPORT_FAILED");
    }
  }

  /**
   * Wrap a document key to a collaborator's public key.
   *
   * Takes the raw key BYTES (not a CryptoKey) so it never needs the key to be
   * extractable: live-note document keys are imported non-extractable (like
   * share keys), and the caller already holds their Base64 form. Decode with
   * ``CryptoCore.base64ToBuffer`` at the call site.
   *
   * @param {Uint8Array} rawDocKey The document AES-256 key's 32 bytes.
   * @param {string} recipientPublicKeyBase64 The collaborator's SPKI key.
   * @returns {Promise<{wrappedKey: string, wrapIv: string,
   *   ephemeralPublicKey: string}>} The wrap triple stored server-side.
   */
  async function wrapDocKey(rawDocKey, recipientPublicKeyBase64) {
    const recipientKey = await importPublicKey(recipientPublicKeyBase64);
    const ephemeral = await crypto.subtle.generateKey(EC_PARAMS, true, ["deriveBits"]);
    const ephemeralSpki = await crypto.subtle.exportKey("spki", ephemeral.publicKey);
    const wrapKey = await deriveWrapKey(ephemeral.privateKey, recipientKey, ephemeralSpki);
    const payload = await window.CryptoCore.encryptBytesWithKey(toBytes(rawDocKey), wrapKey);
    return {
      wrappedKey: payload.encryptedData,
      wrapIv: payload.iv,
      ephemeralPublicKey: window.CryptoCore.bufferToBase64(toBytes(ephemeralSpki)),
    };
  }

  /**
   * Unwrap a document key with the account's private key.
   *
   * @param {{wrappedKey: string, wrapIv: string, ephemeralPublicKey: string}}
   *   wrap The stored wrap triple.
   * @param {CryptoKey} privateKey The account's ECDH private key.
   * @returns {Promise<{key: CryptoKey, keyBase64: string}>} The document key
   *   (encrypt + decrypt) and its Base64 form (for the per-tab key stash —
   *   the same shape a fragment key has).
   */
  async function unwrapDocKey(wrap, privateKey) {
    const ephemeralKey = await importPublicKey(wrap.ephemeralPublicKey);
    const ephemeralSpki = window.CryptoCore.base64ToBuffer(wrap.ephemeralPublicKey);
    const wrapKey = await deriveWrapKey(privateKey, ephemeralKey, ephemeralSpki);
    const rawDocKey = await window.CryptoCore.decryptBytes(wrap.wrappedKey, wrap.wrapIv, wrapKey);
    const keyBase64 = window.CryptoCore.bufferToBase64(toBytes(rawDocKey));
    const key = await window.CryptoCore.importKeyFromBase64(keyBase64, ["encrypt", "decrypt"]);
    return { key: key, keyBase64: keyBase64 };
  }

  window.KeyWrap = {
    generateKeyPair,
    encryptPrivateKeyBlob,
    decryptPrivateKeyBlob,
    wrapDocKey,
    unwrapDocKey,
    HKDF_CONTEXT,
  };
})();
