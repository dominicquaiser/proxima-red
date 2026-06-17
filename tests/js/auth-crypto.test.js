/**
 * Tests for static/js/auth-crypto.js - the zero-knowledge vault flow
 * (window.AuthCrypto): PBKDF2 derivation, the auth-secret/vault-key domain
 * separation, account-data encryption, and the secure-session storage.
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCryptoModules, base64ByteLength, flipFirstByte, cryptoError } = require("./helpers");

const { AuthCrypto, sessionStorage } = loadCryptoModules();

// The production default is 100,000 iterations; derivation tests pass a low
// count through the public `iterations` parameter to keep the suite fast.
// What matters here is determinism and separation, not the work factor.
const FAST_ITERATIONS = 1000;

describe("generateSalt", () => {
  test("returns Base64 of 32 bytes, unique per call", () => {
    const a = AuthCrypto.generateSalt();
    const b = AuthCrypto.generateSalt();

    assert.equal(base64ByteLength(a), 32);
    assert.equal(base64ByteLength(b), 32);
    assert.notEqual(a, b);
  });
});

describe("deriveAuthSecret", () => {
  test("is deterministic for the same password and salt", async () => {
    const salt = AuthCrypto.generateSalt();
    const a = await AuthCrypto.deriveAuthSecret("correct horse", salt, FAST_ITERATIONS);
    const b = await AuthCrypto.deriveAuthSecret("correct horse", salt, FAST_ITERATIONS);

    assert.equal(a, b);
    assert.equal(base64ByteLength(a), 32);
  });

  test("changes with the password and with the salt", async () => {
    const salt = AuthCrypto.generateSalt();
    const base = await AuthCrypto.deriveAuthSecret("password-one", salt, FAST_ITERATIONS);

    assert.notEqual(await AuthCrypto.deriveAuthSecret("password-two", salt, FAST_ITERATIONS), base);
    assert.notEqual(
      await AuthCrypto.deriveAuthSecret("password-one", AuthCrypto.generateSalt(), FAST_ITERATIONS),
      base,
    );
  });

  test("rejects empty password or salt", async () => {
    await assert.rejects(
      AuthCrypto.deriveAuthSecret("", "c2FsdA=="),
      cryptoError("AUTH_SECRET_DERIVATION_FAILED"),
    );
    await assert.rejects(
      AuthCrypto.deriveAuthSecret("password", ""),
      cryptoError("AUTH_SECRET_DERIVATION_FAILED"),
    );
  });
});

describe("auth secret / vault key domain separation", () => {
  test("the same password and salt yield different auth-secret and vault-key bytes", async () => {
    // The zero-knowledge core invariant: the server receives the auth secret,
    // and that must not let it reconstruct the vault key. Both are
    // PBKDF2-SHA256 over the same password, so the separation comes entirely
    // from the context string mixed into the auth-secret salt.
    const salt = AuthCrypto.generateSalt();

    const authSecret = await AuthCrypto.deriveAuthSecret("shared-password", salt, FAST_ITERATIONS);
    const vaultKey = await AuthCrypto.deriveKeyFromPassword(
      "shared-password",
      salt,
      FAST_ITERATIONS,
      true,
    );
    const vaultKeyBase64 = await AuthCrypto.exportKeyToBase64(vaultKey);

    assert.notEqual(authSecret, vaultKeyBase64);
  });
});

describe("deriveKeyFromPassword", () => {
  test("is deterministic for the same password and salt", async () => {
    const salt = AuthCrypto.generateSalt();
    const a = await AuthCrypto.deriveKeyFromPassword("pw", salt, FAST_ITERATIONS, true);
    const b = await AuthCrypto.deriveKeyFromPassword("pw", salt, FAST_ITERATIONS, true);

    assert.equal(await AuthCrypto.exportKeyToBase64(a), await AuthCrypto.exportKeyToBase64(b));
  });

  test("is not extractable by default", async () => {
    const key = await AuthCrypto.deriveKeyFromPassword(
      "pw",
      AuthCrypto.generateSalt(),
      FAST_ITERATIONS,
    );

    assert.equal(key.extractable, false);
    await assert.rejects(AuthCrypto.exportKeyToBase64(key), cryptoError("KEY_EXPORT_FAILED"));
  });

  test("rejects empty password or salt", async () => {
    await assert.rejects(
      AuthCrypto.deriveKeyFromPassword("", "c2FsdA=="),
      cryptoError("KEY_DERIVATION_FAILED"),
    );
    await assert.rejects(
      AuthCrypto.deriveKeyFromPassword("password", ""),
      cryptoError("KEY_DERIVATION_FAILED"),
    );
  });
});

describe("encryptAccountData / decryptAccountData", () => {
  async function vaultKey(password = "vault-password", salt = AuthCrypto.generateSalt()) {
    return AuthCrypto.deriveKeyFromPassword(password, salt, FAST_ITERATIONS);
  }

  test("round-trips an account data object", async () => {
    const key = await vaultKey();
    const data = {
      services: [{ name: "example.com", user: "alice", password: "p4ss" }],
      note: "unicode ✓ 密码",
    };

    const blob = await AuthCrypto.encryptAccountData(data, key);
    assert.equal(base64ByteLength(blob.iv), 12);
    assert.deepEqual(await AuthCrypto.decryptAccountData(blob.encryptedData, blob.iv, key), data);
  });

  test("encrypting the same object twice yields fresh IVs and ciphertexts", async () => {
    const key = await vaultKey();
    const data = { a: 1 };

    const first = await AuthCrypto.encryptAccountData(data, key);
    const second = await AuthCrypto.encryptAccountData(data, key);
    assert.notEqual(first.iv, second.iv);
    assert.notEqual(first.encryptedData, second.encryptedData);
  });

  test("wrong key fails authentication", async () => {
    const key = await vaultKey("password-one");
    const wrongKey = await vaultKey("password-two");
    const blob = await AuthCrypto.encryptAccountData({ a: 1 }, key);

    await assert.rejects(
      AuthCrypto.decryptAccountData(blob.encryptedData, blob.iv, wrongKey),
      cryptoError("AUTHENTICATION_FAILED"),
    );
  });

  test("tampered ciphertext fails authentication", async () => {
    const key = await vaultKey();
    const blob = await AuthCrypto.encryptAccountData({ a: 1 }, key);

    await assert.rejects(
      AuthCrypto.decryptAccountData(flipFirstByte(blob.encryptedData), blob.iv, key),
      cryptoError("AUTHENTICATION_FAILED"),
    );
  });

  test("rejects non-object input on encrypt and missing input on decrypt", async () => {
    const key = await vaultKey();

    await assert.rejects(
      AuthCrypto.encryptAccountData("not-an-object", key),
      cryptoError("ACCOUNT_ENCRYPTION_FAILED"),
    );
    await assert.rejects(
      AuthCrypto.encryptAccountData(null, key),
      cryptoError("ACCOUNT_ENCRYPTION_FAILED"),
    );
    await assert.rejects(
      AuthCrypto.decryptAccountData("", "aXY=", key),
      cryptoError("ACCOUNT_DECRYPTION_FAILED"),
    );
    await assert.rejects(
      AuthCrypto.decryptAccountData("ZGF0YQ==", "", key),
      cryptoError("ACCOUNT_DECRYPTION_FAILED"),
    );
  });
});

describe("password-change vault migration (account.js flow)", () => {
  test("vault decrypted with the old key re-encrypts under the new key intact", async () => {
    const data = { services: [{ name: "svc", password: "secret" }] };

    const oldKey = await AuthCrypto.deriveKeyFromPassword(
      "old-password",
      AuthCrypto.generateSalt(),
      FAST_ITERATIONS,
    );
    const oldBlob = await AuthCrypto.encryptAccountData(data, oldKey);

    // The migration step: read with the old key, re-encrypt with the new one.
    const decrypted = await AuthCrypto.decryptAccountData(
      oldBlob.encryptedData,
      oldBlob.iv,
      oldKey,
    );
    const newKey = await AuthCrypto.deriveKeyFromPassword(
      "new-password",
      AuthCrypto.generateSalt(),
      FAST_ITERATIONS,
    );
    const newBlob = await AuthCrypto.encryptAccountData(decrypted, newKey);

    assert.deepEqual(
      await AuthCrypto.decryptAccountData(newBlob.encryptedData, newBlob.iv, newKey),
      data,
    );
    // The old key must no longer open the migrated blob.
    await assert.rejects(
      AuthCrypto.decryptAccountData(newBlob.encryptedData, newBlob.iv, oldKey),
      cryptoError("AUTHENTICATION_FAILED"),
    );
  });
});

describe("validatePassword", () => {
  test("accepts an 8+ character password", () => {
    assert.deepEqual(AuthCrypto.validatePassword("12345678"), {
      isValid: true,
      messages: [],
    });
  });

  test("rejects short, overlong, empty, and non-string passwords", () => {
    assert.equal(AuthCrypto.validatePassword("1234567").isValid, false);
    assert.equal(AuthCrypto.validatePassword("x".repeat(257)).isValid, false);
    assert.equal(AuthCrypto.validatePassword("x".repeat(256)).isValid, true);
    assert.equal(AuthCrypto.validatePassword("").isValid, false);
    assert.equal(AuthCrypto.validatePassword(null).isValid, false);
    assert.equal(AuthCrypto.validatePassword(12345678).isValid, false);
  });
});

describe("secure session storage", () => {
  test("establishSecureSession stores a vault key that decrypts session data", async () => {
    // Uses the production iteration count internally - slower, but it tests
    // the real signin path end to end.
    const salt = AuthCrypto.generateSalt();
    await AuthCrypto.establishSecureSession("session-password", salt);

    const stored = sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey);
    assert.ok(stored, "master key should be in sessionStorage");
    assert.equal(base64ByteLength(stored), 32);

    // The restored key must both encrypt and decrypt (vault-key usages).
    const restored = await AuthCrypto.importKeyFromBase64(stored);
    assert.deepEqual([...restored.usages].sort(), ["decrypt", "encrypt"]);
    const blob = await AuthCrypto.encryptAccountData({ a: 1 }, restored);
    assert.deepEqual(await AuthCrypto.decryptAccountData(blob.encryptedData, blob.iv, restored), {
      a: 1,
    });
  });

  test("establishSecureSession requires a salt", async () => {
    await assert.rejects(
      AuthCrypto.establishSecureSession("password", ""),
      cryptoError("MISSING_SALT"),
    );
  });

  test("clearSecureSession removes the stored key", async () => {
    sessionStorage.setItem(AuthCrypto.STORAGE_KEYS.masterKey, "sentinel");
    AuthCrypto.clearSecureSession();

    assert.equal(sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey), null);
  });
});
