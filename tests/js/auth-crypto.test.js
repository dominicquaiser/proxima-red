/**
 * Tests for static/auth/js/auth-crypto.js - the zero-knowledge vault flow
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

describe("deriveVaultKeyBase64", () => {
  test("returns the same Base64 key establishSecureSession would store", async () => {
    const salt = AuthCrypto.generateSalt();

    const exported = await AuthCrypto.deriveVaultKeyBase64("handoff-password", salt);
    assert.equal(base64ByteLength(exported), 32);

    // establishSecureSession derives the same (password, salt) key; deriving for
    // a cross-origin handoff must match what the same-origin path stores.
    AuthCrypto.clearSecureSession();
    await AuthCrypto.establishSecureSession("handoff-password", salt);
    assert.equal(sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey), exported);
  });

  test("does not store the key itself", async () => {
    AuthCrypto.clearSecureSession();
    await AuthCrypto.deriveVaultKeyBase64("handoff-password", AuthCrypto.generateSalt());
    assert.equal(sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey), null);
  });

  test("requires a salt", async () => {
    await assert.rejects(
      AuthCrypto.deriveVaultKeyBase64("password", ""),
      cryptoError("MISSING_SALT"),
    );
  });
});

describe("consumeVaultKeyFromFragment", () => {
  // The fragment handoff touches window.location/history; stub them per test.
  // `window` is globalThis in the loader, so assignment is visible to the module.
  function withFragment(hash, { existingKey = null } = {}) {
    AuthCrypto.clearSecureSession();
    if (existingKey) sessionStorage.setItem(AuthCrypto.STORAGE_KEYS.masterKey, existingKey);
    const replaceCalls = [];
    window.location = { hash, pathname: "/vault/", search: "?x=1" };
    window.history = {
      replaceState: (state, title, url) => replaceCalls.push(url),
    };
    return replaceCalls;
  }

  test("adopts a valid key from the fragment and scrubs the URL", async () => {
    const key = await AuthCrypto.deriveVaultKeyBase64("pw", AuthCrypto.generateSalt());
    // signin.js hands the key over with encodeURIComponent (base64 has +/=).
    const replaceCalls = withFragment("#" + encodeURIComponent(key));

    assert.equal(AuthCrypto.consumeVaultKeyFromFragment(), true);
    assert.equal(sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey), key);
    // The fragment (and the key) is gone from the URL; path + query are kept.
    assert.deepEqual(replaceCalls, ["/vault/?x=1"]);
  });

  test("ignores but still scrubs a malformed fragment", async () => {
    const replaceCalls = withFragment("#not-a-valid-key");

    assert.equal(AuthCrypto.consumeVaultKeyFromFragment(), false);
    assert.equal(sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey), null);
    assert.deepEqual(replaceCalls, ["/vault/?x=1"]);
  });

  test("rejects a Base64 value of the wrong length", async () => {
    // Valid Base64, but 16 bytes rather than the required 32 (AES-256).
    const shortKey = Buffer.alloc(16, 7).toString("base64");
    const replaceCalls = withFragment("#" + encodeURIComponent(shortKey));

    assert.equal(AuthCrypto.consumeVaultKeyFromFragment(), false);
    assert.equal(sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey), null);
    assert.deepEqual(replaceCalls, ["/vault/?x=1"]);
  });

  test("no-ops without a fragment (no scrub)", async () => {
    const replaceCalls = withFragment("");

    assert.equal(AuthCrypto.consumeVaultKeyFromFragment(), false);
    assert.deepEqual(replaceCalls, []);
  });

  test("does not overwrite a key already stored for this origin", async () => {
    const key = await AuthCrypto.deriveVaultKeyBase64("pw", AuthCrypto.generateSalt());
    const replaceCalls = withFragment("#" + encodeURIComponent("c2VudGluZWw="), {
      existingKey: key,
    });

    assert.equal(AuthCrypto.consumeVaultKeyFromFragment(), false);
    assert.equal(sessionStorage.getItem(AuthCrypto.STORAGE_KEYS.masterKey), key);
    assert.deepEqual(replaceCalls, []);
  });
});
