/**
 * Tests for static/shared/js/crypto.js - the anonymous sharing flow
 * (window.PasswordCrypto) and the shared primitives (window.CryptoCore).
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const { loadCryptoModules, base64ByteLength, flipFirstByte, cryptoError } = require("./helpers");

const { PasswordCrypto, CryptoCore } = loadCryptoModules();

describe("encryptShare / decryptPassword round trip", () => {
  test("secret without title decrypts back to the plaintext", async () => {
    const share = await PasswordCrypto.encryptShare("hunter2-secret");

    assert.equal(share.title, null);
    const plaintext = await PasswordCrypto.decryptPassword(
      share.password.encryptedData,
      share.password.iv,
      share.key,
    );
    assert.equal(plaintext, "hunter2-secret");
  });

  test("secret and title decrypt under the same key", async () => {
    const share = await PasswordCrypto.encryptShare("the-secret", "Prod DB");

    const secret = await PasswordCrypto.decryptPassword(
      share.password.encryptedData,
      share.password.iv,
      share.key,
    );
    const title = await PasswordCrypto.decryptPassword(
      share.title.encryptedData,
      share.title.iv,
      share.key,
    );
    assert.equal(secret, "the-secret");
    assert.equal(title, "Prod DB");
  });

  test("unicode plaintext survives the round trip", async () => {
    const plaintext = "pässwörd-✓-密码-🔑";
    const share = await PasswordCrypto.encryptShare(plaintext);

    assert.equal(
      await PasswordCrypto.decryptPassword(
        share.password.encryptedData,
        share.password.iv,
        share.key,
      ),
      plaintext,
    );
  });

  test("decryptPassword accepts a CryptoKey object as well as a Base64 string", async () => {
    const share = await PasswordCrypto.encryptShare("object-key-secret");
    const key = await CryptoCore.importKeyFromBase64(share.key);

    assert.equal(
      await PasswordCrypto.decryptPassword(share.password.encryptedData, share.password.iv, key),
      "object-key-secret",
    );
  });
});

describe("encryptShare output format", () => {
  test("key is Base64 of 32 bytes (AES-256) and IV is 12 bytes (GCM)", async () => {
    const share = await PasswordCrypto.encryptShare("secret");

    assert.equal(base64ByteLength(share.key), 32);
    assert.equal(base64ByteLength(share.password.iv), 12);
  });

  test("blank or whitespace-only title is skipped", async () => {
    assert.equal((await PasswordCrypto.encryptShare("s", "")).title, null);
    assert.equal((await PasswordCrypto.encryptShare("s", "   ")).title, null);
  });

  test("title is trimmed before encryption", async () => {
    const share = await PasswordCrypto.encryptShare("s", "  My Title  ");

    assert.equal(
      await PasswordCrypto.decryptPassword(share.title.encryptedData, share.title.iv, share.key),
      "My Title",
    );
  });
});

describe("IV and key uniqueness invariants", () => {
  test("secret and title never share an IV (AES-GCM key+IV reuse breaks confidentiality)", async () => {
    for (let i = 0; i < 5; i++) {
      const share = await PasswordCrypto.encryptShare("secret", "title");
      assert.notEqual(share.password.iv, share.title.iv);
    }
  });

  test("every share gets a fresh key and IV", async () => {
    const a = await PasswordCrypto.encryptShare("same-plaintext");
    const b = await PasswordCrypto.encryptShare("same-plaintext");

    assert.notEqual(a.key, b.key);
    assert.notEqual(a.password.iv, b.password.iv);
    assert.notEqual(a.password.encryptedData, b.password.encryptedData);
  });
});

describe("decryptPassword failure modes", () => {
  test("wrong key fails authentication", async () => {
    const share = await PasswordCrypto.encryptShare("secret");
    const other = await PasswordCrypto.encryptShare("other");

    await assert.rejects(
      PasswordCrypto.decryptPassword(share.password.encryptedData, share.password.iv, other.key),
      cryptoError("AUTHENTICATION_FAILED"),
    );
  });

  test("tampered ciphertext fails authentication", async () => {
    const share = await PasswordCrypto.encryptShare("secret");

    await assert.rejects(
      PasswordCrypto.decryptPassword(
        flipFirstByte(share.password.encryptedData),
        share.password.iv,
        share.key,
      ),
      cryptoError("AUTHENTICATION_FAILED"),
    );
  });

  test("tampered IV fails authentication", async () => {
    const share = await PasswordCrypto.encryptShare("secret");

    await assert.rejects(
      PasswordCrypto.decryptPassword(
        share.password.encryptedData,
        flipFirstByte(share.password.iv),
        share.key,
      ),
      cryptoError("AUTHENTICATION_FAILED"),
    );
  });

  test("missing arguments are rejected", async () => {
    const share = await PasswordCrypto.encryptShare("secret");

    await assert.rejects(
      PasswordCrypto.decryptPassword("", share.password.iv, share.key),
      cryptoError("DECRYPTION_FAILED"),
    );
    await assert.rejects(
      PasswordCrypto.decryptPassword(share.password.encryptedData, "", share.key),
      cryptoError("DECRYPTION_FAILED"),
    );
    await assert.rejects(
      PasswordCrypto.decryptPassword(share.password.encryptedData, share.password.iv, ""),
      cryptoError("DECRYPTION_FAILED"),
    );
  });

  test("IV of the wrong length is rejected before decryption", async () => {
    const share = await PasswordCrypto.encryptShare("secret");
    const shortIv = Buffer.alloc(8, 1).toString("base64");

    await assert.rejects(
      PasswordCrypto.decryptPassword(share.password.encryptedData, shortIv, share.key),
      cryptoError("DECRYPTION_FAILED"),
    );
  });
});

describe("encryptShare input validation", () => {
  test("empty password is rejected", async () => {
    await assert.rejects(PasswordCrypto.encryptShare(""), cryptoError("ENCRYPTION_FAILED"));
  });

  test("non-string password is rejected", async () => {
    await assert.rejects(PasswordCrypto.encryptShare(12345), cryptoError("ENCRYPTION_FAILED"));
  });

  test("password over the 10000-character cap is rejected", async () => {
    await assert.rejects(
      PasswordCrypto.encryptShare("x".repeat(10001)),
      cryptoError("ENCRYPTION_FAILED"),
    );
    // The boundary itself is allowed.
    const share = await PasswordCrypto.encryptShare("x".repeat(10000));
    assert.ok(share.password.encryptedData);
  });
});

describe("CryptoCore key import/export", () => {
  test("imported keys are decrypt-only and not extractable (sharing-flow default)", async () => {
    const share = await PasswordCrypto.encryptShare("secret");
    const key = await CryptoCore.importKeyFromBase64(share.key);

    assert.deepEqual(key.usages, ["decrypt"]);
    assert.equal(key.extractable, false);
    await assert.rejects(CryptoCore.exportKeyToBase64(key), cryptoError("KEY_EXPORT_FAILED"));
  });

  test("key of the wrong byte length is rejected", async () => {
    const shortKey = Buffer.alloc(16, 1).toString("base64");

    await assert.rejects(
      CryptoCore.importKeyFromBase64(shortKey),
      cryptoError("KEY_IMPORT_FAILED"),
    );
  });

  test("empty or non-string key is rejected", async () => {
    await assert.rejects(CryptoCore.importKeyFromBase64(""), cryptoError("KEY_IMPORT_FAILED"));
    await assert.rejects(CryptoCore.importKeyFromBase64(null), cryptoError("KEY_IMPORT_FAILED"));
  });

  test("exportKeyToBase64 rejects non-CryptoKey values", async () => {
    await assert.rejects(
      CryptoCore.exportKeyToBase64("not-a-key"),
      cryptoError("KEY_EXPORT_FAILED"),
    );
  });
});

describe("encryptWithKey (size-agnostic primitive for the note tool)", () => {
  test("round-trips under a generated key", async () => {
    const key = await CryptoCore.generateEncryptionKey();
    const payload = await CryptoCore.encryptWithKey("# markdown note", key);
    const exported = await CryptoCore.exportKeyToBase64(key);

    assert.equal(
      await PasswordCrypto.decryptPassword(payload.encryptedData, payload.iv, exported),
      "# markdown note",
    );
  });

  test("accepts plaintext beyond encryptPassword's cap (callers bring their own bound)", async () => {
    const large = "A".repeat(120000); // > MAX_PASSWORD_LENGTH (10,000)
    const key = await CryptoCore.generateEncryptionKey();
    const payload = await CryptoCore.encryptWithKey(large, key);
    const exported = await CryptoCore.exportKeyToBase64(key);

    assert.equal(
      await PasswordCrypto.decryptPassword(payload.encryptedData, payload.iv, exported),
      large,
    );
  });

  test("uses a fresh 12-byte IV per call", async () => {
    const key = await CryptoCore.generateEncryptionKey();
    const first = await CryptoCore.encryptWithKey("same text", key);
    const second = await CryptoCore.encryptWithKey("same text", key);

    assert.equal(base64ByteLength(first.iv), 12);
    assert.notEqual(first.iv, second.iv);
  });

  test("rejects empty plaintext", async () => {
    const key = await CryptoCore.generateEncryptionKey();
    await assert.rejects(CryptoCore.encryptWithKey("", key), cryptoError("ENCRYPTION_FAILED"));
  });
});

describe("isCryptoSupported", () => {
  test("reports true when WebCrypto is available", () => {
    assert.equal(PasswordCrypto.isCryptoSupported(), true);
  });
});
