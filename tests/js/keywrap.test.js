/**
 * Tests for static/shared/js/keywrap.js (window.KeyWrap) — the ECDH P-256 +
 * HKDF-SHA256 + AES-256-GCM key wrapping behind named collaborators. Runs
 * against Node's built-in WebCrypto, like the other crypto suites.
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const { loadCryptoModules, base64ByteLength, flipFirstByte } = require("./helpers");

const { CryptoCore } = loadCryptoModules();

vm.runInThisContext(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "static", "shared", "js", "keywrap.js"),
    "utf8",
  ),
  { filename: "keywrap.js" },
);

const KeyWrap = window.KeyWrap;

// wrapDocKey takes the raw 32-byte key material (not a CryptoKey), so it never
// needs the key to be extractable — mirroring the live page, which holds the
// document key's Base64 form.
function randomDocKeyBytes() {
  return crypto.getRandomValues(new Uint8Array(32));
}

describe("generateKeyPair", () => {
  test("produces a compact SPKI public key and a usable private key", async () => {
    const pair = await KeyWrap.generateKeyPair();
    assert.equal(typeof pair.publicKeyBase64, "string");
    // P-256 SPKI is 91 bytes — the whole point of choosing EC over RSA.
    assert.equal(base64ByteLength(pair.publicKeyBase64), 91);
    assert.equal(pair.privateKey.type, "private");
  });
});

describe("wrapDocKey / unwrapDocKey", () => {
  test("round trip yields the same document key", async () => {
    const recipient = await KeyWrap.generateKeyPair();
    const docKey = await CryptoCore.generateEncryptionKey();
    const docKeyBase64 = await CryptoCore.exportKeyToBase64(docKey);
    const docKeyBytes = new Uint8Array(CryptoCore.base64ToBuffer(docKeyBase64));

    const wrap = await KeyWrap.wrapDocKey(docKeyBytes, recipient.publicKeyBase64);
    const unwrapped = await KeyWrap.unwrapDocKey(wrap, recipient.privateKey);

    assert.equal(unwrapped.keyBase64, docKeyBase64);

    // The unwrapped CryptoKey actually decrypts content encrypted under the
    // original key.
    const secret = new TextEncoder().encode("collaborator payload ✓");
    const sealed = await CryptoCore.encryptBytesWithKey(secret, docKey);
    const opened = await CryptoCore.decryptBytes(sealed.encryptedData, sealed.iv, unwrapped.key);
    assert.equal(new TextDecoder().decode(opened), "collaborator payload ✓");
  });

  test("wrap artifacts stay far under the server-side field caps", async () => {
    const recipient = await KeyWrap.generateKeyPair();
    const wrap = await KeyWrap.wrapDocKey(randomDocKeyBytes(), recipient.publicKeyBase64);

    assert.equal(base64ByteLength(wrap.ephemeralPublicKey), 91);
    assert.equal(base64ByteLength(wrap.wrappedKey), 32 + 16); // key + GCM tag
    assert.equal(base64ByteLength(wrap.wrapIv), 12);
  });

  test("each wrap uses a fresh ephemeral key (no deterministic output)", async () => {
    const recipient = await KeyWrap.generateKeyPair();
    const docKey = randomDocKeyBytes();
    const first = await KeyWrap.wrapDocKey(docKey, recipient.publicKeyBase64);
    const second = await KeyWrap.wrapDocKey(docKey, recipient.publicKeyBase64);
    assert.notEqual(first.ephemeralPublicKey, second.ephemeralPublicKey);
    assert.notEqual(first.wrappedKey, second.wrappedKey);
  });

  test("a tampered wrap or the wrong private key fails closed", async () => {
    const recipient = await KeyWrap.generateKeyPair();
    const intruder = await KeyWrap.generateKeyPair();
    const docKey = randomDocKeyBytes();
    const wrap = await KeyWrap.wrapDocKey(docKey, recipient.publicKeyBase64);

    await assert.rejects(
      KeyWrap.unwrapDocKey({ ...wrap, wrappedKey: flipFirstByte(wrap.wrappedKey) },
        recipient.privateKey),
    );
    await assert.rejects(KeyWrap.unwrapDocKey(wrap, intruder.privateKey));
    // Swapping the ephemeral key breaks the HKDF binding even before GCM.
    const other = await KeyWrap.wrapDocKey(docKey, recipient.publicKeyBase64);
    await assert.rejects(
      KeyWrap.unwrapDocKey({ ...wrap, ephemeralPublicKey: other.ephemeralPublicKey },
        recipient.privateKey),
    );
  });

  test("rejects a garbage recipient public key", async () => {
    await assert.rejects(
      KeyWrap.wrapDocKey(randomDocKeyBytes(), "bm90IGEga2V5"),
      (error) => error.name === "CryptoError",
    );
  });
});

describe("private key blob", () => {
  test("round-trips through vault-key encryption and still unwraps", async () => {
    const vaultKey = await CryptoCore.generateEncryptionKey();
    const account = await KeyWrap.generateKeyPair();

    const blob = await KeyWrap.encryptPrivateKeyBlob(account.privateKey, vaultKey);
    // P-256 PKCS8 is ~138 bytes; the blob adds the 16-byte GCM tag.
    assert.ok(base64ByteLength(blob.encryptedPrivateKey) < 200);
    assert.equal(base64ByteLength(blob.iv), 12);

    const restored = await KeyWrap.decryptPrivateKeyBlob(
      blob.encryptedPrivateKey, blob.iv, vaultKey,
    );

    const docKeyBytes = randomDocKeyBytes();
    const wrap = await KeyWrap.wrapDocKey(docKeyBytes, account.publicKeyBase64);
    const unwrapped = await KeyWrap.unwrapDocKey(wrap, restored);
    assert.equal(unwrapped.keyBase64, CryptoCore.bufferToBase64(docKeyBytes));
  });

  test("the wrong vault key fails closed (password-change contract)", async () => {
    const vaultKey = await CryptoCore.generateEncryptionKey();
    const otherVaultKey = await CryptoCore.generateEncryptionKey();
    const account = await KeyWrap.generateKeyPair();
    const blob = await KeyWrap.encryptPrivateKeyBlob(account.privateKey, vaultKey);

    await assert.rejects(
      KeyWrap.decryptPrivateKeyBlob(blob.encryptedPrivateKey, blob.iv, otherVaultKey),
    );
  });
});
