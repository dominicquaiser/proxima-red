/**
 * Test loader for the browser crypto scripts.
 *
 * static/js/crypto.js and static/js/auth-crypto.js are IIFEs written for the
 * browser: they read window.crypto, register a DOMContentLoaded listener, and
 * (at call time) touch sessionStorage. Node 20+ ships the same WebCrypto API,
 * btoa/atob, and TextEncoder/TextDecoder, so the real scripts can run
 * unmodified. This module just provides window/document/sessionStorage
 * stand-ins and evaluates the files in their required order.
 */

"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const STATIC_JS_DIR = path.join(__dirname, "..", "..", "static", "js");

function createSessionStorageStub() {
  const store = new Map();
  return {
    getItem: (key) => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => store.set(key, String(value)),
    removeItem: (key) => store.delete(key),
    clear: () => store.clear(),
    get length() {
      return store.size;
    },
  };
}

function loadCryptoModules() {
  global.window = globalThis;
  global.document = { addEventListener: () => {} };
  global.sessionStorage = createSessionStorageStub();

  for (const file of ["crypto.js", "auth-crypto.js"]) {
    const source = fs.readFileSync(path.join(STATIC_JS_DIR, file), "utf8");
    vm.runInThisContext(source, { filename: file });
  }

  return {
    PasswordCrypto: window.PasswordCrypto,
    CryptoCore: window.CryptoCore,
    AuthCrypto: window.AuthCrypto,
    sessionStorage: global.sessionStorage,
  };
}

/** Decoded byte length of a Base64 string. */
function base64ByteLength(base64) {
  return Buffer.from(base64, "base64").length;
}

/** Re-encode a Base64 payload with one byte flipped, for tamper tests. */
function flipFirstByte(base64) {
  const bytes = Buffer.from(base64, "base64");
  bytes[0] ^= 0xff;
  return bytes.toString("base64");
}

/** assert.rejects() matcher for a CryptoError with the given code. */
function cryptoError(code) {
  return (error) => error.name === "CryptoError" && error.code === code;
}

module.exports = {
  loadCryptoModules,
  base64ByteLength,
  flipFirstByte,
  cryptoError,
};
