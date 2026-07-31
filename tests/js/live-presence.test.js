/**
 * Tests for the pure helpers of static/note/js/live-presence.js
 * (window.NoteLivePresence): identity assignment, cursor encode/resolve as
 * relative positions, and the awareness-state round trip through the
 * encrypted relay. The DOM rendering (mirror measurement, overlay) is
 * exercised in the browser.
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const { loadCryptoModules } = require("./helpers");

const { CryptoCore } = loadCryptoModules();

const staticJs = (...parts) => path.join(__dirname, "..", "..", "static", "note", "js", ...parts);
vm.runInThisContext(fs.readFileSync(staticJs("vendor", "yjs.min.js"), "utf8"), {
  filename: "yjs.min.js",
});
vm.runInThisContext(fs.readFileSync(staticJs("live-presence.js"), "utf8"), {
  filename: "live-presence.js",
});

const Presence = window.NoteLivePresence;
const Y = window.Y;

describe("identityFor", () => {
  test("is deterministic and in range", () => {
    for (const id of [0, 1, 42, 0xdeadbeef, 4294967295]) {
      const first = Presence.identityFor(id);
      const second = Presence.identityFor(id);
      assert.deepEqual(first, second);
      assert.ok(Presence.GREEK_NAMES.includes(first.name));
      assert.ok(first.colorIndex >= 0 && first.colorIndex < Presence.PALETTE_SIZE);
    }
  });

  test("name and colour hashes are independent (not always co-varying)", () => {
    // Find two ids with the same name but different colours — if name and
    // colour were derived from one hash, same name would force same colour.
    const byName = new Map();
    let found = false;
    for (let id = 1; id < 4000 && !found; id++) {
      const identity = Presence.identityFor(id);
      const seen = byName.get(identity.name);
      if (seen !== undefined && seen !== identity.colorIndex) found = true;
      if (seen === undefined) byName.set(identity.name, identity.colorIndex);
    }
    assert.ok(found);
  });

  test("spreads across the palette", () => {
    const seen = new Set();
    for (let id = 1; id < 500; id++) seen.add(Presence.identityFor(id).colorIndex);
    assert.equal(seen.size, Presence.PALETTE_SIZE);
  });
});

describe("cursor encode/resolve", () => {
  test("round-trips offsets through base64 relative positions", () => {
    const doc = new Y.Doc();
    const ytext = doc.getText("content");
    ytext.insert(0, "hello world");

    const cursor = Presence.encodeCursorState(ytext, 2, 7);
    assert.equal(typeof cursor.anchor, "string");
    assert.equal(typeof cursor.head, "string");
    // JSON-safe: the awareness protocol serializes states as JSON.
    assert.deepEqual(JSON.parse(JSON.stringify(cursor)), cursor);

    const resolved = Presence.resolveCursorState(doc, ytext, cursor);
    assert.deepEqual(resolved, { anchor: 2, head: 7 });
  });

  test("survives a concurrent remote insert before the cursor", () => {
    const doc = new Y.Doc();
    const ytext = doc.getText("content");
    ytext.insert(0, "hello world");
    const cursor = Presence.encodeCursorState(ytext, 6, 11); // "world"

    const other = new Y.Doc();
    Y.applyUpdate(other, Y.encodeStateAsUpdate(doc));
    other.getText("content").insert(0, ">>> ");
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(other), "remote");

    const resolved = Presence.resolveCursorState(doc, ytext, cursor);
    assert.deepEqual(resolved, { anchor: 10, head: 15 });
    assert.equal(ytext.toString().slice(resolved.anchor, resolved.head), "world");
  });

  test("returns null for absent or garbage cursors", () => {
    const doc = new Y.Doc();
    const ytext = doc.getText("content");
    assert.equal(Presence.resolveCursorState(doc, ytext, null), null);
    assert.equal(Presence.resolveCursorState(doc, ytext, {}), null);
    assert.equal(
      Presence.resolveCursorState(doc, ytext, { anchor: "!!!", head: "!!!" }),
      null,
    );
  });
});

describe("awareness round trip with presence-shaped state", () => {
  test("cursor + identity survive encode -> encrypt -> decrypt -> apply", async () => {
    const key = await CryptoCore.generateEncryptionKey();

    const docA = new Y.Doc();
    const ytextA = docA.getText("content");
    ytextA.insert(0, "shared text");
    const docB = new Y.Doc();
    Y.applyUpdate(docB, Y.encodeStateAsUpdate(docA));
    const ytextB = docB.getText("content");

    const awarenessA = new Y.awareness.Awareness(docA);
    const awarenessB = new Y.awareness.Awareness(docB);
    try {
      const identity = Presence.identityFor(docA.clientID);
      awarenessA.setLocalState({
        user: { name: identity.name, color: identity.colorIndex },
        cursor: Presence.encodeCursorState(ytextA, 0, 6),
      });

      const update = Y.awareness.encodeAwarenessUpdate(awarenessA, [docA.clientID]);
      const payload = await CryptoCore.encryptBytesWithKey(update, key);
      const bytes = await CryptoCore.decryptBytes(payload.encryptedData, payload.iv, key);
      Y.awareness.applyAwarenessUpdate(awarenessB, bytes, "remote");

      const state = awarenessB.getStates().get(docA.clientID);
      assert.equal(state.user.name, identity.name);
      // B resolves A's cursor against its own replica of the doc.
      const resolved = Presence.resolveCursorState(docB, ytextB, state.cursor);
      assert.deepEqual(resolved, { anchor: 0, head: 6 });
    } finally {
      awarenessA.destroy();
      awarenessB.destroy();
    }
  });
});
