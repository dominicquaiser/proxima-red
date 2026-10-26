/**
 * Tests for static/note/js/vendor/yjs.min.js - the vendored Yjs bundle that
 * powers editable share links (live notes). Guards the exact API surface the
 * live-note client depends on (Y.Doc, getText, encodeStateAsUpdate,
 * applyUpdate, mergeUpdates, observer deltas, update events with origins,
 * Y.UndoManager, relative positions, and the bundled y-protocols awareness
 * module at Y.awareness) and proves the encrypt -> relay -> decrypt -> merge
 * round trip using the binary primitives from crypto.js.
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

const source = fs.readFileSync(
  path.join(__dirname, "..", "..", "static", "note", "js", "vendor", "yjs.min.js"),
  "utf8",
);
vm.runInThisContext(source, { filename: "yjs.min.js" });

const Y = window.Y;

describe("vendored Yjs bundle", () => {
  test("exposes the API surface the live-note client uses", () => {
    assert.equal(typeof Y.Doc, "function");
    assert.equal(typeof Y.encodeStateAsUpdate, "function");
    assert.equal(typeof Y.applyUpdate, "function");
    assert.equal(typeof Y.mergeUpdates, "function");
    // Undo across remote edits (live.js).
    assert.equal(typeof Y.UndoManager, "function");
    // Cursor anchoring that survives concurrent edits (live-presence).
    assert.equal(typeof Y.createRelativePositionFromTypeIndex, "function");
    assert.equal(typeof Y.createAbsolutePositionFromRelativePosition, "function");
    assert.equal(typeof Y.encodeRelativePosition, "function");
    assert.equal(typeof Y.decodeRelativePosition, "function");
    // y-protocols awareness, bundled as Y.awareness (presence protocol).
    assert.equal(typeof Y.awareness.Awareness, "function");
    assert.equal(typeof Y.awareness.encodeAwarenessUpdate, "function");
    assert.equal(typeof Y.awareness.applyAwarenessUpdate, "function");
    assert.equal(typeof Y.awareness.removeAwarenessStates, "function");
    assert.equal(typeof Y.awareness.outdatedTimeout, "number");
  });

  test("two docs with divergent edits converge after exchanging updates", () => {
    const docA = new Y.Doc();
    const docB = new Y.Doc();
    docA.getText("content").insert(0, "alpha ");
    docB.getText("content").insert(0, "beta");

    Y.applyUpdate(docA, Y.encodeStateAsUpdate(docB));
    Y.applyUpdate(docB, Y.encodeStateAsUpdate(docA));

    const a = docA.getText("content").toString();
    const b = docB.getText("content").toString();
    assert.equal(a, b);
    assert.ok(a.includes("alpha "));
    assert.ok(a.includes("beta"));
  });

  test("applying the same update twice is idempotent (own-echo safety)", () => {
    const source = new Y.Doc();
    source.getText("content").insert(0, "once");
    const update = Y.encodeStateAsUpdate(source);

    const target = new Y.Doc();
    Y.applyUpdate(target, update);
    Y.applyUpdate(target, update);

    assert.equal(target.getText("content").toString(), "once");
  });

  test("incremental updates carry origins and merge into one blob", () => {
    const doc = new Y.Doc();
    const outbox = [];
    doc.on("update", (update, origin) => {
      if (origin !== "remote") outbox.push(update);
    });

    doc.transact(() => doc.getText("content").insert(0, "hello"), "local");
    doc.transact(() => doc.getText("content").insert(5, " world"), "local");
    // A remote apply must not be queued again (the echo firewall).
    const other = new Y.Doc();
    other.getText("content").insert(0, "X");
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(other), "remote");

    assert.equal(outbox.length, 2);
    const merged = Y.mergeUpdates(outbox);

    const fresh = new Y.Doc();
    Y.applyUpdate(fresh, merged);
    assert.equal(fresh.getText("content").toString(), "hello world");
  });

  test("snapshot plus later tail updates reconstruct the document (resync path)", () => {
    const writer = new Y.Doc();
    writer.getText("content").insert(0, "snapshot state. ");
    const snapshot = Y.encodeStateAsUpdate(writer);

    const tail = [];
    writer.on("update", (update) => tail.push(update));
    writer.getText("content").insert(16, "tail edit one. ");
    writer.getText("content").insert(31, "tail edit two.");

    const late = new Y.Doc();
    Y.applyUpdate(late, snapshot);
    tail.forEach((update) => Y.applyUpdate(late, update));

    assert.equal(late.getText("content").toString(), writer.getText("content").toString());
  });

  test("text observer reports remote-origin deltas", () => {
    const doc = new Y.Doc();
    doc.getText("content").insert(0, "abc");

    const deltas = [];
    doc.getText("content").observe((event) => {
      if (event.transaction.origin === "remote") deltas.push(event.delta);
    });

    const other = new Y.Doc();
    Y.applyUpdate(other, Y.encodeStateAsUpdate(doc));
    other.getText("content").insert(3, "!");
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(other), "remote");

    assert.equal(deltas.length, 1);
    assert.equal(doc.getText("content").toString(), "abc!");
  });

  test("updates survive the encrypt -> base64 -> decrypt relay round trip", async () => {
    const key = await CryptoCore.generateEncryptionKey();

    const writer = new Y.Doc();
    writer.getText("content").insert(0, "zero-knowledge relay ✓");
    const update = Y.encodeStateAsUpdate(writer);

    // What the server stores: opaque ciphertext + IV, never the update.
    const payload = await CryptoCore.encryptBytesWithKey(update, key);
    const decrypted = await CryptoCore.decryptBytes(payload.encryptedData, payload.iv, key);

    const reader = new Y.Doc();
    Y.applyUpdate(reader, decrypted);
    assert.equal(reader.getText("content").toString(), "zero-knowledge relay ✓");
  });

  test("UndoManager undoes only tracked-origin edits across interleaved remote updates", () => {
    const doc = new Y.Doc();
    const ytext = doc.getText("content");
    const undoManager = new Y.UndoManager(ytext, { trackedOrigins: new Set(["local"]) });

    doc.transact(() => ytext.insert(0, "mine "), "local");

    // A remote edit lands after the local one.
    const other = new Y.Doc();
    Y.applyUpdate(other, Y.encodeStateAsUpdate(doc));
    other.getText("content").insert(5, "theirs ");
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(other), "remote");
    assert.equal(ytext.toString(), "mine theirs ");

    // Undo removes only the local edit; the remote edit survives (rebased).
    undoManager.undo();
    assert.equal(ytext.toString(), "theirs ");
    undoManager.redo();
    assert.equal(ytext.toString(), "mine theirs ");
  });

  test("relative positions survive a concurrent remote insert before the cursor", () => {
    const doc = new Y.Doc();
    const ytext = doc.getText("content");
    ytext.insert(0, "hello world");

    // Cursor after "hello" (offset 5), encoded like an awareness payload.
    const rel = Y.createRelativePositionFromTypeIndex(ytext, 5);
    const encoded = Y.encodeRelativePosition(rel);

    // A remote client prepends text, shifting all absolute offsets.
    const other = new Y.Doc();
    Y.applyUpdate(other, Y.encodeStateAsUpdate(doc));
    other.getText("content").insert(0, ">>> ");
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(other), "remote");

    const abs = Y.createAbsolutePositionFromRelativePosition(
      Y.decodeRelativePosition(encoded),
      doc,
    );
    assert.ok(abs);
    assert.equal(abs.index, 9); // 5 + ">>> ".length
    assert.equal(ytext.toString().slice(0, abs.index), ">>> hello");
  });

  test("awareness state survives the encode -> encrypt -> decrypt -> apply relay", async () => {
    const key = await CryptoCore.generateEncryptionKey();

    const docA = new Y.Doc();
    const docB = new Y.Doc();
    // NB: Awareness starts a liveness setInterval; destroy() below or the
    // node:test process never exits.
    const awarenessA = new Y.awareness.Awareness(docA);
    const awarenessB = new Y.awareness.Awareness(docB);

    try {
      awarenessA.setLocalState({
        user: { name: "Alpha", color: "#fb4934" },
        cursor: { anchor: "aGk=", head: "aGk=" },
      });

      // What the consumer relays: opaque ciphertext, never the awareness bytes.
      const update = Y.awareness.encodeAwarenessUpdate(awarenessA, [docA.clientID]);
      const payload = await CryptoCore.encryptBytesWithKey(update, key);
      const decrypted = await CryptoCore.decryptBytes(payload.encryptedData, payload.iv, key);
      Y.awareness.applyAwarenessUpdate(awarenessB, decrypted, "remote");

      const state = awarenessB.getStates().get(docA.clientID);
      assert.equal(state.user.name, "Alpha");
      assert.equal(state.user.color, "#fb4934");
      assert.equal(state.cursor.anchor, "aGk=");

      // Clearing local state (pagehide) propagates as a removal.
      awarenessA.setLocalState(null);
      const removal = Y.awareness.encodeAwarenessUpdate(awarenessA, [docA.clientID]);
      Y.awareness.applyAwarenessUpdate(awarenessB, removal, "remote");
      assert.equal(awarenessB.getStates().has(docA.clientID), false);
    } finally {
      awarenessA.destroy();
      awarenessB.destroy();
    }
  });
});
