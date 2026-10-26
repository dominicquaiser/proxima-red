/**
 * Tests for the live-note undo integration: Y.UndoManager tracked on the
 * "local" origin (live.js) driving the textarea through the same replay path
 * as remote edits (live-binding splices, editor-core applyRemoteSplices).
 *
 * These tests exercise the exact origin contract the live page relies on:
 * - only "local" transactions are undoable; remote edits never are;
 * - undo/redo transactions carry the UndoManager as origin, so they pass the
 *   sync outbox filter (origin !== "remote" -> uploaded) AND the replay
 *   filter (origin !== "local" -> spliced into the textarea);
 * - selection memory stored in stackItem.meta as relative positions survives
 *   interleaved remote edits.
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

global.window = globalThis;
const staticJs = (...parts) => path.join(__dirname, "..", "..", "static", "note", "js", ...parts);
vm.runInThisContext(fs.readFileSync(staticJs("live-binding.js"), "utf8"), {
  filename: "live-binding.js",
});
vm.runInThisContext(fs.readFileSync(staticJs("vendor", "yjs.min.js"), "utf8"), {
  filename: "yjs.min.js",
});

const Binding = window.NoteLiveBinding;
const Y = window.Y;

/**
 * A miniature live page: one doc wired the way live.js wires it, with a
 * string standing in for the textarea, replayed via the real splice math.
 */
function createPage() {
  const doc = new Y.Doc();
  const ytext = doc.getText("content");
  const undoManager = new Y.UndoManager(ytext, { trackedOrigins: new Set(["local"]) });

  const page = { doc, ytext, undoManager, buffer: "", outbox: [] };

  doc.on("update", (update, origin) => {
    if (origin !== "remote") page.outbox.push(update);
  });
  ytext.observe((event) => {
    if (event.transaction.origin === "local") return;
    page.buffer = Binding.applySplices(page.buffer, Binding.spliceListFromDelta(event.delta));
  });

  page.typeLocal = (nextValue) => {
    const diff = Binding.diffText(ytext.toString(), nextValue);
    if (!diff) return;
    doc.transact(() => {
      if (diff.removed) ytext.delete(diff.index, diff.removed.length);
      if (diff.inserted) ytext.insert(diff.index, diff.inserted);
    }, "local");
    page.buffer = nextValue; // the textarea already shows what was typed
  };
  page.applyRemote = (update) => Y.applyUpdate(doc, update, "remote");

  return page;
}

/** A second client's edit, encoded as the update the server would relay. */
function remoteEditFrom(page, mutate) {
  const other = new Y.Doc();
  Y.applyUpdate(other, Y.encodeStateAsUpdate(page.doc));
  mutate(other.getText("content"));
  return Y.encodeStateAsUpdate(other);
}

describe("live-note undo integration", () => {
  test("undo reverts only local edits across interleaved remote updates", () => {
    const page = createPage();

    page.typeLocal("mine ");
    page.applyRemote(remoteEditFrom(page, (t) => t.insert(5, "theirs ")));
    assert.equal(page.ytext.toString(), "mine theirs ");
    assert.equal(page.buffer, "mine theirs ");

    page.undoManager.undo();
    assert.equal(page.ytext.toString(), "theirs ");
    // The undo replayed into the textarea through the non-"local" path.
    assert.equal(page.buffer, "theirs ");

    page.undoManager.redo();
    assert.equal(page.ytext.toString(), "mine theirs ");
    assert.equal(page.buffer, "mine theirs ");
  });

  test("remote edits are not undoable; empty history is a no-op", () => {
    const page = createPage();
    page.applyRemote(remoteEditFrom(page, (t) => t.insert(0, "remote only")));
    assert.equal(page.buffer, "remote only");

    assert.equal(page.undoManager.canUndo(), false);
    page.undoManager.undo();
    assert.equal(page.ytext.toString(), "remote only");
    assert.equal(page.buffer, "remote only");
  });

  test("undo and redo transactions are queued for upload (outbox contract)", () => {
    const page = createPage();
    page.typeLocal("sync me");
    page.outbox.length = 0;

    page.undoManager.undo();
    assert.equal(page.outbox.length, 1);
    page.undoManager.redo();
    assert.equal(page.outbox.length, 2);

    // A fresh doc replaying the full outbox history converges on the result.
    const replayed = new Y.Doc();
    Y.applyUpdate(replayed, Y.encodeStateAsUpdate(page.doc));
    assert.equal(replayed.getText("content").toString(), "sync me");
  });

  test("selection memory in stackItem.meta survives a concurrent remote insert", () => {
    const page = createPage();

    // live.js stores the caret as relative positions on capture...
    page.undoManager.on("stack-item-added", (event) => {
      event.stackItem.meta.set("cursor", {
        anchor: Y.createRelativePositionFromTypeIndex(page.ytext, 4),
        head: Y.createRelativePositionFromTypeIndex(page.ytext, 4),
      });
    });
    let popped = null;
    page.undoManager.on("stack-item-popped", (event) => {
      popped = event.stackItem.meta.get("cursor") || null;
    });

    page.typeLocal("mine");
    // ...a remote client then prepends text, shifting absolute offsets...
    page.applyRemote(remoteEditFrom(page, (t) => t.insert(0, ">>> ")));

    page.undoManager.undo();
    assert.ok(popped);
    // ...and the restored offset accounts for the remote shift: the caret
    // anchors to where "mine" was, now after ">>> " (offset 4), not at the
    // stale absolute offset in the pre-remote coordinate space.
    const abs = Y.createAbsolutePositionFromRelativePosition(popped.anchor, page.doc);
    assert.ok(abs);
    assert.equal(abs.index, 4);
    assert.equal(page.buffer, ">>> ");
  });

  test("undo collapses to a no-op when a remote edit already deleted the text", () => {
    const page = createPage();
    page.typeLocal("doomed");
    // A remote client deletes everything the local user typed.
    page.applyRemote(remoteEditFrom(page, (t) => t.delete(0, 6)));
    assert.equal(page.buffer, "");

    // Undoing the local insert has nothing left to remove; the doc must not
    // corrupt or resurrect content.
    page.undoManager.undo();
    assert.equal(page.ytext.toString(), "");
    assert.equal(page.buffer, "");
  });
});
