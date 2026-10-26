/**
 * Tests for static/note/js/live-binding.js - the pure diff/splice/caret
 * operations between the live-note textarea and the Yjs document
 * (window.NoteLiveBinding). The module is DOM-free and Yjs-free; the
 * equivalence suite at the bottom loads the vendored Yjs bundle to prove the
 * splice math matches real Y.Text deltas.
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

describe("diffText", () => {
  test("identical strings diff to null", () => {
    assert.equal(Binding.diffText("same", "same"), null);
    assert.equal(Binding.diffText("", ""), null);
  });

  test("insert at start, middle, and end", () => {
    assert.deepEqual(Binding.diffText("bc", "abc"), { index: 0, removed: "", inserted: "a" });
    assert.deepEqual(Binding.diffText("ac", "abc"), { index: 1, removed: "", inserted: "b" });
    assert.deepEqual(Binding.diffText("ab", "abc"), { index: 2, removed: "", inserted: "c" });
  });

  test("delete and replace", () => {
    assert.deepEqual(Binding.diffText("abcdef", "abef"), {
      index: 2,
      removed: "cd",
      inserted: "",
    });
    assert.deepEqual(Binding.diffText("hello world", "hello bold"), {
      index: 6,
      removed: "wor", // shared prefix "hello " and shared suffix "ld"
      inserted: "bo",
    });
  });

  test("ambiguous overlap clamps the suffix at the prefix boundary", () => {
    // "aa" -> "aaa" could be an insert at 0, 1, or 2; the clamp picks the end.
    assert.deepEqual(Binding.diffText("aa", "aaa"), { index: 2, removed: "", inserted: "a" });
    assert.deepEqual(Binding.diffText("abcabc", "abc"), {
      index: 3,
      removed: "abc",
      inserted: "",
    });
  });

  test("whole-string replacement and empty edges", () => {
    assert.deepEqual(Binding.diffText("", "abc"), { index: 0, removed: "", inserted: "abc" });
    assert.deepEqual(Binding.diffText("abc", ""), { index: 0, removed: "abc", inserted: "" });
  });

  test("indexes are UTF-16 code units (astral characters span two)", () => {
    const diff = Binding.diffText("ab", "a🙂b");
    assert.deepEqual(diff, { index: 1, removed: "", inserted: "🙂" });
    assert.equal(diff.inserted.length, 2);
    assert.equal(Binding.applySplices("ab", [{ index: 1, remove: 0, insert: "🙂" }]), "a🙂b");
  });

  test("diff round-trips through applySplices", () => {
    const cases = [
      ["hello", "hello world"],
      ["one two three", "one 2 three"],
      ["# Heading\nbody", "# Heading\n\nnew body"],
      ["", "fresh"],
      ["gone", ""],
    ];
    for (const [before, after] of cases) {
      const diff = Binding.diffText(before, after);
      const splice = { index: diff.index, remove: diff.removed.length, insert: diff.inserted };
      assert.equal(Binding.applySplices(before, [splice]), after);
    }
  });
});

describe("spliceListFromDelta", () => {
  test("retain + insert", () => {
    assert.deepEqual(Binding.spliceListFromDelta([{ retain: 2 }, { insert: "xy" }]), [
      { index: 2, remove: 0, insert: "xy" },
    ]);
  });

  test("retain + delete", () => {
    assert.deepEqual(Binding.spliceListFromDelta([{ retain: 1 }, { delete: 2 }]), [
      { index: 1, remove: 2, insert: "" },
    ]);
  });

  test("mixed ops keep pre-change coordinates and ascend", () => {
    const delta = [{ retain: 1 }, { insert: "Z" }, { delete: 1 }, { retain: 3 }, { insert: "!" }];
    const splices = Binding.spliceListFromDelta(delta);

    assert.deepEqual(splices, [
      { index: 1, remove: 0, insert: "Z" },
      { index: 1, remove: 1, insert: "" },
      { index: 5, remove: 0, insert: "!" },
    ]);
    // "abcdef": retain a, insert Z, delete b, retain cde, insert ! -> "aZcde!f"
    assert.equal(Binding.applySplices("abcdef", splices), "aZcde!f");
  });

  test("empty delta produces no splices", () => {
    assert.deepEqual(Binding.spliceListFromDelta([]), []);
  });
});

describe("transformOffset", () => {
  const insertAt = (index, text) => [{ index, remove: 0, insert: text }];
  const deleteAt = (index, count) => [{ index, remove: count, insert: "" }];

  test("insert before the caret shifts it right", () => {
    assert.equal(Binding.transformOffset(5, insertAt(2, "xy")), 7);
  });

  test("insert exactly at the caret does not shift it", () => {
    assert.equal(Binding.transformOffset(5, insertAt(5, "xy")), 5);
  });

  test("insert after the caret does not shift it", () => {
    assert.equal(Binding.transformOffset(5, insertAt(6, "xy")), 5);
  });

  test("delete fully before the caret shifts it left", () => {
    assert.equal(Binding.transformOffset(5, deleteAt(1, 2)), 3);
  });

  test("delete spanning the caret clamps it to the deletion start", () => {
    assert.equal(Binding.transformOffset(5, deleteAt(3, 4)), 3);
  });

  test("delete after the caret does not shift it", () => {
    assert.equal(Binding.transformOffset(5, deleteAt(5, 2)), 5);
    assert.equal(Binding.transformOffset(5, deleteAt(6, 2)), 5);
  });

  test("replace before the caret shifts by the net length change", () => {
    const replace = [{ index: 0, remove: 3, insert: "longer" }];
    assert.equal(Binding.transformOffset(5, replace), 8);
  });

  test("multiple splices accumulate while comparing in old coordinates", () => {
    const splices = [
      { index: 0, remove: 0, insert: "AA" }, // +2
      { index: 4, remove: 2, insert: "" }, // -2, still before offset 8
    ];
    assert.equal(Binding.transformOffset(8, splices), 8);
  });

  test("selection edges transform independently (delete across a selection)", () => {
    // Selection [4, 9), remote deletes [2, 6): start clamps to 2, end shifts by -4.
    const splices = deleteAt(2, 4);
    assert.equal(Binding.transformOffset(4, splices), 2);
    assert.equal(Binding.transformOffset(9, splices), 5);
  });
});

describe("equivalence with real Y.Text deltas", () => {
  /**
   * Apply a remote edit to `doc` (mutating a synced twin), capture the
   * remote-origin delta, and assert the splice pipeline reproduces the
   * document text exactly.
   */
  function assertSpliceEquivalence(seedText, mutate) {
    const doc = new Y.Doc();
    doc.getText("content").insert(0, seedText);

    const twin = new Y.Doc();
    Y.applyUpdate(twin, Y.encodeStateAsUpdate(doc));

    const before = doc.getText("content").toString();
    let observed = null;
    doc.getText("content").observe((event) => {
      if (event.transaction.origin === "remote") observed = event.delta;
    });

    mutate(twin.getText("content"));
    Y.applyUpdate(doc, Y.encodeStateAsUpdate(twin), "remote");

    assert.ok(observed, "expected a remote-origin delta");
    const splices = Binding.spliceListFromDelta(observed);
    assert.equal(Binding.applySplices(before, splices), doc.getText("content").toString());
    return splices;
  }

  test("remote insert", () => {
    assertSpliceEquivalence("hello world", (text) => text.insert(5, ", brave"));
  });

  test("remote delete", () => {
    assertSpliceEquivalence("hello world", (text) => text.delete(2, 6));
  });

  test("remote replace (delete + insert in one transaction)", () => {
    assertSpliceEquivalence("hello world", (text) => {
      text.doc.transact(() => {
        text.delete(6, 5);
        text.insert(6, "there");
      });
    });
  });

  test("remote multi-region edit in one transaction", () => {
    assertSpliceEquivalence("aaa bbb ccc", (text) => {
      text.doc.transact(() => {
        text.insert(0, ">> ");
        text.delete(7, 4); // coordinates after the first insert
        text.insert(text.length, " <<");
      });
    });
  });

  test("remote edit with astral characters", () => {
    assertSpliceEquivalence("plain text", (text) => text.insert(5, " 🙂🎉 "));
  });
});
