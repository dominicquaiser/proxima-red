/**
 * Tests for static/note/js/vault-index.js - the pure operations on the note
 * vault's encrypted index (window.NoteVaultIndex). The module is DOM-free so
 * it runs under Node directly; crypto.randomUUID comes from Node's global
 * webcrypto.
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
const source = fs.readFileSync(
  path.join(__dirname, "..", "..", "static", "note", "js", "vault-index.js"),
  "utf8",
);
vm.runInThisContext(source, { filename: "vault-index.js" });

const Index = window.NoteVaultIndex;

/** An index with two folders and notes in root, folders, and trash. */
function sampleIndex() {
  let index = Index.createEmpty();
  index = Index.addFolder(index, "Research", "folder-1");
  index = Index.addFolder(index, "Personal", "folder-2");
  index = Index.addNote(index, { id: "note-root", name: "root.md" });
  index = Index.addNote(index, { id: "note-ml", name: "machine_learning.md", folderId: "folder-1" });
  index = Index.addNote(index, { id: "note-crypto", name: "cryptography.md", folderId: "folder-1" });
  index = Index.addNote(index, { id: "note-diary", name: "diary.md", folderId: "folder-2" });
  index = Index.trashNote(index, "note-diary");
  return index;
}

describe("createEmpty / isSupported", () => {
  test("creates a supported version-1 index", () => {
    const index = Index.createEmpty();
    assert.equal(index.version, 1);
    assert.ok(Index.isSupported(index));
  });

  test("rejects unknown versions and malformed documents", () => {
    assert.ok(!Index.isSupported(null));
    assert.ok(!Index.isSupported({ version: 2, folders: [], notes: [] }));
    assert.ok(!Index.isSupported({ version: 1, folders: {}, notes: [] }));
  });
});

describe("immutability", () => {
  test("operations never mutate their input", () => {
    const index = sampleIndex();
    const snapshot = JSON.stringify(index);

    Index.addFolder(index, "New");
    Index.renameFolder(index, "folder-1", "Renamed");
    Index.deleteFolder(index, "folder-1");
    Index.addNote(index, { id: "x", name: "x.md" });
    Index.renameNote(index, "note-ml", "renamed.md");
    Index.moveNote(index, "note-ml", "folder-2");
    Index.trashNote(index, "note-ml");
    Index.restoreNote(index, "note-diary");
    Index.removeNote(index, "note-ml");
    Index.touchNote(index, "note-ml");
    Index.filter(index, "ml");
    Index.reconcile(index, []);

    assert.equal(JSON.stringify(index), snapshot);
  });
});

describe("folders", () => {
  test("addFolder appends with increasing order", () => {
    const index = sampleIndex();
    const next = Index.addFolder(index, "Archive", "folder-3");
    const added = next.folders.find((f) => f.id === "folder-3");
    assert.equal(added.name, "Archive");
    assert.ok(added.order > next.folders.find((f) => f.id === "folder-2").order);
  });

  test("addFolder falls back to a default name for blank input", () => {
    const next = Index.addFolder(Index.createEmpty(), "   ", "folder-x");
    assert.equal(next.folders[0].name, "folder");
  });

  test("renameFolder changes the name and ignores blank names", () => {
    const index = sampleIndex();
    const renamed = Index.renameFolder(index, "folder-1", "Lab");
    assert.equal(renamed.folders.find((f) => f.id === "folder-1").name, "Lab");

    const unchanged = Index.renameFolder(index, "folder-1", "  ");
    assert.equal(unchanged.folders.find((f) => f.id === "folder-1").name, "Research");
  });

  test("deleteFolder moves contained notes to trash", () => {
    const next = Index.deleteFolder(sampleIndex(), "folder-1");
    assert.ok(!next.folders.some((f) => f.id === "folder-1"));
    const ml = next.notes.find((n) => n.id === "note-ml");
    assert.equal(ml.trashed, true);
    assert.equal(ml.folderId, null);
    assert.ok(ml.deletedAt);
  });

  test("deleteFolder keeps an already-trashed note's deletedAt", () => {
    let index = sampleIndex();
    index = Index.moveNote(Index.restoreNote(index, "note-diary"), "note-diary", "folder-2");
    index = Index.trashNote(index, "note-diary");
    const before = index.notes.find((n) => n.id === "note-diary").deletedAt;

    const next = Index.deleteFolder(index, "folder-2");
    assert.equal(next.notes.find((n) => n.id === "note-diary").deletedAt, before);
  });
});

describe("notes", () => {
  test("addNote defaults and folder validation", () => {
    const index = sampleIndex();
    const next = Index.addNote(index, { id: "n", name: "n.md", folderId: "missing" });
    const added = next.notes.find((note) => note.id === "n");
    assert.equal(added.folderId, null); // unknown folder falls back to root
    assert.equal(added.trashed, false);
    assert.ok(added.createdAt);
    assert.ok(added.updatedAt);
  });

  test("renameNote changes the name", () => {
    const next = Index.renameNote(sampleIndex(), "note-ml", "ml2.md");
    assert.equal(next.notes.find((n) => n.id === "note-ml").name, "ml2.md");
  });

  test("moveNote reassigns the folder, unknown target means root", () => {
    const index = sampleIndex();
    const moved = Index.moveNote(index, "note-ml", "folder-2");
    assert.equal(moved.notes.find((n) => n.id === "note-ml").folderId, "folder-2");

    const rooted = Index.moveNote(index, "note-ml", "nope");
    assert.equal(rooted.notes.find((n) => n.id === "note-ml").folderId, null);
  });

  test("trashNote sets trashed + deletedAt once", () => {
    const index = sampleIndex();
    const next = Index.trashNote(index, "note-ml");
    const note = next.notes.find((n) => n.id === "note-ml");
    assert.equal(note.trashed, true);
    assert.ok(note.deletedAt);

    const again = Index.trashNote(next, "note-ml");
    assert.equal(again.notes.find((n) => n.id === "note-ml").deletedAt, note.deletedAt);
  });

  test("restoreNote returns the note to its surviving folder", () => {
    const index = sampleIndex();
    const restored = Index.restoreNote(index, "note-diary");
    const note = restored.notes.find((n) => n.id === "note-diary");
    assert.equal(note.trashed, false);
    assert.equal(note.deletedAt, null);
    assert.equal(note.folderId, "folder-2"); // folder still exists
  });

  test("restoreNote falls back to root when the folder is gone", () => {
    const index = Index.deleteFolder(sampleIndex(), "folder-2");
    const restored = Index.restoreNote(index, "note-diary");
    assert.equal(restored.notes.find((n) => n.id === "note-diary").folderId, null);
  });

  test("removeNote drops the entry", () => {
    const next = Index.removeNote(sampleIndex(), "note-ml");
    assert.ok(!next.notes.some((n) => n.id === "note-ml"));
  });

  test("touchNote bumps updatedAt", () => {
    const next = Index.touchNote(sampleIndex(), "note-ml", "2026-07-12T00:00:00Z");
    assert.equal(
      next.notes.find((n) => n.id === "note-ml").updatedAt,
      "2026-07-12T00:00:00Z",
    );
  });
});

describe("defaultName", () => {
  test("suffixes until the name is free", () => {
    let index = Index.createEmpty();
    assert.equal(Index.defaultName(index), "untitled.md");

    index = Index.addNote(index, { id: "a", name: "untitled.md" });
    assert.equal(Index.defaultName(index), "untitled-2.md");

    index = Index.addNote(index, { id: "b", name: "untitled-2.md" });
    assert.equal(Index.defaultName(index), "untitled-3.md");
  });
});

describe("filter", () => {
  test("empty term returns everything", () => {
    const index = sampleIndex();
    const filtered = Index.filter(index, "  ");
    assert.equal(filtered.notes.length, index.notes.length);
  });

  test("matches note names case-insensitively and keeps their folders", () => {
    const filtered = Index.filter(sampleIndex(), "MACHINE");
    assert.deepEqual(
      filtered.notes.map((n) => n.id),
      ["note-ml"],
    );
    assert.deepEqual(
      filtered.folders.map((f) => f.id),
      ["folder-1"],
    );
  });

  test("a matching folder name keeps all its notes", () => {
    const filtered = Index.filter(sampleIndex(), "research");
    assert.deepEqual(
      filtered.notes.map((n) => n.id).sort(),
      ["note-crypto", "note-ml"],
    );
  });

  test("drops folders with no matches", () => {
    const filtered = Index.filter(sampleIndex(), "root");
    assert.equal(filtered.folders.length, 0);
    assert.deepEqual(
      filtered.notes.map((n) => n.id),
      ["note-root"],
    );
  });
});

describe("reconcile", () => {
  const rows = (...ids) => ids.map((id) => ({ id }));

  test("no drift reports changed: false", () => {
    const index = sampleIndex();
    const outcome = Index.reconcile(
      index,
      rows("note-root", "note-ml", "note-crypto", "note-diary"),
    );
    assert.equal(outcome.changed, false);
    assert.deepEqual(outcome.orphanIds, []);
    assert.deepEqual(outcome.droppedIds, []);
    assert.equal(outcome.index.notes.length, 4);
  });

  test("drops index entries with no server row", () => {
    const outcome = Index.reconcile(sampleIndex(), rows("note-root", "note-ml", "note-diary"));
    assert.equal(outcome.changed, true);
    assert.deepEqual(outcome.droppedIds, ["note-crypto"]);
    assert.ok(!outcome.index.notes.some((n) => n.id === "note-crypto"));
  });

  test("reports server rows missing from the index as orphans", () => {
    const outcome = Index.reconcile(
      sampleIndex(),
      rows("note-root", "note-ml", "note-crypto", "note-diary", "note-orphan"),
    );
    assert.deepEqual(outcome.orphanIds, ["note-orphan"]);
    // Orphans are NOT auto-added: the caller decrypts and adopts them.
    assert.ok(!outcome.index.notes.some((n) => n.id === "note-orphan"));
    assert.equal(outcome.changed, false);
  });
});

describe("visibleTree", () => {
  test("splits folders, root notes, and trash", () => {
    const tree = Index.visibleTree(sampleIndex());

    assert.deepEqual(
      tree.folders.map((f) => f.id),
      ["folder-1", "folder-2"],
    );
    // Folder notes are name-sorted and exclude trashed entries.
    assert.deepEqual(
      tree.folders[0].notes.map((n) => n.name),
      ["cryptography.md", "machine_learning.md"],
    );
    assert.equal(tree.folders[1].notes.length, 0);
    assert.deepEqual(
      tree.rootNotes.map((n) => n.id),
      ["note-root"],
    );
    assert.deepEqual(
      tree.trash.map((n) => n.id),
      ["note-diary"],
    );
  });

  test("folders keep their order", () => {
    let index = Index.createEmpty();
    index = Index.addFolder(index, "B", "b");
    index = Index.addFolder(index, "A", "a");
    const tree = Index.visibleTree(index);
    assert.deepEqual(
      tree.folders.map((f) => f.name),
      ["B", "A"],
    );
  });
});
