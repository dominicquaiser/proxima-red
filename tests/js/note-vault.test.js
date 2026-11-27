/**
 * Exercise the real note vault controller through its sidebar actions, with
 * manually completed HTTP requests to check index/Trash flag ordering.
 * Run with: node --test tests/js/note-vault.test.js
 */
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const settled = () => new Promise(setImmediate);
const copy = (value) => JSON.parse(JSON.stringify(value));

// Only the DOM operations used to render the sidebar and open its menus.
function element() {
  const listeners = new Map();
  return {
    children: [],
    dataset: {},
    style: {},
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    addEventListener(name, listener) {
      if (!listeners.has(name)) listeners.set(name, []);
      listeners.get(name).push(listener);
    },
    fire(name, event = {}) {
      for (const listener of listeners.get(name) || []) listener(event);
    },
    appendChild(child) {
      this.children.push(child);
    },
    replaceChildren(...children) {
      this.children = children;
    },
    get textContent() {
      return this.children.map((child) => child.textContent).join("");
    },
    set textContent(value) {
      this.children = [{ textContent: value }];
    },
    setAttribute() {},
    querySelector: () => null,
    querySelectorAll: () => [],
    getBoundingClientRect: () => ({ right: 0, top: 0, width: 0, height: 0 }),
  };
}

function descendants(node) {
  return [node, ...(node.children || []).flatMap(descendants)];
}

async function setup({ trashed = false, flagged = trashed } = {}) {
  const nodes = new Map();
  const getNode = (id) => {
    if (!nodes.has(id)) nodes.set(id, element());
    return nodes.get(id);
  };
  getNode("main-content").dataset = {
    indexUrl: "/index/",
    notesUrl: "/notes/",
    noteUrlBase: "/notes/dummy/",
    dummyNoteId: "dummy",
    noteTrashUrl: "/trash/",
    trashRetentionDays: "7",
  };
  const doc = element();
  Object.assign(doc, {
    body: element(),
    getElementById: getNode,
    querySelector: () => element(),
    createElement: element,
    createTextNode: (textContent) => ({ textContent }),
  });
  const note = (id, folderId = null) => ({
    id,
    name: id + ".md",
    folderId,
    trashed,
    deletedAt: trashed ? "2026-11-01T00:00:00Z" : null,
  });
  let stored = {
    version: 1,
    folders: [{ id: "folder", name: "folder", order: 0 }],
    notes: [note("root"), note("one", "folder"), note("two", "folder")],
  };
  const flags = new Map(stored.notes.map(({ id }) => [id, flagged]));
  const requests = [];
  let editorValue = "";
  let onInput;
  let createdNotes = 0;
  const context = {
    document: doc,
    crypto: webcrypto,
    console: { error() {} },
    innerWidth: 1000,
    innerHeight: 1000,
    addEventListener: doc.addEventListener.bind(doc),
    matchMedia: () => ({ matches: false }),
    confirm: () => true,
    NoteEditorCore: {
      init: () => ({
        onInput(listener) {
          onInput = listener;
        },
        getValue: () => editorValue,
        setValue(text) {
          editorValue = text;
        },
        noteTooLarge: () => false,
        showEdit() {},
      }),
    },
    NoteShare: { init() {} },
    Notify: { show() {} },
    CryptoCore: { encryptWithKey: async (text) => ({ encryptedData: text, iv: "iv" }) },
    PasswordCrypto: { decryptPassword: async (content) => content },
    VaultSession: { create: () => ({ start: async () => "key" }) },
    AuthCrypto: {
      importKeyFromBase64: async () => "key",
      decryptAccountData: async (data) => JSON.parse(data),
      encryptAccountData: async (data) => ({ encryptedData: JSON.stringify(data), iv: "iv" }),
    },
    Http: {
      getCsrfToken: () => "csrf",
      getJson: async (url) => {
        if (url.startsWith("/notes/") && url !== "/notes/") {
          return new Promise((resolve) => {
            requests.push({
              url,
              finish() {
                requests.splice(requests.indexOf(this), 1);
                resolve({
                  response: { ok: true, status: 200 },
                  result: { success: true, content: "Saved note text", iv: "iv" },
                });
              },
            });
          });
        }
        return {
          response: { ok: true, status: 200 },
          result:
            url === "/index/"
              ? { success: true, encrypted_data: JSON.stringify(stored), iv: "iv" }
              : {
                  success: true,
                  notes: stored.notes.map(({ id }) => ({
                    id,
                    trashed_at: flags.get(id) ? "2026-11-01T00:00:00Z" : null,
                  })),
                },
        };
      },
      postForm: (url, body) =>
        new Promise((resolve) => {
          requests.push({
            url,
            body: copy(body),
            finish(accepted = true) {
              requests.splice(requests.indexOf(this), 1);
              let noteId;
              if (accepted) {
                if (url === "/index/") stored = JSON.parse(body.encrypted_data);
                else if (url === "/trash/") body.ids.forEach((id) => flags.set(id, body.trashed));
                else if (url === "/notes/") {
                  createdNotes += 1;
                  noteId = createdNotes === 1 ? "new-note" : "new-note-" + createdNotes;
                }
              }
              resolve({
                response: { ok: accepted, status: accepted ? 200 : 500 },
                result: { success: accepted, note_id: noteId },
              });
            },
          });
        }),
    },
  };
  context.window = context;
  vm.createContext(context);
  for (const file of ["shared/js/save-queue.js", "note/js/vault-index.js", "note/js/vault.js"]) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, "../../static", file), "utf8"), context, {
      filename: file,
    });
  }
  doc.fire("DOMContentLoaded");
  await settled();

  return {
    flags,
    requests,
    stored: () => stored,
    editorValue: () => editorValue,
    editorName: () => getNode("vault-crumb").textContent,
    edit(text) {
      editorValue = text;
      onInput();
    },
    async saveNote() {
      doc.fire("keydown", { ctrlKey: true, key: "s", preventDefault() {} });
      await settled();
    },
    async openNote(id) {
      const tree = getNode("vault-tree");
      const row = descendants(tree).find((node) => node.dataset?.noteId === id);
      assert.ok(row, `Missing note ${id}`);
      tree.fire("click", {
        target: { closest: (selector) => (selector === ".tree__file" ? row : null) },
      });
      await settled();
    },
    async newFolder() {
      getNode("new-folder-btn").fire("click");
      await settled();
    },
    async newNote() {
      getNode("new-note-btn").fire("click");
      await settled();
    },
    async action(kind, id, label, confirm = false) {
      const anchor = descendants(getNode("vault-tree")).find(
        (node) => node.dataset?.ctxKind === kind && node.dataset.ctxId === id,
      );
      assert.ok(anchor, `Missing ${kind} actions for ${id}`);
      const event = { preventDefault() {}, stopPropagation() {} };
      getNode("vault-tree").fire("click", { ...event, target: { closest: () => anchor } });
      const button = getNode("ctx-menu").children.find((node) => node.textContent === label);
      assert.ok(button, `Missing ${label} menu item`);
      button.fire("click", event);
      if (confirm) button.fire("click", event);
      await settled();
    },
    async finish(url, accepted = true) {
      const request = requests.find((item) => item.url === url);
      assert.ok(request, `Missing pending ${url} request`);
      request.finish(accepted);
      await settled();
    },
    unloadIsBlocked() {
      let blocked = false;
      doc.fire("beforeunload", { preventDefault: () => (blocked = true) });
      return blocked;
    },
  };
}

test("restore waits for a trash queued behind an unrelated index save", async () => {
  const page = await setup();
  await page.newFolder();
  await page.action("note", "root", "Move to Trash");
  await page.action("trash", "root", "Restore");
  assert.equal(page.requests.length, 1, "restore must not clear the flag before trash completes");

  await page.finish("/index/"); // Unrelated folder save.
  await page.finish("/index/"); // Trashed index.
  assert.equal(page.requests[0].body.trashed, true);
  await page.finish("/trash/");
  assert.equal(page.requests[0].body.trashed, false);
  await page.finish("/trash/");
  await page.finish("/index/"); // Restored index.

  assert.equal(page.stored().notes.find(({ id }) => id === "root").trashed, false);
  assert.equal(page.flags.get("root"), false, "an active note must not be scheduled for deletion");
  assert.equal(page.unloadIsBlocked(), false);
});

test("restore waits for an in-flight deletion flag and keeps the unload warning active", async () => {
  const page = await setup();
  await page.action("note", "root", "Move to Trash");
  await page.finish("/index/");
  await page.action("trash", "root", "Restore");
  assert.equal(page.requests.length, 1, "only the earlier trash flag may be in flight");
  assert.equal(
    page.unloadIsBlocked(),
    true,
    "queued restore is unsaved even without an index POST",
  );

  await page.finish("/trash/");
  await page.finish("/trash/");
  assert.equal(page.flags.get("root"), false, "clear deletion before saving the active index");
  assert.equal(page.stored().notes.find(({ id }) => id === "root").trashed, true);
  await page.finish("/index/");
  assert.equal(page.stored().notes.find(({ id }) => id === "root").trashed, false);
  assert.equal(page.unloadIsBlocked(), false);
});

test("restoring one note waits for the folder's bulk trash write", async () => {
  const page = await setup();
  await page.newFolder();
  await page.action("folder", "folder", "Delete folder", true);
  await page.action("trash", "one", "Restore");
  assert.equal(page.requests.length, 1);

  await page.finish("/index/");
  await page.finish("/index/");
  assert.deepEqual(page.requests[0].body.ids, ["one", "two"]);
  await page.finish("/trash/");
  await page.finish("/trash/");
  await page.finish("/index/");

  assert.equal(page.flags.get("one"), false);
  assert.equal(page.flags.get("two"), true);
  assert.equal(page.stored().notes.find(({ id }) => id === "one").trashed, false);
  assert.equal(page.stored().notes.find(({ id }) => id === "two").trashed, true);
});

test("a failed flag clear keeps the note in Trash and a retry can restore it", async () => {
  const page = await setup({ trashed: true });
  await page.action("trash", "root", "Restore");
  await page.finish("/trash/", false);
  assert.equal(page.requests.length, 0, "a failed flag clear must not save an active index");
  assert.equal(page.stored().notes.find(({ id }) => id === "root").trashed, true);
  assert.equal(page.unloadIsBlocked(), false);

  await page.action("trash", "root", "Restore");
  await page.finish("/trash/");
  await page.finish("/index/");
  assert.equal(page.flags.get("root"), false);
  assert.equal(page.stored().notes.find(({ id }) => id === "root").trashed, false);
});

test("a failed trash index never sets the deletion flag or blocks a waiting restore", async () => {
  const page = await setup();
  await page.action("note", "root", "Move to Trash");
  await page.action("trash", "root", "Restore");
  await page.finish("/index/", false);
  assert.equal(page.requests.length, 1);
  assert.equal(page.requests[0].body.trashed, false, "only the queued restore may update flags");
  assert.equal(page.flags.get("root"), false);

  await page.finish("/trash/");
  await page.finish("/index/");
  assert.equal(page.stored().notes.find(({ id }) => id === "root").trashed, false);
  assert.equal(page.unloadIsBlocked(), false);
});

test("startup flag repair finishes before a new trash operation", async () => {
  const page = await setup({ flagged: true });
  assert.equal(page.requests[0].body.trashed, false);
  await page.action("note", "root", "Move to Trash");
  assert.equal(page.requests.length, 1, "trash must wait for the startup flag repair");

  await page.finish("/trash/");
  await page.finish("/index/");
  await page.finish("/trash/");
  assert.equal(page.flags.get("root"), true);
  assert.equal(page.stored().notes.find(({ id }) => id === "root").trashed, true);
});

test("a pending Trash move blocks reopening until a failed move has rolled back", async () => {
  const page = await setup({ flagged: true });
  await page.openNote("root");
  await page.finish("/notes/root/");
  assert.equal(page.editorValue(), "Saved note text");

  await page.action("note", "root", "Move to Trash");
  await page.openNote("root");
  assert.deepEqual(page.requests.map(({ url }) => url), ["/trash/"]);
  assert.equal(page.editorValue(), "");

  await page.finish("/trash/"); // Startup repair.
  await page.finish("/index/", false); // Moving to Trash failed.
  await page.openNote("root");
  await page.finish("/notes/root/");
  assert.equal(page.editorValue(), "Saved note text");
  assert.equal(page.flags.get("root"), false);
});

test("a note read that finishes during a queued Trash move leaves the editor alone", async () => {
  const page = await setup({ flagged: true });
  await page.openNote("root");
  await page.action("note", "root", "Move to Trash");
  await page.finish("/notes/root/");
  assert.equal(page.editorValue(), "");

  await page.finish("/trash/");
  await page.finish("/index/");
  await page.finish("/trash/");
  assert.equal(page.flags.get("root"), true);
});

test("deleting a folder keeps unsaved edits as a draft and blocks opening its other notes", async () => {
  const page = await setup({ flagged: true });
  await page.openNote("one");
  await page.finish("/notes/one/");
  page.edit("Unsaved note text");

  await page.action("folder", "folder", "Delete folder", true);
  await page.openNote("two");
  await page.saveNote();
  assert.deepEqual(page.requests.map(({ url }) => url), ["/trash/"]);

  await page.finish("/trash/");
  await page.finish("/index/");
  await page.finish("/trash/");
  assert.equal(page.flags.get("one"), true);
  assert.equal(page.editorValue(), "Unsaved note text");
  assert.equal(page.editorName(), "/untitled.md");
  assert.equal(page.unloadIsBlocked(), true);

  await page.saveNote();
  assert.equal(page.requests[0].url, "/notes/");
  assert.equal(page.requests[0].body.content, "Unsaved note text");
  await page.finish("/notes/");
  await page.finish("/index/");
  assert.equal(page.flags.get("one"), true);
  assert.equal(page.stored().notes.find(({ id }) => id === "new-note").trashed, false);
  assert.equal(page.unloadIsBlocked(), false);
});

test("a new note's first save that lands after opening another note leaves that note open", async () => {
  const page = await setup();
  page.edit("Draft text");
  await page.saveNote();
  await page.openNote("root");
  await page.finish("/notes/root/");
  await page.finish("/notes/");
  await page.finish("/index/");

  const names = new Map(page.stored().notes.map(({ id, name }) => [id, name]));
  assert.equal(names.get("new-note"), "untitled.md", "index the new note under its own name");
  assert.equal(names.get("root"), "root.md");
  assert.equal(page.editorName(), "/root.md");
  assert.equal(page.editorValue(), "Saved note text");
  assert.equal(page.unloadIsBlocked(), false, "the open note has no unsaved changes");

  page.edit("Edited root text");
  await page.saveNote();
  assert.equal(page.requests[0].url, "/notes/root/");
  assert.equal(page.requests[0].body.content, "Edited root text");
});

test("starting a new note while another new note saves keeps the two buffers apart", async () => {
  const page = await setup();
  page.edit("First draft");
  await page.saveNote();
  await page.newNote();
  await page.finish("/notes/");
  await page.finish("/index/");

  assert.equal(page.editorValue(), "");
  assert.equal(page.unloadIsBlocked(), false, "the blank buffer has no unsaved changes");

  page.edit("Second draft");
  await page.saveNote();
  assert.equal(page.requests[0].url, "/notes/", "the second draft gets a row of its own");
  await page.finish("/notes/");
  await page.finish("/index/");

  const created = page.stored().notes.filter(({ id }) => id.startsWith("new-note"));
  assert.deepEqual(
    created.map(({ id, name }) => [id, name]),
    [
      ["new-note", "untitled.md"],
      ["new-note-2", "untitled-2.md"],
    ],
  );
  assert.equal(page.editorName(), "/untitled-2.md");
});
