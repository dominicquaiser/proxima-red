/**
 * @fileoverview DOM-free operations for the note vault's encrypted index.
 *
 * Folders are flat (no nesting); Trash is the `trashed` flag, not a folder.
 * Every function is non-mutating so vault.js can optimistically save/rollback.
 */
(function () {
  "use strict";

  const INDEX_VERSION = 1;
  const DEFAULT_FOLDER_NAME = "folder";
  const DEFAULT_NOTE_NAME = "untitled.md";

  const nowIso = () => new Date().toISOString();

  /** @param {Object} index */
  const clone = (index) => JSON.parse(JSON.stringify(index));

  function createEmpty() {
    return { version: INDEX_VERSION, folders: [], notes: [] };
  }

  // Unknown versions must be rejected, never silently rewritten.
  function isSupported(index) {
    return (
      !!index &&
      index.version === INDEX_VERSION &&
      Array.isArray(index.folders) &&
      Array.isArray(index.notes)
    );
  }

  function newId() {
    return crypto.randomUUID();
  }

  function cleanName(name) {
    const trimmed = (name || "").trim();
    return trimmed.length > 0 ? trimmed : null;
  }

  function folderExists(index, folderId) {
    return index.folders.some((folder) => folder.id === folderId);
  }

  // --- Folders ---

  function addFolder(index, name, id = newId()) {
    const next = clone(index);
    const order = next.folders.reduce((max, folder) => Math.max(max, folder.order + 1), 0);
    next.folders.push({ id, name: cleanName(name) || DEFAULT_FOLDER_NAME, order });
    return next;
  }

  function renameFolder(index, folderId, name) {
    const cleaned = cleanName(name);
    const next = clone(index);
    const folder = next.folders.find((item) => item.id === folderId);
    if (folder && cleaned) folder.name = cleaned;
    return next;
  }

  // Delete a folder; its notes go to Trash.
  function deleteFolder(index, folderId) {
    const next = clone(index);
    next.folders = next.folders.filter((folder) => folder.id !== folderId);
    const deletedAt = nowIso();
    next.notes.forEach((note) => {
      if (note.folderId === folderId) {
        note.folderId = null;
        if (!note.trashed) {
          note.trashed = true;
          note.deletedAt = deletedAt;
        }
      }
    });
    return next;
  }

  // --- Notes ---

  function addNote(index, { id, name, folderId = null, createdAt, updatedAt }) {
    const next = clone(index);
    const stamp = nowIso();
    next.notes.push({
      id,
      name: cleanName(name) || defaultName(index),
      folderId: folderExists(next, folderId) ? folderId : null,
      trashed: false,
      deletedAt: null,
      createdAt: createdAt || stamp,
      updatedAt: updatedAt || stamp,
    });
    return next;
  }

  function renameNote(index, id, name) {
    const cleaned = cleanName(name);
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note && cleaned) note.name = cleaned;
    return next;
  }

  function moveNote(index, id, folderId) {
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note) {
      note.folderId = folderExists(next, folderId) ? folderId : null;
    }
    return next;
  }

  function trashNote(index, id) {
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note && !note.trashed) {
      note.trashed = true;
      note.deletedAt = nowIso();
    }
    return next;
  }

  // Un-trash a note; fall back to root if its folder is gone.
  function restoreNote(index, id) {
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note) {
      note.trashed = false;
      note.deletedAt = null;
      if (!folderExists(next, note.folderId)) note.folderId = null;
    }
    return next;
  }

  function removeNote(index, id) {
    const next = clone(index);
    next.notes = next.notes.filter((note) => note.id !== id);
    return next;
  }

  function touchNote(index, id, updatedAt = nowIso()) {
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note) note.updatedAt = updatedAt;
    return next;
  }

  // --- Queries ---

  /**
   * "untitled.md", then "untitled-2.md", "untitled-3.md", ...
   */
  function defaultName(index) {
    const taken = new Set(index.notes.map((note) => note.name));
    if (!taken.has(DEFAULT_NOTE_NAME)) return DEFAULT_NOTE_NAME;
    let counter = 2;
    while (taken.has("untitled-" + counter + ".md")) counter++;
    return "untitled-" + counter + ".md";
  }

  /**
   * Filter by note/folder name. Matching folders keep all their notes.
   */
  function filter(index, term) {
    const needle = (term || "").trim().toLowerCase();
    if (!needle) return clone(index);

    const next = clone(index);
    const matchingFolderIds = new Set(
      next.folders
        .filter((folder) => folder.name.toLowerCase().includes(needle))
        .map((folder) => folder.id),
    );
    next.notes = next.notes.filter(
      (note) => note.name.toLowerCase().includes(needle) || matchingFolderIds.has(note.folderId),
    );
    next.folders = next.folders.filter(
      (folder) =>
        matchingFolderIds.has(folder.id) || next.notes.some((note) => note.folderId === folder.id),
    );
    return next;
  }

  /**
   * Reconcile decrypted index entries against server rows.
   *
   * @param {Object} index
   * @param {Array<{id: string}>} serverNotes
   * @returns {{index: Object, orphanIds: string[], droppedIds: string[],
   *            changed: boolean}}
   */
  function reconcile(index, serverNotes) {
    const serverIds = new Set(serverNotes.map((note) => note.id));
    const indexIds = new Set(index.notes.map((note) => note.id));

    const droppedIds = index.notes
      .filter((note) => !serverIds.has(note.id))
      .map((note) => note.id);
    const orphanIds = serverNotes
      .filter((note) => !indexIds.has(note.id))
      .map((note) => note.id);

    const next = clone(index);
    next.notes = next.notes.filter((note) => serverIds.has(note.id));

    return { index: next, orphanIds, droppedIds, changed: droppedIds.length > 0 };
  }

  // Render input for the sidebar.
  function visibleTree(index) {
    const byName = (a, b) => a.name.localeCompare(b.name);
    const active = index.notes.filter((note) => !note.trashed);

    const folders = index.folders
      .slice()
      .sort((a, b) => a.order - b.order)
      .map((folder) => ({
        id: folder.id,
        name: folder.name,
        notes: active.filter((note) => note.folderId === folder.id).sort(byName),
      }));

    return {
      folders,
      rootNotes: active.filter((note) => note.folderId === null).sort(byName),
      trash: index.notes.filter((note) => note.trashed).sort(byName),
    };
  }

  window.NoteVaultIndex = {
    createEmpty,
    isSupported,
    newId,
    addFolder,
    renameFolder,
    deleteFolder,
    addNote,
    renameNote,
    moveNote,
    trashNote,
    restoreNote,
    removeNote,
    touchNote,
    defaultName,
    filter,
    reconcile,
    visibleTree,
  };
})();
