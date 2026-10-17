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

  /**
   * @typedef {Object} FolderEntry
   * @property {string} id
   * @property {string} name
   * @property {number} order Sidebar sort position; folders never nest.
   */

  /**
   * @typedef {Object} NoteEntry
   * @property {string} id Matches the server row's UUID.
   * @property {string} name Exists only inside the index ciphertext.
   * @property {?string} folderId null for a note at the root.
   * @property {boolean} trashed
   * @property {?string} deletedAt ISO stamp, set while trashed.
   * @property {string} createdAt ISO stamp.
   * @property {string} updatedAt ISO stamp.
   */

  /**
   * @typedef {Object} VaultIndexData
   * @property {number} version
   * @property {Array<FolderEntry>} folders
   * @property {Array<NoteEntry>} notes
   */

  const nowIso = () => new Date().toISOString();

  /**
   * Deep copy, so callers can mutate the result freely.
   *
   * Every exported operation returns a fresh index rather than editing in
   * place, which is what lets vault.js render optimistically and roll back to
   * the previous object when the save fails.
   *
   * @param {VaultIndexData} index
   * @returns {VaultIndexData}
   */
  const clone = (index) => JSON.parse(JSON.stringify(index));

  /** @returns {VaultIndexData} */
  function createEmpty() {
    return { version: INDEX_VERSION, folders: [], notes: [] };
  }

  /**
   * Whether a decrypted blob is an index this build can safely operate on.
   *
   * Unknown versions must be rejected, never silently rewritten: the caller
   * disables the vault instead, because saving a downgraded index over a newer
   * one would discard whatever the newer build recorded.
   *
   * @param {*} index Decrypted JSON, shape unverified.
   * @returns {boolean}
   */
  function isSupported(index) {
    return (
      !!index &&
      index.version === INDEX_VERSION &&
      Array.isArray(index.folders) &&
      Array.isArray(index.notes)
    );
  }

  /** @returns {string} A fresh folder id. Note ids come from the server row. */
  function newId() {
    return crypto.randomUUID();
  }

  /**
   * Trim a user-supplied name, collapsing "nothing usable" to null.
   *
   * @param {?string} name
   * @returns {?string} The trimmed name, or null when it was blank.
   */
  function cleanName(name) {
    const trimmed = (name || "").trim();
    return trimmed.length > 0 ? trimmed : null;
  }

  function folderExists(index, folderId) {
    return index.folders.some((folder) => folder.id === folderId);
  }

  // --- Folders ---

  /**
   * Add a folder at the end of the sidebar order.
   *
   * @param {VaultIndexData} index
   * @param {?string} name Falls back to DEFAULT_FOLDER_NAME when blank.
   * @param {string} [id] Caller-supplied, so the sidebar can mark the folder
   *   open before the save returns and rename it once the save lands.
   * @returns {VaultIndexData}
   */
  function addFolder(index, name, id = newId()) {
    const next = clone(index);
    const order = next.folders.reduce((max, folder) => Math.max(max, folder.order + 1), 0);
    next.folders.push({ id, name: cleanName(name) || DEFAULT_FOLDER_NAME, order });
    return next;
  }

  /**
   * Rename a folder. A blank name or an unknown id is a no-op.
   *
   * @param {VaultIndexData} index
   * @param {string} folderId
   * @param {?string} name
   * @returns {VaultIndexData}
   */
  function renameFolder(index, folderId, name) {
    const cleaned = cleanName(name);
    const next = clone(index);
    const folder = next.folders.find((item) => item.id === folderId);
    if (folder && cleaned) folder.name = cleaned;
    return next;
  }

  /**
   * Delete a folder and send the notes it held to Trash.
   *
   * Notes already in Trash keep their original deletedAt, so deleting the
   * folder around them does not restart their retention window.
   *
   * @param {VaultIndexData} index
   * @param {string} folderId
   * @returns {VaultIndexData}
   */
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

  /**
   * Add a note entry for a row that already exists on the server.
   *
   * `trashed`/`deletedAt` default to active; orphan recovery passes the server
   * row's trash state so a re-adopted note keeps it rather than silently
   * climbing back out of Trash. A folderId that no longer exists falls back to
   * the root.
   *
   * @param {VaultIndexData} index
   * @param {{id: string, name: ?string, folderId?: ?string, createdAt?: string,
   *   updatedAt?: string, trashed?: boolean, deletedAt?: ?string}} entry
   * @returns {VaultIndexData}
   */
  function addNote(
    index,
    { id, name, folderId = null, createdAt, updatedAt, trashed = false, deletedAt = null },
  ) {
    const next = clone(index);
    const stamp = nowIso();
    next.notes.push({
      id,
      name: cleanName(name) || defaultName(index),
      folderId: folderExists(next, folderId) ? folderId : null,
      trashed: !!trashed,
      deletedAt: trashed ? deletedAt || stamp : null,
      createdAt: createdAt || stamp,
      updatedAt: updatedAt || stamp,
    });
    return next;
  }

  /**
   * Rename a note. A blank name or an unknown id is a no-op.
   *
   * @param {VaultIndexData} index
   * @param {string} id
   * @param {?string} name
   * @returns {VaultIndexData}
   */
  function renameNote(index, id, name) {
    const cleaned = cleanName(name);
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note && cleaned) note.name = cleaned;
    return next;
  }

  /**
   * Move a note into a folder, or to the root when folderId is null or gone.
   *
   * @param {VaultIndexData} index
   * @param {string} id
   * @param {?string} folderId
   * @returns {VaultIndexData}
   */
  function moveNote(index, id, folderId) {
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note) {
      note.folderId = folderExists(next, folderId) ? folderId : null;
    }
    return next;
  }

  /**
   * Move a note to Trash, stamping deletedAt for the retention countdown.
   *
   * Already-trashed notes keep their original stamp, so re-trashing cannot
   * extend the window.
   *
   * @param {VaultIndexData} index
   * @param {string} id
   * @returns {VaultIndexData}
   */
  function trashNote(index, id) {
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note && !note.trashed) {
      note.trashed = true;
      note.deletedAt = nowIso();
    }
    return next;
  }

  /**
   * Take a note back out of Trash, falling back to the root if the folder it
   * came from was deleted in the meantime.
   *
   * @param {VaultIndexData} index
   * @param {string} id
   * @returns {VaultIndexData}
   */
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

  /**
   * Drop a note entry entirely. Pairs with deleting the server row.
   *
   * @param {VaultIndexData} index
   * @param {string} id
   * @returns {VaultIndexData}
   */
  function removeNote(index, id) {
    const next = clone(index);
    next.notes = next.notes.filter((note) => note.id !== id);
    return next;
  }

  /**
   * Record a new modification time, normally the one the server just returned.
   *
   * @param {VaultIndexData} index
   * @param {string} id
   * @param {string} [updatedAt] ISO stamp; defaults to now.
   * @returns {VaultIndexData}
   */
  function touchNote(index, id, updatedAt = nowIso()) {
    const next = clone(index);
    const note = next.notes.find((item) => item.id === id);
    if (note) note.updatedAt = updatedAt;
    return next;
  }

  // --- Queries ---

  /**
   * First unused default note name: "untitled.md", then "untitled-2.md", ...
   *
   * @param {VaultIndexData} index
   * @returns {string}
   */
  function defaultName(index) {
    const taken = new Set(index.notes.map((note) => note.name));
    if (!taken.has(DEFAULT_NOTE_NAME)) return DEFAULT_NOTE_NAME;
    let counter = 2;
    while (taken.has("untitled-" + counter + ".md")) counter++;
    return "untitled-" + counter + ".md";
  }

  /**
   * Narrow the index to entries matching a search term.
   *
   * A folder whose own name matches keeps all of its notes, so searching for a
   * folder shows its contents rather than an empty folder.
   *
   * @param {VaultIndexData} index
   * @param {?string} term Case-insensitive; blank returns a copy of everything.
   * @returns {VaultIndexData}
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
   * Reconcile decrypted index entries against the server's note rows.
   *
   * Rows are written before the index, so an interrupted save leaves rows with
   * no index entry (orphans, which vault.js decrypts and re-adopts) or entries
   * with no row (stale, dropped here). `changed` reports only the latter,
   * because that is the part this function already repaired.
   *
   * @param {VaultIndexData} index
   * @param {Array<{id: string}>} serverNotes
   * @returns {{index: VaultIndexData, orphanIds: string[], droppedIds: string[],
   *            changed: boolean}}
   */
  function reconcile(index, serverNotes) {
    const serverIds = new Set(serverNotes.map((note) => note.id));
    const indexIds = new Set(index.notes.map((note) => note.id));

    const droppedIds = index.notes.filter((note) => !serverIds.has(note.id)).map((note) => note.id);
    const orphanIds = serverNotes.filter((note) => !indexIds.has(note.id)).map((note) => note.id);

    const next = clone(index);
    next.notes = next.notes.filter((note) => serverIds.has(note.id));

    return { index: next, orphanIds, droppedIds, changed: droppedIds.length > 0 };
  }

  /**
   * Ids whose index trash state disagrees with the server's `trashed_at`.
   *
   * The index is authoritative: it holds the user's actual intent, so a
   * mismatch means an interrupted trash/restore (or a row predating the
   * server-side flag) and the row is what gets corrected. vault.js repairs
   * each direction with one bulk call on load.
   *
   * @param {VaultIndexData} index
   * @param {Array<{id: string, trashed_at: ?string}>} serverNotes
   * @returns {{trash: string[], restore: string[]}} Ids to flag on the server,
   *   and ids whose flag to clear.
   */
  function trashFlagDrift(index, serverNotes) {
    const flaggedOnServer = new Set(
      serverNotes.filter((note) => note.trashed_at).map((note) => note.id),
    );
    const trash = [];
    const restore = [];
    index.notes.forEach((note) => {
      const flagged = flaggedOnServer.has(note.id);
      if (note.trashed && !flagged) trash.push(note.id);
      if (!note.trashed && flagged) restore.push(note.id);
    });
    return { trash, restore };
  }

  /**
   * Shape the index for the sidebar: folders in their stored order, notes
   * alphabetical within each section, and Trash as its own flat list.
   *
   * @param {VaultIndexData} index
   * @returns {{folders: Array<{id: string, name: string, notes: Array<NoteEntry>}>,
   *   rootNotes: Array<NoteEntry>, trash: Array<NoteEntry>}}
   */
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
    trashFlagDrift,
    visibleTree,
  };
})();
