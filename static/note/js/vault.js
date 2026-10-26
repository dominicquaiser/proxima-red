/**
 * @fileoverview Controller for the encrypted note vault page.
 *
 * Note content and the encrypted index are saved separately. Content writes
 * and permanent deletions precede index writes; reconciliation repairs drift
 * on load. Trash and restore use their own ordering to avoid premature deletion.
 */
(function () {
  "use strict";

  const DEFAULT_NOTE_NAME = "untitled.md";
  const DEFAULT_FOLDER_NAME = "folder";
  const HIDDEN_CLASS = "hidden";
  const NOTE_DIRTY_CLASS = "note-dirty";
  const SIDEBAR_COLLAPSED_CLASS = "sidebar-collapsed";
  const MOBILE_SIDEBAR_QUERY = "(max-width: 900px)";
  const MENU_OFFSET_PX = 4;
  const VIEWPORT_GUTTER_PX = 8;
  const UNREADABLE_ID_PREFIX_LENGTH = 8;

  document.addEventListener("DOMContentLoaded", function () {
    const main = document.getElementById("main-content");
    const textarea = document.getElementById("note-content");
    const rail = document.querySelector(".rail");
    const treeEl = document.getElementById("vault-tree");
    if (!main || !textarea || !rail || !treeEl) return;

    const indexUrl = main.dataset.indexUrl;
    const notesUrl = main.dataset.notesUrl;
    const noteUrlBase = main.dataset.noteUrlBase;
    const noteDeleteUrlBase = main.dataset.noteDeleteUrlBase;
    const noteTrashUrl = main.dataset.noteTrashUrl;
    const trashRetentionDays = main.dataset.trashRetentionDays;
    const dummyNoteId = main.dataset.dummyNoteId;

    const crumbEl = document.getElementById("vault-crumb");
    const searchInput = document.getElementById("vault-search");
    const ctxMenu = document.getElementById("ctx-menu");
    const saveBtn = document.getElementById("save-note-btn");
    const sessionModal = document.getElementById("session-modal");
    const sessionDismissBtn = document.getElementById("session-dismiss-btn");
    const sessionReloadBtn = document.getElementById("session-reload-btn");

    const Index = window.NoteVaultIndex;

    let masterKey = null;
    let index = Index.createEmpty();
    let readOnly = false;
    let permanentReadOnly = false;
    let vaultLoaded = false;
    let currentNoteId = null; // null means the buffer has no server row yet.
    let currentName = DEFAULT_NOTE_NAME;
    let lastSavedValue = "";
    let isDirty = false;
    let isSaving = false;
    let searchTerm = "";

    // Rows that cannot decrypt stay outside the index and can only be deleted.
    const unreadableIds = new Set();
    const openFolders = new Set();
    let trashOpen = false;

    /**
     * @param {string} id Note UUID.
     * @returns {string} Note read/write URL.
     */
    const noteUrl = (id) => noteUrlBase.replace(dummyNoteId, id);
    /**
     * @param {string} id Note UUID.
     * @returns {string} Permanent-deletion URL.
     */
    const noteDeleteUrl = (id) => noteDeleteUrlBase.replace(dummyNoteId, id);

    const core = window.NoteEditorCore.init({
      textarea,
      preview: document.getElementById("note-preview"),
      tabEdit: document.getElementById("tab-edit"),
      tabPreview: document.getElementById("tab-preview"),
      counter: document.getElementById("note-meta"),
      caret: document.getElementById("note-caret"),
      editor: main,
      rail,
    });

    window.NoteShare.init({
      popover: document.getElementById("share-pop"),
      menu: document.getElementById("share-menu"),
      result: document.getElementById("share-result"),
      linkInput: document.getElementById("share-link"),
      copyBtn: document.getElementById("copy-link-btn"),
      encryptedBtn: document.getElementById("share-encrypted-btn"),
      plainBtn: document.getElementById("share-plain-btn"),
      editableBtn: document.getElementById("share-editable-btn"),
      expiryName: "note-expiry",
      createUrl: main.dataset.createUrl,
      retrieveUrlBase: main.dataset.retrieveUrlBase,
      liveCreateUrl: main.dataset.liveCreateUrl,
      liveUrlBase: main.dataset.liveUrlBase,
      dummyNoteId,
      getText: core.getValue,
      noteTooLarge: core.noteTooLarge,
    });

    /** @param {boolean} dirty Whether the buffer differs from its saved content. */
    const setDirty = (dirty) => {
      isDirty = dirty;
      document.body.classList.toggle(NOTE_DIRTY_CLASS, dirty);
    };

    core.onInput(() => setDirty(core.getValue() !== lastSavedValue));

    window.addEventListener("beforeunload", (event) => {
      if (!isDirty) return;
      event.preventDefault();
      event.returnValue = "";
    });

    /** @returns {boolean} Whether switching buffers may discard unsaved edits. */
    const confirmDiscard = () =>
      !isDirty || window.confirm("Discard unsaved changes to this note?");

    /** Repaint the breadcrumb as "/folder/name" for the open buffer. */
    const renderCrumb = () => {
      crumbEl.replaceChildren();
      const currentEntry = index.notes.find((note) => note.id === currentNoteId);
      const folder = index.folders.find(
        (folderItem) => folderItem.id === (currentEntry || {}).folderId,
      );
      const directory = document.createElement("span");
      directory.className = "topbar__crumb-dir";
      directory.textContent = folder ? "/" + folder.name + "/" : "/";
      crumbEl.appendChild(directory);
      crumbEl.appendChild(document.createTextNode(currentName));
    };

    /**
     * Build a decorative icon hidden from assistive technology.
     *
     * @param {string} name Suffix of the `nicon--` CSS class.
     * @param {string} [extraClass] Additional CSS classes.
     * @returns {HTMLSpanElement} Icon element.
     */
    const icon = (name, extraClass) => {
      const span = document.createElement("span");
      span.className = "nicon nicon--" + name + (extraClass ? " " + extraClass : "");
      span.setAttribute("aria-hidden", "true");
      return span;
    };

    /**
     * Build the "..." button that opens a row's context menu.
     *
     * @param {"note"|"trash"|"folder"|"unreadable"} kind Context-menu variant.
     * @param {string} id Note or folder UUID.
     * @returns {HTMLButtonElement} Row action button.
     */
    const rowActionsButton = (kind, id) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "tree__row-actions";
      button.title = "Actions";
      button.dataset.ctxKind = kind;
      button.dataset.ctxId = id;
      button.appendChild(icon("dots-three"));
      return button;
    };

    /**
     * Build one note row for the sidebar.
     *
     * @param {NoteEntry} note Index entry.
     * @param {"note"|"trash"} kind Which section the row is being built for.
     * @returns {HTMLButtonElement} Sidebar note row.
     */
    const buildFileRow = (note, kind) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "tree__row tree__file";
      row.dataset.noteId = note.id;
      if (note.id === currentNoteId) row.classList.add("tree__file--active");
      row.appendChild(icon("file", "tree__icon"));
      const name = document.createElement("span");
      name.className = "tree__name";
      name.textContent = note.name;
      row.appendChild(name);
      row.appendChild(rowActionsButton(kind, note.id));
      return row;
    };

    /**
     * Build a deletion-only row, using an ID prefix when the name is unreadable.
     *
     * @param {string} id UUID of the unreadable server row.
     * @returns {HTMLButtonElement} Sidebar row for an unreadable note.
     */
    const buildUnreadableRow = (id) => {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "tree__row tree__file tree__file--unreadable";
      row.dataset.unreadable = "1";
      row.title = "This note could not be decrypted with the current key.";
      row.appendChild(icon("file", "tree__icon"));
      const name = document.createElement("span");
      name.className = "tree__name";
      name.textContent = "unreadable note (" + id.slice(0, UNREADABLE_ID_PREFIX_LENGTH) + "…)";
      row.appendChild(name);
      row.appendChild(rowActionsButton("unreadable", id));
      return row;
    };

    /**
     * Build a collapsible folder section.
     *
     * `openFolders` preserves expanded sections across sidebar rebuilds.
     *
     * @param {{id: string, name: string, notes: NoteEntry[]}} folder Visible folder.
     * @returns {HTMLDetailsElement} Folder section and its note rows.
     */
    const buildFolderDetails = (folder) => {
      const details = document.createElement("details");
      details.dataset.folderId = folder.id;
      if (openFolders.has(folder.id)) details.open = true;
      details.addEventListener("toggle", () => {
        if (details.open) openFolders.add(folder.id);
        else openFolders.delete(folder.id);
      });

      const summary = document.createElement("summary");
      summary.className = "tree__row";
      summary.appendChild(icon("caret-right", "tree__chev"));
      summary.appendChild(icon("folder", "tree__icon tree__icon--folder tree__icon--closed"));
      summary.appendChild(icon("folder-open", "tree__icon tree__icon--folder tree__icon--open"));
      const name = document.createElement("span");
      name.className = "tree__name";
      name.textContent = folder.name;
      summary.appendChild(name);
      summary.appendChild(rowActionsButton("folder", folder.id));
      details.appendChild(summary);

      folder.notes.forEach((note) => details.appendChild(buildFileRow(note, "note")));
      return details;
    };

    /**
     * Build the permanent Trash section, preserving its expanded state.
     *
     * @param {NoteEntry[]} notes Trashed notes matching the current search.
     * @returns {HTMLDetailsElement} Trash section, including when empty.
     */
    const buildTrashDetails = (notes) => {
      const trashDetails = document.createElement("details");
      trashDetails.dataset.trash = "1";
      if (trashOpen) trashDetails.open = true;
      trashDetails.addEventListener("toggle", () => {
        trashOpen = trashDetails.open;
      });
      const trashSummary = document.createElement("summary");
      trashSummary.className = "tree__row";
      trashSummary.title =
        "Items in Trash are deleted permanently after " + trashRetentionDays + " days.";
      trashSummary.appendChild(icon("caret-right", "tree__chev"));
      trashSummary.appendChild(icon("trash", "tree__icon tree__icon--trash"));
      const trashName = document.createElement("span");
      trashName.className = "tree__name";
      trashName.textContent = "Trash";
      trashSummary.appendChild(trashName);
      trashDetails.appendChild(trashSummary);
      notes.forEach((note) => trashDetails.appendChild(buildFileRow(note, "trash")));
      return trashDetails;
    };

    /** Rebuild the sidebar from the index, search term, and unreadable rows. */
    const renderTree = () => {
      const tree = Index.visibleTree(Index.filter(index, searchTerm));
      treeEl.replaceChildren();

      tree.folders.forEach((folder) => treeEl.appendChild(buildFolderDetails(folder)));
      tree.rootNotes.forEach((note) => treeEl.appendChild(buildFileRow(note, "note")));
      unreadableIds.forEach((id) => treeEl.appendChild(buildUnreadableRow(id)));
      treeEl.appendChild(buildTrashDetails(tree.trash));

      if (tree.folders.length === 0 && tree.rootNotes.length === 0 && unreadableIds.size === 0) {
        const empty = document.createElement("p");
        empty.className = "tree__empty";
        empty.textContent = searchTerm ? "No notes match the search." : "No notes yet.";
        treeEl.appendChild(empty);
      }

      renderCrumb();
    };

    /**
     * Suspend writes. A message also prevents unlocking from re-enabling writes.
     *
     * @param {string} [message] Error toast; omit for a recoverable session lock.
     */
    const disableVault = (message) => {
      readOnly = true;
      if (message) permanentReadOnly = true;
      if (saveBtn) saveBtn.disabled = true;
      if (message) window.Notify.show(message, "error");
    };

    /**
     * Show the sign-in prompt while preserving the editor buffer.
     *
     * @param {"retry"|"reload"} mode Retry with the buffer or reload an unloaded vault.
     */
    const showSessionExpired = (mode) => {
      if (!sessionModal) {
        window.Notify.show("Your session timed out. Sign in again to save your work.", "error");
        return;
      }
      sessionModal.querySelectorAll("[data-session-mode]").forEach((el) => {
        el.classList.toggle(HIDDEN_CLASS, el.dataset.sessionMode !== mode);
      });
      if (sessionDismissBtn) {
        sessionDismissBtn.classList.toggle(HIDDEN_CLASS, mode !== "retry");
      }
      if (sessionReloadBtn) {
        sessionReloadBtn.classList.toggle(HIDDEN_CLASS, mode !== "reload");
      }
      sessionModal.classList.remove(HIDDEN_CLASS);
    };

    /** Dismiss the sign-in prompt without changing the vault's lock state. */
    const hideSessionExpired = () => {
      if (sessionModal) sessionModal.classList.add(HIDDEN_CLASS);
    };

    /**
     * Handle session errors for each response, including both writes in a save.
     *
     * A 401 shows the sign-in modal; a 423 uses VaultSession's password prompt.
     * Other statuses dismiss the sign-in modal. Callers skip their own error
     * reporting when this returns true.
     *
     * @param {Response} response Server reply to inspect.
     * @param {"retry"|"reload"} mode Sign-in modal actions to offer.
     * @returns {boolean} True when the session or tool access has expired.
     */
    const sessionIsGone = (response, mode) => {
      if (response.status === 423) return true;
      if (response.status === 401) {
        // Http also emits "vault-session-error" so VaultSession drops cached keys.
        showSessionExpired(mode);
        return true;
      }
      hideSessionExpired();
      return false;
    };

    if (sessionDismissBtn) {
      sessionDismissBtn.addEventListener("click", hideSessionExpired);
    }
    if (sessionReloadBtn) {
      sessionReloadBtn.addEventListener("click", () => window.location.reload());
    }

    /**
     * Encrypt and save the current index.
     *
     * Failures are reported and returned as false so callers can roll back.
     *
     * @returns {Promise<boolean>} True when the server accepted the index.
     */
    const persistIndex = async () => {
      if (!masterKey || readOnly) return false;
      try {
        if (!window.Http.getCsrfToken()) {
          throw new Error("Missing CSRF token");
        }
        const payload = await window.AuthCrypto.encryptAccountData(index, masterKey);
        const { response, result } = await window.Http.postForm(indexUrl, {
          encrypted_data: payload.encryptedData,
          iv: payload.iv,
        });
        if (sessionIsGone(response, "retry")) return false;
        if (!response.ok || !result.success) {
          throw new Error(result.error || `HTTP ${response.status}`);
        }
        return true;
      } catch (error) {
        console.error("Failed to persist vault index:", error);
        window.Notify.show("We could not save your vault. Please try again.", "error");
        return false;
      }
    };

    /**
     * Render a new index immediately and restore the previous one if saving fails.
     *
     * @param {function(VaultIndexData): VaultIndexData} mutate Must leave its input unchanged.
     * @returns {Promise<boolean>} True when the change was persisted.
     */
    const commitIndexChange = async (mutate) => {
      const previousIndex = index;
      index = mutate(index);
      renderTree();

      const persisted = await persistIndex();
      if (!persisted) {
        index = previousIndex;
        renderTree();
      }
      return persisted;
    };

    /** Reset to an empty buffer with an unused default name and no server row. */
    const startNewBuffer = () => {
      currentNoteId = null;
      currentName = Index.defaultName(index);
      core.setValue("");
      lastSavedValue = "";
      setDirty(false);
      core.showEdit();
      renderTree();
    };

    /**
     * Load, decrypt, and open a note, after confirming any unsaved changes.
     *
     * Failed requests or decryption leave the current buffer intact.
     *
     * @param {string} id UUID of the note to open.
     * @returns {Promise<void>} Resolves after opening or reporting a failure.
     */
    const openNote = async (id) => {
      if (id === currentNoteId) return;
      if (!confirmDiscard()) return;

      let body;
      try {
        const { response, result } = await window.Http.getJson(noteUrl(id));
        if (sessionIsGone(response, "retry")) return;
        if (!response.ok || !result.success) {
          throw new Error(result.error || `HTTP ${response.status}`);
        }
        body = result;
      } catch (error) {
        console.error("Failed to load note:", error);
        window.Notify.show("Could not load the note. Please try again.", "error");
        return;
      }

      let text;
      try {
        text = await window.PasswordCrypto.decryptPassword(body.content, body.iv, masterKey);
      } catch (error) {
        console.error("Failed to decrypt note:", error);
        window.Notify.show(
          "Could not decrypt the note with the current key. It may have been " +
            "written under a previous password.",
          "error",
        );
        return;
      }

      const entry = index.notes.find((note) => note.id === id);
      currentNoteId = id;
      currentName = entry ? entry.name : DEFAULT_NOTE_NAME;
      core.setValue(text);
      lastSavedValue = text;
      setDirty(false);
      core.showEdit();
      renderTree();
    };

    /**
     * Write the encrypted row before committing its index entry.
     *
     * @param {{encryptedData: string, iv: string}} payload Encrypted buffer.
     * @returns {Promise<?{isNew: boolean, result: Object}>} Saved row metadata,
     *   or null when session access expired.
     * @throws {Error} If the request fails or the server rejects the row.
     */
    const persistNoteRow = async (payload) => {
      const isNew = currentNoteId === null;
      const url = isNew ? notesUrl : noteUrl(currentNoteId);
      const { response, result } = await window.Http.postForm(url, {
        content: payload.encryptedData,
        iv: payload.iv,
      });
      if (sessionIsGone(response, "retry")) return null;
      if (!response.ok || !result.success) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }
      if (isNew) currentNoteId = result.note_id;
      return { isNew, result };
    };

    /**
     * Add a saved row to the index or update its modification timestamp.
     *
     * @param {{isNew: boolean, result: Object}} savedRow Metadata from persistNoteRow.
     * @returns {Promise<boolean>} Whether the index was persisted.
     */
    const indexSavedNote = ({ isNew, result }) =>
      commitIndexChange((idx) =>
        isNew
          ? Index.addNote(idx, {
              id: result.note_id,
              name: currentName,
              createdAt: result.created_at,
              updatedAt: result.updated_at,
            })
          : Index.touchNote(idx, currentNoteId, result.updated_at),
      );

    /**
     * Encrypt and save the buffer, creating the server row on first save.
     *
     * A successful content write marks the buffer clean even if indexing fails.
     * Orphan recovery re-adopts unindexed rows on load; the success toast requires
     * both writes to succeed.
     *
     * @returns {Promise<void>} Resolves after saving or reporting a failure.
     */
    const saveNote = async () => {
      if (!masterKey || readOnly) {
        window.Notify.show("Secure session missing. Please sign in again.", "error");
        return;
      }
      if (isSaving) return;

      const text = core.getValue();
      if (!text.trim()) {
        window.Notify.show("Nothing to save yet - the note is empty.", "error");
        return;
      }
      if (core.noteTooLarge()) return;

      isSaving = true;
      try {
        const payload = await window.CryptoCore.encryptWithKey(text, masterKey);
        const savedRow = await persistNoteRow(payload);
        if (!savedRow) return;
        const indexed = await indexSavedNote(savedRow);

        lastSavedValue = text;
        setDirty(false);
        if (!indexed) return;
        window.Notify.show("Note saved to your vault.", "success");
      } catch (error) {
        console.error("Failed to save note:", error);
        window.Notify.show(error.message || "Failed to save the note.", "error");
      } finally {
        isSaving = false;
      }
    };

    /**
     * Record Trash state on the server rows.
     *
     * The encrypted index controls the sidebar; server flags let the expiry
     * sweep enforce retention. Bulk updates use one rate-limited write per folder.
     *
     * @param {string[]} ids Note UUIDs; an empty list succeeds without a request.
     * @param {boolean} trashed Set the deletion timestamp, or clear it to restore.
     * @returns {Promise<boolean>} True when the server recorded the change.
     */
    const setTrashed = async (ids, trashed) => {
      if (ids.length === 0) return true;
      try {
        const { response, result } = await window.Http.postForm(noteTrashUrl, {
          ids,
          trashed,
        });
        if (sessionIsGone(response, "retry")) return false;
        if (!response.ok || !result.success) {
          throw new Error(result.error || `HTTP ${response.status}`);
        }
        return true;
      } catch (error) {
        console.error("Failed to update Trash state:", error);
        window.Notify.show("Could not update Trash. Please try again.", "error");
        return false;
      }
    };

    /**
     * Delete a note permanently: the server row first, then its index entry.
     *
     * Unreadable rows have no index entry. Deleting the open note resets its buffer.
     *
     * @param {string} id Note UUID.
     * @returns {Promise<void>} Resolves after deletion or reporting a failure.
     */
    const deleteNoteForever = async (id) => {
      try {
        const { response, result } = await window.Http.postForm(noteDeleteUrl(id), {});
        if (sessionIsGone(response, "retry")) return;
        if (!response.ok || !result.success) {
          throw new Error(result.error || `HTTP ${response.status}`);
        }
      } catch (error) {
        console.error("Failed to delete note:", error);
        window.Notify.show("Could not delete the note. Please try again.", "error");
        return;
      }

      if (unreadableIds.delete(id)) {
        renderTree();
      } else {
        await commitIndexChange((idx) => Index.removeNote(idx, id));
      }
      if (currentNoteId === id) {
        setDirty(false);
        startNewBuffer();
      }
      window.Notify.show("Note deleted.", "success");
    };

    /**
     * Swap a row's label for an inline text input.
     *
     * Enter and blur commit once; Escape, blank names, and unchanged names cancel.
     *
     * @param {Element} row Row or summary holding a `.tree__name`.
     * @param {string} initialValue Existing note or folder name.
     * @param {function(string): void} onCommit Receives the trimmed new name.
     */
    const startRename = (row, initialValue, onCommit) => {
      const nameEl = row.querySelector(".tree__name");
      if (!nameEl) return;

      const input = document.createElement("input");
      input.type = "text";
      input.className = "tree__rename-input";
      input.value = initialValue;
      input.setAttribute("aria-label", "New name");
      nameEl.replaceWith(input);
      input.focus();
      input.select();

      let finished = false;
      const finish = (commit) => {
        if (finished) return;
        finished = true;
        const value = input.value.trim();
        if (commit && value && value !== initialValue) {
          onCommit(value);
        } else {
          renderTree();
        }
      };

      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          finish(true);
        } else if (event.key === "Escape") {
          event.preventDefault();
          finish(false);
        }
      });
      input.addEventListener("blur", () => finish(true));
      // Avoid opening/toggling the row beneath the input.
      input.addEventListener("click", (event) => event.stopPropagation());
    };

    /** @param {string} id UUID of the note to rename inline. */
    const renameNote = (id) => {
      const row = treeEl.querySelector('[data-note-id="' + id + '"]');
      const entry = index.notes.find((note) => note.id === id);
      if (!row || !entry) return;
      startRename(row, entry.name, (value) => {
        commitIndexChange((idx) => Index.renameNote(idx, id, value));
        if (id === currentNoteId) currentName = value;
      });
    };

    /** @param {string} id UUID of the folder to rename inline. */
    const renameFolder = (id) => {
      const details = treeEl.querySelector('[data-folder-id="' + id + '"]');
      const folder = index.folders.find((item) => item.id === id);
      if (!details || !folder) return;
      startRename(details.querySelector("summary"), folder.name, (value) => {
        commitIndexChange((idx) => Index.renameFolder(idx, id, value));
      });
    };

    let armedDelete = null;

    /** Hide and empty the context menu, disarming any pending delete. */
    const closeCtxMenu = () => {
      ctxMenu.classList.add(HIDDEN_CLASS);
      ctxMenu.replaceChildren();
      armedDelete = null;
      treeEl
        .querySelectorAll('[aria-expanded="true"]')
        .forEach((el) => el.setAttribute("aria-expanded", "false"));
    };

    /**
     * Build one context-menu entry.
     *
     * @param {string} label Visible action label.
     * @param {string} iconName Decorative icon name.
     * @param {function(MouseEvent): void} onClick Action handler.
     * @param {string} [extraClass] Additional CSS classes.
     * @returns {HTMLButtonElement} Menu item with its click handler attached.
     */
    const ctxItem = (label, iconName, onClick, extraClass) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "ctx-menu__item" + (extraClass ? " " + extraClass : "");
      button.setAttribute("role", "menuitem");
      button.appendChild(icon(iconName));
      button.appendChild(document.createTextNode(label));
      button.addEventListener("click", onClick);
      return button;
    };

    /**
     * Build a delete entry that requires a second click to confirm.
     *
     * Closing the menu clears the pending confirmation.
     *
     * @param {string} label Initial action label.
     * @param {function(): void} onConfirm Action to run after the second click.
     * @returns {HTMLButtonElement} Two-click deletion item.
     */
    const ctxDeleteItem = (label, onConfirm) => {
      const button = ctxItem(
        label,
        "trash",
        (event) => {
          event.stopPropagation();
          if (armedDelete === button) {
            closeCtxMenu();
            onConfirm();
            return;
          }
          armedDelete = button;
          button.classList.add("ctx-menu__item--armed");
          button.replaceChildren(icon("trash"), document.createTextNode("Click again to confirm"));
        },
        "ctx-menu__item--danger",
      );
      return button;
    };

    /**
     * Offer move destinations, omitting the note's current folder.
     *
     * @param {string} noteId UUID of the note to move.
     */
    const showMoveTargets = (noteId) => {
      ctxMenu.replaceChildren();
      const label = document.createElement("div");
      label.className = "ctx-menu__label";
      label.textContent = "Move to";
      ctxMenu.appendChild(label);

      const entry = index.notes.find((note) => note.id === noteId);
      const targets = [{ id: null, name: "/ (root)" }].concat(
        index.folders.slice().sort((a, b) => a.order - b.order),
      );
      targets.forEach((target) => {
        if (entry && target.id === entry.folderId) return;
        ctxMenu.appendChild(
          ctxItem(target.name, target.id === null ? "caret-right" : "folder", () => {
            closeCtxMenu();
            if (target.id !== null) openFolders.add(target.id);
            commitIndexChange((idx) => Index.moveNote(idx, noteId, target.id));
          }),
        );
      });
    };

    /**
     * @param {string} id UUID of the note to move to Trash.
     * @returns {Promise<void>} Resolves after index and server Trash updates are attempted.
     */
    const moveNoteToTrash = async (id) => {
      if (id === currentNoteId) {
        setDirty(false);
        startNewBuffer();
      }
      // Index first, then the flag. The reverse order could leave a note the
      // user still sees as active carrying a deletion flag.
      if (await commitIndexChange((idx) => Index.trashNote(idx, id))) {
        await setTrashed([id], true);
      }
    };

    /**
     * @param {string} id UUID of the note to restore.
     * @returns {Promise<void>} Resolves after attempting restoration or reporting a failure.
     */
    const restoreTrashedNote = async (id) => {
      // Clear the flag first: a note still in Trash is recoverable, while one
      // the server still plans to delete is not.
      if (await setTrashed([id], false)) {
        await commitIndexChange((idx) => Index.restoreNote(idx, id));
      }
    };

    /**
     * @param {string} id Folder UUID; its active notes move to Trash.
     * @returns {Promise<void>} Resolves after attempting deletion or reporting a failure.
     */
    const deleteFolderToTrash = async (id) => {
      // Collect active note IDs before the folder is removed from the index.
      const noteIdsToTrash = index.notes
        .filter((note) => note.folderId === id && !note.trashed)
        .map((note) => note.id);
      if (await commitIndexChange((idx) => Index.deleteFolder(idx, id))) {
        await setTrashed(noteIdsToTrash, true);
      }
    };

    /** @param {string} id UUID of the active note whose actions to display. */
    const buildNoteCtxMenu = (id) => {
      ctxMenu.appendChild(
        ctxItem("Rename", "pencil-simple-line", () => {
          closeCtxMenu();
          renameNote(id);
        }),
      );
      ctxMenu.appendChild(
        ctxItem("Move to…", "folder-open", (event) => {
          event.stopPropagation();
          showMoveTargets(id);
        }),
      );
      const divider = document.createElement("div");
      divider.className = "ctx-menu__divider";
      ctxMenu.appendChild(divider);
      ctxMenu.appendChild(
        ctxItem(
          "Move to Trash",
          "trash",
          () => {
            closeCtxMenu();
            moveNoteToTrash(id);
          },
          "ctx-menu__item--danger",
        ),
      );
    };

    /** @param {string} id UUID of the trashed note whose actions to display. */
    const buildTrashCtxMenu = (id) => {
      ctxMenu.appendChild(
        ctxItem("Restore", "arrow-counter-clockwise", () => {
          closeCtxMenu();
          restoreTrashedNote(id);
        }),
      );
      ctxMenu.appendChild(ctxDeleteItem("Delete forever", () => deleteNoteForever(id)));
    };

    /** @param {string} id UUID of the folder whose actions to display. */
    const buildFolderCtxMenu = (id) => {
      ctxMenu.appendChild(
        ctxItem("Rename", "pencil-simple-line", () => {
          closeCtxMenu();
          renameFolder(id);
        }),
      );
      ctxMenu.appendChild(ctxDeleteItem("Delete folder", () => deleteFolderToTrash(id)));
    };

    /**
     * Build and position the context menu for one row.
     *
     * @param {HTMLElement} anchor Row action button used for menu positioning.
     * @param {"note"|"trash"|"folder"|"unreadable"} kind Context-menu variant.
     * @param {string} id Note or folder UUID.
     */
    const openCtxMenu = (anchor, kind, id) => {
      closeCtxMenu();
      anchor.setAttribute("aria-expanded", "true");

      if (kind === "note") buildNoteCtxMenu(id);
      else if (kind === "trash") buildTrashCtxMenu(id);
      else if (kind === "unreadable") {
        ctxMenu.appendChild(ctxDeleteItem("Delete forever", () => deleteNoteForever(id)));
      } else if (kind === "folder") buildFolderCtxMenu(id);

      // Position beside the anchor, clamped to the viewport.
      const rect = anchor.getBoundingClientRect();
      ctxMenu.classList.remove(HIDDEN_CLASS);
      const menuRect = ctxMenu.getBoundingClientRect();
      const left = Math.min(
        rect.right + MENU_OFFSET_PX,
        window.innerWidth - menuRect.width - VIEWPORT_GUTTER_PX,
      );
      const top = Math.min(rect.top, window.innerHeight - menuRect.height - VIEWPORT_GUTTER_PX);
      ctxMenu.style.left = left + "px";
      ctxMenu.style.top = top + "px";
    };

    document.addEventListener("click", (event) => {
      if (!ctxMenu.classList.contains(HIDDEN_CLASS) && !ctxMenu.contains(event.target)) {
        closeCtxMenu();
      }
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeCtxMenu();
    });

    treeEl.addEventListener("click", (event) => {
      const actions = event.target.closest(".tree__row-actions");
      if (actions) {
        // Inside a <summary>, this click would also toggle the folder.
        event.preventDefault();
        event.stopPropagation();
        openCtxMenu(actions, actions.dataset.ctxKind, actions.dataset.ctxId);
        return;
      }

      const fileRow = event.target.closest(".tree__file");
      if (fileRow) {
        if (fileRow.dataset.unreadable) return;
        const entry = index.notes.find((note) => note.id === fileRow.dataset.noteId);
        if (entry && entry.trashed) return;
        openNote(fileRow.dataset.noteId);
      }
    });

    document.getElementById("new-note-btn").addEventListener("click", () => {
      if (!confirmDiscard()) return;
      startNewBuffer();
    });

    document.getElementById("new-folder-btn").addEventListener("click", async () => {
      if (readOnly) return;
      const folderId = Index.newId();
      openFolders.add(folderId);
      const persisted = await commitIndexChange((idx) =>
        Index.addFolder(idx, DEFAULT_FOLDER_NAME, folderId),
      );
      if (persisted) renameFolder(folderId);
    });

    searchInput.addEventListener("input", () => {
      searchTerm = searchInput.value;
      renderTree();
    });

    saveBtn.addEventListener("click", saveNote);
    document.addEventListener("keydown", (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        saveNote();
      }
    });

    /** @param {boolean} collapsed Whether to hide the sidebar. */
    const setCollapsed = (collapsed) => {
      document.body.classList.toggle(SIDEBAR_COLLAPSED_CLASS, collapsed);
    };
    document
      .getElementById("sidebar-collapse-btn")
      .addEventListener("click", () => setCollapsed(true));
    document
      .getElementById("sidebar-open-btn")
      .addEventListener("click", () => setCollapsed(false));
    if (window.matchMedia(MOBILE_SIDEBAR_QUERY).matches) setCollapsed(true);

    /**
     * Load and decrypt the index, rejecting results from an outdated session key.
     *
     * @returns {Promise<boolean>} Whether the index is ready for reconciliation.
     */
    const loadVaultIndex = async () => {
      const loadKey = masterKey;
      let blob;
      try {
        const { response, result } = await window.Http.getJson(indexUrl);
        if (loadKey !== masterKey) return false;
        // An unloaded vault needs a reload after sign-in.
        if (sessionIsGone(response, "reload")) {
          disableVault();
          return false;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        if (!result.success) throw new Error(result.error || `HTTP ${response.status}`);
        blob = result;
      } catch (error) {
        console.error("Failed to load vault index:", error);
        disableVault("Could not load your vault. Please reload the page.");
        return false;
      }

      if (blob.encrypted_data && blob.iv) {
        try {
          const decrypted = await window.AuthCrypto.decryptAccountData(
            blob.encrypted_data,
            blob.iv,
            loadKey,
          );
          if (loadKey !== masterKey) return false;
          if (!Index.isSupported(decrypted)) {
            throw new Error("Unsupported vault index format");
          }
          index = decrypted;
        } catch (error) {
          console.error("Failed to decrypt vault index:", error);
          disableVault("Could not decrypt your vault index. Reload the page or sign in again.");
          return false;
        }
      }
      return true;
    };

    /**
     * List server rows for reconciliation; failures suspend vault writes.
     *
     * @returns {Promise<?Object[]>} Server metadata, or null if the list is unavailable.
     */
    const loadVaultRows = async () => {
      try {
        const { response, result } = await window.Http.getJson(notesUrl);
        if (sessionIsGone(response, "reload")) {
          disableVault();
          return null;
        }
        if (!response.ok || !result.success) throw new Error(`HTTP ${response.status}`);
        return result.notes || [];
      } catch (error) {
        console.error("Failed to list vault notes:", error);
        disableVault("Could not load your notes. Please reload the page.");
        return null;
      }
    };

    /**
     * Decrypt and index orphan rows, leaving failures visible as unreadable rows.
     *
     * @param {string[]} orphanIds Server row UUIDs missing from the index.
     * @returns {Promise<?boolean>} Whether any rows were recovered; null when
     *   session access expires or the key changes during recovery.
     */
    const recoverOrphanRows = async (orphanIds) => {
      const loadKey = masterKey;
      let recovered = false;
      for (const id of orphanIds) {
        try {
          const { response, result } = await window.Http.getJson(noteUrl(id));
          if (loadKey !== masterKey) return null;
          // Session failures must not classify valid ciphertext as unreadable.
          if (sessionIsGone(response, "reload")) {
            disableVault();
            return null;
          }
          if (!response.ok || !result.success) throw new Error(`HTTP ${response.status}`);
          const text = await window.PasswordCrypto.decryptPassword(
            result.content,
            result.iv,
            loadKey,
          );
          if (loadKey !== masterKey) return null;
          // Preserve server Trash state when recovering an unindexed row.
          index = Index.addNote(index, {
            id,
            name: window.NoteMarkdown.titleSlug(text, "recovered-note") + ".md",
            createdAt: result.created_at,
            updatedAt: result.updated_at,
            trashed: !!result.trashed_at,
            deletedAt: result.trashed_at || null,
          });
          recovered = true;
        } catch (error) {
          console.error("Could not recover vault note " + id + ":", error);
          unreadableIds.add(id);
        }
      }
      return recovered;
    };

    /**
     * Load the index and rows, recover orphans, and repair server Trash flags.
     *
     * Loading failures suspend writes to avoid replacing an unreadable index.
     *
     * @returns {Promise<void>} Resolves after loading or reporting a failure.
     */
    const loadVault = async () => {
      const loadKey = masterKey;
      if (!(await loadVaultIndex())) return;
      if (loadKey !== masterKey) return;
      const serverNotes = await loadVaultRows();
      if (serverNotes === null || loadKey !== masterKey) return;

      const outcome = Index.reconcile(index, serverNotes);
      index = outcome.index;
      const recovered = await recoverOrphanRows(outcome.orphanIds);
      if (recovered === null) return;

      if (outcome.changed || recovered) await persistIndex();
      vaultLoaded = true;
      if (!isDirty) startNewBuffer();
      else renderTree();

      // The index is authoritative; repair interrupted Trash writes after rendering.
      if (!readOnly) {
        const drift = Index.trashFlagDrift(index, serverNotes);
        await setTrashed(drift.trash, true);
        await setTrashed(drift.restore, false);
      }
    };

    /**
     * Establish the secure session, import its key, and load the vault.
     *
     * @returns {Promise<void>} Resolves after initialization or disabling writes.
     */
    const initialize = async () => {
      if (!window.AuthCrypto) {
        disableVault("Cryptographic module unavailable. Please reload the page.");
        return;
      }

      const session = window.VaultSession.create({
        tool: "note",
        userId: document.getElementById("unlock-modal").dataset.userId,
        onLock: () => {
          masterKey = null;
          disableVault();
        },
        onUnlock: async (key) => {
          masterKey = await window.AuthCrypto.importKeyFromBase64(key);
          readOnly = permanentReadOnly;
          if (saveBtn) saveBtn.disabled = readOnly;
          hideSessionExpired();
          if (!vaultLoaded && !readOnly) await loadVault();
        },
        onSignedOut: () => showSessionExpired(vaultLoaded ? "retry" : "reload"),
        onIdentityChange: () =>
          disableVault("Your account or password changed. Copy any unsaved text before reloading."),
      });
      let storedKeyBase64;
      try {
        storedKeyBase64 = await session.start();
      } catch {
        disableVault("Unable to check your session. Check your connection and reload.");
        return;
      }
      if (!storedKeyBase64) {
        disableVault("This tab is locked. Reload the page to unlock your vault.");
        return;
      }

      try {
        masterKey = await window.AuthCrypto.importKeyFromBase64(storedKeyBase64);
      } catch (error) {
        console.error("Failed to import stored key:", error);
        disableVault("Could not unlock your notes. Please sign in again.");
        return;
      }

      await loadVault();
    };

    renderTree();
    initialize();
  });
})();
