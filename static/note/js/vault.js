/**
 * @fileoverview Controller for the encrypted note vault page.
 *
 * The server stores note rows separately from an encrypted index. Rows are
 * saved/deleted first and the index is saved last, so the index is the commit
 * marker and reconcile() can heal drift on the next load.
 */
(function () {
  "use strict";

  // Cross-tab key cache for this origin; cleared during sign-out.
  const NOTE_VAULT_KEY_STORAGE = "noteVaultMasterKey";
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
    // Bounds how long the cross-tab key copy may sit in localStorage. Server
    // supplied (SESSION_COOKIE_AGE) so it cannot drift from the session it
    // is tied to; 0 if absent, which disables the mirror rather than
    // defaulting to some guessed lifetime.
    const sessionMaxAgeMs = (Number(main.dataset.sessionMaxAge) || 0) * 1000;
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

    const noteUrl = (id) => noteUrlBase.replace(dummyNoteId, id);
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

    // A snapshot model loses unsaved work on note switches too.
    const confirmDiscard = () =>
      !isDirty || window.confirm("Discard unsaved changes to this note?");

    const renderCrumb = () => {
      crumbEl.replaceChildren();
      const currentEntry = index.notes.find((note) => note.id === currentNoteId);
      const folder = index.folders.find(
        (folderItem) => folderItem.id === (currentEntry || {}).folderId,
      );
      const dir = document.createElement("span");
      dir.className = "topbar__crumb-dir";
      dir.textContent = folder ? "/" + folder.name + "/" : "/";
      crumbEl.appendChild(dir);
      crumbEl.appendChild(document.createTextNode(currentName));
    };

    const icon = (name, extraClass) => {
      const span = document.createElement("span");
      span.className = "nicon nicon--" + name + (extraClass ? " " + extraClass : "");
      span.setAttribute("aria-hidden", "true");
      return span;
    };

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

    const renderTree = () => {
      const tree = Index.visibleTree(Index.filter(index, searchTerm));
      treeEl.replaceChildren();

      tree.folders.forEach((folder) => treeEl.appendChild(buildFolderDetails(folder)));
      tree.rootNotes.forEach((note) => treeEl.appendChild(buildFileRow(note, "note")));
      unreadableIds.forEach((id) => treeEl.appendChild(buildUnreadableRow(id)));

      // Trash is a permanent section, even when empty.
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
      tree.trash.forEach((note) => trashDetails.appendChild(buildFileRow(note, "trash")));
      treeEl.appendChild(trashDetails);

      if (tree.folders.length === 0 && tree.rootNotes.length === 0 && unreadableIds.size === 0) {
        const empty = document.createElement("p");
        empty.className = "tree__empty";
        empty.textContent = searchTerm ? "No notes match the search." : "No notes yet.";
        treeEl.appendChild(empty);
      }

      renderCrumb();
    };

    // `message` is optional: the session-expiry path locks the vault but lets
    // its own modal carry the explanation, so a toast alongside would only
    // compete with it.
    const disableVault = (message) => {
      readOnly = true;
      if (saveBtn) saveBtn.disabled = true;
      if (message) window.Notify.show(message, "error");
    };

    // --- Expired session ---
    //
    // A 401 from any vault API means the session itself is gone. The unlock
    // overlay cannot fix that (/auth/reauth/ is session-gated too, and only
    // ever re-derives a missing key), so the recovery is a real sign-in - in
    // a NEW tab, because this tab holds the unsaved buffer and there is no
    // autosave to fall back on. The vault key survives signing in again (it
    // derives from the password and vault_salt, neither of which a sign-in
    // changes), so the retry afterwards just works.
    //
    // `mode` is "retry" (the editor is intact; sign in and try again) or
    // "reload" (the vault never loaded; sign in and reload the page).
    const showSessionExpired = (mode) => {
      if (!sessionModal) {
        // No modal in the DOM: still say something useful rather than nothing.
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

    const hideSessionExpired = () => {
      if (sessionModal) sessionModal.classList.add(HIDDEN_CLASS);
    };

    /**
     * Raise or clear the sign-in prompt from one reply. Last response wins.
     *
     * Callers return early on true, skipping their own error toast: the modal
     * is the message. Clearing on every non-401 matters as much as raising on
     * a 401, because a save is two requests (row, then index) and can fail on
     * the second. Hiding once at the end of a flow would dismiss a prompt
     * that had just gone up.
     *
     * @param {Response} response
     * @param {"retry"|"reload"} mode
     * @returns {boolean} True when the session has expired.
     */
    const sessionIsGone = (response, mode) => {
      if (response.status === 401) {
        // The session is over, so the mirrored key has nothing left to
        // unlock: drop it instead of leaving it on disk for the next tab.
        // This tab keeps its in-memory masterKey, so the sign-in-and-retry
        // flow the modal offers still works.
        window.AuthCrypto.clearMirroredVaultKey(NOTE_VAULT_KEY_STORAGE);
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

    // Encrypt and save the current index.
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

    // Optimistically apply an index change, then roll back on save failure.
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

    const startNewBuffer = () => {
      currentNoteId = null;
      currentName = Index.defaultName(index);
      core.setValue("");
      lastSavedValue = "";
      setDirty(false);
      core.showEdit();
      renderTree();
    };

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
      let indexed = false;
      try {
        const payload = await window.CryptoCore.encryptWithKey(text, masterKey);

        if (currentNoteId === null) {
          // Row first, index last; reconcile() re-adopts orphan rows.
          const { response, result } = await window.Http.postForm(notesUrl, {
            content: payload.encryptedData,
            iv: payload.iv,
          });
          if (sessionIsGone(response, "retry")) return;
          if (!response.ok || !result.success) {
            throw new Error(result.error || `HTTP ${response.status}`);
          }
          currentNoteId = result.note_id;
          indexed = await commitIndexChange((idx) =>
            Index.addNote(idx, {
              id: result.note_id,
              name: currentName,
              createdAt: result.created_at,
              updatedAt: result.updated_at,
            }),
          );
        } else {
          const { response, result } = await window.Http.postForm(noteUrl(currentNoteId), {
            content: payload.encryptedData,
            iv: payload.iv,
          });
          if (sessionIsGone(response, "retry")) return;
          if (!response.ok || !result.success) {
            throw new Error(result.error || `HTTP ${response.status}`);
          }
          indexed = await commitIndexChange((idx) =>
            Index.touchNote(idx, currentNoteId, result.updated_at),
          );
        }

        // The row is written either way, so the buffer does match the server.
        lastSavedValue = text;
        setDirty(false);
        if (!indexed) {
          // Row saved, index not: the note exists but is missing from the
          // tree until reconcile() re-adopts it on the next load. Saying
          // "saved" here would contradict whatever persistIndex just put on
          // screen.
          return;
        }
        window.Notify.show("Note saved to your vault.", "success");
      } catch (error) {
        console.error("Failed to save note:", error);
        window.Notify.show(error.message || "Failed to save the note.", "error");
      } finally {
        isSaving = false;
      }
    };

    // Record Trash state on the server rows. Trash itself lives in the
    // encrypted index; this flag is only what lets the expiry sweep delete a
    // note once the retention window passes. Bulk on purpose: trashing a whole
    // folder costs one write of the vault rate limit, not one per note.
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

    // Server row first, then the index; reset if the open note was deleted.
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

    const renameNote = (id) => {
      const row = treeEl.querySelector('[data-note-id="' + id + '"]');
      const entry = index.notes.find((note) => note.id === id);
      if (!row || !entry) return;
      startRename(row, entry.name, (value) => {
        commitIndexChange((idx) => Index.renameNote(idx, id, value));
        if (id === currentNoteId) currentName = value;
      });
    };

    const renameFolder = (id) => {
      const details = treeEl.querySelector('[data-folder-id="' + id + '"]');
      const folder = index.folders.find((item) => item.id === id);
      if (!details || !folder) return;
      startRename(details.querySelector("summary"), folder.name, (value) => {
        commitIndexChange((idx) => Index.renameFolder(idx, id, value));
      });
    };

    let armedDelete = null;

    const closeCtxMenu = () => {
      ctxMenu.classList.add(HIDDEN_CLASS);
      ctxMenu.replaceChildren();
      armedDelete = null;
      treeEl
        .querySelectorAll('[aria-expanded="true"]')
        .forEach((el) => el.setAttribute("aria-expanded", "false"));
    };

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

    // Destructive deletes require a second click.
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

    const openCtxMenu = (anchor, kind, id) => {
      closeCtxMenu();
      anchor.setAttribute("aria-expanded", "true");

      if (kind === "note") {
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
            async () => {
              closeCtxMenu();
              if (id === currentNoteId) {
                setDirty(false);
                startNewBuffer();
              }
              // Index first, then the flag. The reverse order could leave a note
              // the user still sees as active carrying a deletion flag.
              if (await commitIndexChange((idx) => Index.trashNote(idx, id))) {
                await setTrashed([id], true);
              }
            },
            "ctx-menu__item--danger",
          ),
        );
      } else if (kind === "trash") {
        ctxMenu.appendChild(
          ctxItem("Restore", "arrow-counter-clockwise", async () => {
            closeCtxMenu();
            // Clear the flag first, and abort the restore if that fails: a
            // note left in Trash is recoverable, one the server still plans to
            // delete is not.
            if (await setTrashed([id], false)) {
              await commitIndexChange((idx) => Index.restoreNote(idx, id));
            }
          }),
        );
        ctxMenu.appendChild(ctxDeleteItem("Delete forever", () => deleteNoteForever(id)));
      } else if (kind === "unreadable") {
        ctxMenu.appendChild(ctxDeleteItem("Delete forever", () => deleteNoteForever(id)));
      } else if (kind === "folder") {
        ctxMenu.appendChild(
          ctxItem("Rename", "pencil-simple-line", () => {
            closeCtxMenu();
            renameFolder(id);
          }),
        );
        ctxMenu.appendChild(
          ctxDeleteItem("Delete folder", async () => {
            // Folder contents move to Trash; rows stay on the server. Collect
            // the ids deleteFolder will trash before mutating, then flag them
            // in one call (index first, then the flag).
            const trashing = index.notes
              .filter((note) => note.folderId === id && !note.trashed)
              .map((note) => note.id);
            if (await commitIndexChange((idx) => Index.deleteFolder(idx, id))) {
              await setTrashed(trashing, true);
            }
          }),
        );
      }

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
        if (fileRow.dataset.unreadable) return; // nothing to open
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

    // Fetch and decrypt the index, list the note rows, reconcile the two,
    // and adopt orphan rows. Failed index load disables the vault.
    const loadVault = async () => {
      let blob;
      try {
        const { response, result } = await window.Http.getJson(indexUrl);
        // "reload", not "retry": nothing loaded, so there is no buffer to
        // preserve and no in-place retry to offer.
        if (sessionIsGone(response, "reload")) {
          disableVault();
          return;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        if (!result.success) throw new Error(result.error || `HTTP ${response.status}`);
        blob = result;
      } catch (error) {
        console.error("Failed to load vault index:", error);
        disableVault("Could not load your vault. Please reload the page.");
        return;
      }

      if (blob.encrypted_data && blob.iv) {
        try {
          const decrypted = await window.AuthCrypto.decryptAccountData(
            blob.encrypted_data,
            blob.iv,
            masterKey,
          );
          if (!Index.isSupported(decrypted)) {
            throw new Error("Unsupported vault index format");
          }
          index = decrypted;
        } catch (error) {
          console.error("Failed to decrypt vault index:", error);
          disableVault("Could not decrypt your vault index. Reload the page or sign in again.");
          return;
        }
      }

      let serverNotes = [];
      try {
        const { response, result } = await window.Http.getJson(notesUrl);
        if (sessionIsGone(response, "reload")) {
          disableVault();
          return;
        }
        if (!response.ok || !result.success) throw new Error(`HTTP ${response.status}`);
        serverNotes = result.notes || [];
      } catch (error) {
        console.error("Failed to list vault notes:", error);
        disableVault("Could not load your notes. Please reload the page.");
        return;
      }

      const outcome = Index.reconcile(index, serverNotes);
      index = outcome.index;
      let changed = outcome.changed;

      for (const id of outcome.orphanIds) {
        try {
          const { response, result } = await window.Http.getJson(noteUrl(id));
          // Stop rather than fall through to the catch: that path files the
          // row as "unreadable", which is a claim about the key and would
          // stick in the UI long after signing in fixed the real problem.
          if (sessionIsGone(response, "reload")) {
            disableVault();
            return;
          }
          if (!response.ok || !result.success) throw new Error(`HTTP ${response.status}`);
          const text = await window.PasswordCrypto.decryptPassword(
            result.content,
            result.iv,
            masterKey,
          );
          // Re-adopt at the row's own Trash state, so a note recovered from a
          // half-finished write does not silently climb back out of Trash.
          index = Index.addNote(index, {
            id,
            name: window.NoteMarkdown.titleSlug(text, "recovered-note") + ".md",
            createdAt: result.created_at,
            updatedAt: result.updated_at,
            trashed: !!result.trashed_at,
            deletedAt: result.trashed_at || null,
          });
          changed = true;
        } catch (error) {
          // Surface unreadable rows, but do not adopt them into the index.
          console.error("Could not recover vault note " + id + ":", error);
          unreadableIds.add(id);
        }
      }

      if (changed) await persistIndex();
      startNewBuffer();

      // Housekeeping, after the vault is on screen and normally a no-op: bring
      // rows whose Trash flag disagrees with the index back in line, one bulk
      // call per direction. This is what heals an interrupted trash/restore,
      // and it is why the ordering at those call sites is an optimization
      // rather than a correctness requirement.
      if (!readOnly) {
        const drift = Index.trashFlagDrift(index, serverNotes);
        await setTrashed(drift.trash, true);
        await setTrashed(drift.restore, false);
      }
    };

    const initialize = async () => {
      if (!window.AuthCrypto) {
        disableVault("Cryptographic module unavailable. Please reload the page.");
        return;
      }

      // Import a key handed over in the URL fragment, then scrub it.
      window.AuthCrypto.consumeVaultKeyFromFragment();

      // Resolve the vault key: this tab's session, a key another tab on this
      // origin mirrored to localStorage, or the in-place unlock modal (the
      // helper mirrors whatever it resolves back to localStorage for siblings).
      const storedKeyBase64 = await window.AuthCrypto.resolveVaultKeyBase64({
        localStorageKey: NOTE_VAULT_KEY_STORAGE,
        maxAgeMs: sessionMaxAgeMs,
      });
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

    // Clear the cross-tab vault key before sign-out navigation.
    // Only reaches the copy when the sign-out happens on THIS origin (the
    // sidebar's form and the unlock modal's). localStorage is origin-scoped,
    // so a sign-out on the main site or the pass subdomain cannot clear it --
    // which is why the stored copy also carries an expiry.
    document.querySelectorAll('form[action*="/auth/signout/"]').forEach((form) => {
      form.addEventListener("submit", () => {
        window.AuthCrypto.clearMirroredVaultKey(NOTE_VAULT_KEY_STORAGE);
      });
    });

    renderTree();
    initialize();
  });
})();
