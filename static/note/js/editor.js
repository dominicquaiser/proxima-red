/**
 * @fileoverview Controller for the note editor page ([note·] /create).
 *
 * Page-specific wiring only; shared editor behavior lives in editor-core.js
 * and sharing lives in share.js.
 */
(function () {
  "use strict";

  /**
   * Connect the public editor DOM to the shared editor and share modules.
   */
  function initPublicEditor() {
    const main = document.getElementById("main-content");
    const textarea = document.getElementById("note-content");
    const rail = document.querySelector(".rail");
    if (!main || !textarea || !rail) return;

    const editorCore = window.NoteEditorCore.init({
      textarea,
      preview: document.getElementById("note-preview"),
      tabEdit: document.getElementById("tab-edit"),
      tabPreview: document.getElementById("tab-preview"),
      counter: document.getElementById("note-meta"),
      caret: document.getElementById("note-caret"),
      editor: document.querySelector(".editor"),
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
      dummyNoteId: main.dataset.dummyNoteId,
      getText: editorCore.getValue,
      noteTooLarge: editorCore.noteTooLarge,
    });
  }

  document.addEventListener("DOMContentLoaded", initPublicEditor);
})();
