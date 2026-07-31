/**
 * @fileoverview Shared note-share popover: expiry selection, encrypted/plain
 * links, editable live links, and the created-link result panel.
 *
 * Vault shares use the same static snapshot flow as public shares; the vault
 * key is never involved. Share keys travel only in URL fragments.
 */
(function () {
  "use strict";

  const DEFAULT_EXPIRY = "1day";
  const HIDDEN_CLASS = "hidden";
  const EMPTY_NOTE_ERROR = "Nothing to share yet - the note is empty.";
  const SHARE_LINK_ERROR = "Failed to create the share link.";
  const EDITABLE_LINK_ERROR = "Failed to create the editable link.";

  /**
   * @typedef {Object} ShareOptions
   * @property {HTMLElement|null} popover
   * @property {HTMLElement} menu
   * @property {HTMLElement} result
   * @property {HTMLInputElement} linkInput
   * @property {HTMLElement} copyBtn
   * @property {HTMLElement} encryptedBtn
   * @property {HTMLElement} plainBtn
   * @property {HTMLElement|null} [editableBtn]
   * @property {string} expiryName
   * @property {string} createUrl
   * @property {string} retrieveUrlBase
   * @property {string} [liveCreateUrl]
   * @property {string} [liveUrlBase]
   * @property {string} dummyNoteId
   * @property {function(): string} getText
   * @property {function(): boolean} noteTooLarge
   */

  /** @param {ShareOptions} opts */
  function init(opts) {
    const {
      popover,
      menu,
      result,
      linkInput,
      copyBtn,
      encryptedBtn,
      plainBtn,
      editableBtn,
      expiryName,
      createUrl,
      retrieveUrlBase,
      liveCreateUrl,
      liveUrlBase,
      dummyNoteId,
      getText,
      noteTooLarge,
    } = opts;

    function selectedExpiry() {
      const checked = document.querySelector('input[name="' + expiryName + '"]:checked');
      return checked ? checked.value : DEFAULT_EXPIRY;
    }

    async function postNote(fields) {
      const params = new URLSearchParams(fields);
      params.set("expiry_time", selectedExpiry());
      const { response, result: body } = await window.Http.postForm(createUrl, params);
      if (!response.ok || !body.success) {
        throw new Error(window.Http.firstError(body));
      }
      return body;
    }

    async function postLiveNote(fields) {
      const { response, result: body } = await window.Http.postForm(liveCreateUrl, fields);
      if (!response.ok || !body.success) {
        throw new Error(window.Http.firstError(body));
      }
      return body;
    }

    function showError(error, fallback) {
      window.Notify.show(error.message || fallback, "error");
    }

    function requireStaticShareText() {
      const text = getText();
      if (!text.trim()) {
        window.Notify.show(EMPTY_NOTE_ERROR, "error");
        return null;
      }
      return noteTooLarge() ? null : text;
    }

    function showShareLink(noteId, fragmentKey, urlBase = retrieveUrlBase) {
      linkInput.value =
        urlBase.replace(dummyNoteId, noteId) + (fragmentKey ? "#" + fragmentKey : "");
      menu.classList.add(HIDDEN_CLASS);
      result.classList.remove(HIDDEN_CLASS);
    }

    async function shareEncrypted() {
      const text = requireStaticShareText();
      if (text === null) return;

      try {
        const key = await window.CryptoCore.generateEncryptionKey();
        const payload = await window.CryptoCore.encryptWithKey(text, key);
        const fragmentKey = await window.CryptoCore.exportKeyToBase64(key);

        const body = await postNote({
          content: payload.encryptedData,
          iv: payload.iv,
          is_encrypted: "1",
        });
        showShareLink(body.note_id, fragmentKey);
      } catch (error) {
        showError(error, SHARE_LINK_ERROR);
      }
    }

    async function sharePlainText() {
      const text = requireStaticShareText();
      if (text === null) return;

      try {
        const body = await postNote({
          content: text,
          is_encrypted: "0",
        });
        showShareLink(body.note_id, "");
      } catch (error) {
        showError(error, SHARE_LINK_ERROR);
      }
    }

    /**
     * Create an editable link (live note): seed a Yjs document with the
     * current text, encrypt its encoded state under a fresh random key, and
     * POST it as the live note's first snapshot. Deliberately no empty-text
     * gate. A blank collaborative pad is a legitimate starting point.
     * The vault key is never involved: like every share, the document key
     * travels only in the URL fragment.
     */
    async function shareEditable() {
      if (noteTooLarge()) return;

      try {
        const text = getText();
        const key = await window.CryptoCore.generateEncryptionKey();
        const doc = new window.Y.Doc();
        if (text) doc.getText("content").insert(0, text);
        const seed = window.Y.encodeStateAsUpdate(doc);
        const payload = await window.CryptoCore.encryptBytesWithKey(seed, key);
        const fragmentKey = await window.CryptoCore.exportKeyToBase64(key);

        // Plain object => Http.postForm sends JSON for the live endpoint.
        const body = await postLiveNote({
          snapshot: payload.encryptedData,
          snapshot_iv: payload.iv,
          expiry_time: selectedExpiry(),
        });
        showShareLink(body.note_id, fragmentKey, liveUrlBase);
      } catch (error) {
        showError(error, EDITABLE_LINK_ERROR);
      }
    }

    encryptedBtn.addEventListener("click", shareEncrypted);
    plainBtn.addEventListener("click", sharePlainText);
    // Pages without the live prerequisites (button, URLs, Yjs) keep working.
    if (editableBtn && liveCreateUrl && liveUrlBase && window.Y) {
      editableBtn.addEventListener("click", shareEditable);
    }

    window.ClipboardUtil.setupButton(copyBtn, () => linkInput.value);

    // Reset the popover back to the menu when it closes, so reopening it
    // offers the share options again (the previous link stays valid).
    if (popover) {
      popover.addEventListener("toggle", function (event) {
        if (event.newState === "closed") {
          menu.classList.remove(HIDDEN_CLASS);
          result.classList.add(HIDDEN_CLASS);
        }
      });
    }
  }

  window.NoteShare = { init };
})();
