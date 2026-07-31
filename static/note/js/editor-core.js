/**
 * @fileoverview Shared markdown-editor core: tabs, caret overlay, toolbar
 * wiring, autosize/counter, and Markdown download.
 *
 * Controllers pass DOM refs to NoteEditorCore.init(). Unknown rail actions are
 * ignored so pages can add their own listeners, e.g. the vault's "save".
 */
(function () {
  "use strict";

  const BYTES_PER_KIB = 1024;
  const HIDDEN_CLASS = "hidden";
  const ACTIVE_TAB_CLASS = "editor-tabs__item--active";
  const CUSTOM_CARET_CLASS = "editor__text--custom-caret";
  const CARET_VISIBLE_CLASS = "editor__caret--visible";
  const CARET_MIRROR_CLASS = "editor__text editor__caret-mirror";
  const OVER_LIMIT_CLASS = "meta--over";

  // Client-side plaintext bound. Contract with the server: the Base64
  // ciphertext of this many UTF-8 bytes (+16-byte GCM tag) stays under
  // MAX_NOTE_CONTENT_LENGTH / MAX_VAULT_NOTE_CONTENT_LENGTH in
  // apps/note/constants.py (200,000 chars).
  const MAX_NOTE_PLAINTEXT_BYTES = 128 * BYTES_PER_KIB;

  /** @typedef {{undo: function(): void, redo: function(): void}} ExternalHistory */

  /**
   * @typedef {Object} EditorElements
   * @property {HTMLTextAreaElement} textarea
   * @property {HTMLElement} preview
   * @property {HTMLElement} tabEdit
   * @property {HTMLElement} tabPreview
   * @property {HTMLElement} counter
   * @property {HTMLElement|null} [caret]
   * @property {HTMLElement|null} [editor]
   * @property {HTMLElement} rail
   * @property {ExternalHistory|null} [history] External undo/redo for live notes.
   */

  /**
   * @typedef {Object} ToolbarEdit
   * @property {string} value Replacement textarea value.
   * @property {number} selStart Selection start after applying value.
   * @property {number} selEnd Selection end after applying value.
   */

  /**
   * @typedef {Object} RemoteSplice
   * @property {number} index Pre-change start offset in UTF-16 code units.
   * @property {number} remove Number of UTF-16 code units to remove.
   * @property {string} insert Text to insert at index.
   */

  /**
   * Find the smallest replacement window that turns previousValue into nextValue.
   *
   * Textarea selections and Y.Text deltas both use UTF-16 code-unit offsets, so
   * the character-by-character scan here deliberately works on JavaScript string
   * indexes rather than Unicode code points.
   *
   * @param {string} previousValue Text before the edit.
   * @param {string} nextValue Text after the edit.
   * @returns {{start: number, endPrevious: number, endNext: number}} Minimal
   *   replacement bounds for previousValue[start:endPrevious] -> nextValue[start:endNext].
   */
  function findChangedRange(previousValue, nextValue) {
    let start = 0;
    const sharedPrefixLimit = Math.min(previousValue.length, nextValue.length);
    while (start < sharedPrefixLimit && previousValue[start] === nextValue[start]) start++;

    let endPrevious = previousValue.length;
    let endNext = nextValue.length;
    while (
      endPrevious > start &&
      endNext > start &&
      previousValue[endPrevious - 1] === nextValue[endNext - 1]
    ) {
      endPrevious--;
      endNext--;
    }

    return { start, endPrevious, endNext };
  }

  /**
   * @param {HTMLElement} activeTab
   * @param {HTMLElement} inactiveTab
   */
  function activateTab(activeTab, inactiveTab) {
    inactiveTab.classList.remove(ACTIVE_TAB_CLASS);
    activeTab.classList.add(ACTIVE_TAB_CLASS);
    inactiveTab.setAttribute("aria-selected", "false");
    activeTab.setAttribute("aria-selected", "true");
  }

  /**
   * Install the optional custom caret overlay.
   *
   * Browsers expose caret color but not caret width. The mirror element copies
   * the textarea text up to selectionStart, then a zero-width marker is measured
   * to place a fixed two-pixel overlay without changing textarea editing.
   *
   * @param {HTMLTextAreaElement} textarea
   * @param {HTMLElement|null|undefined} caret
   * @param {HTMLElement|null|undefined} editor
   * @returns {function(): void} Schedules a caret remeasure.
   */
  function setupCustomCaret(textarea, caret, editor) {
    if (!caret || !editor) {
      return function repositionCaretFallback() {};
    }

    const mirror = document.createElement("div");
    const marker = document.createElement("span");
    let composing = false;

    mirror.className = CARET_MIRROR_CLASS;
    mirror.setAttribute("aria-hidden", "true");
    marker.textContent = "\u200b";
    textarea.insertAdjacentElement("afterend", mirror);

    function hideCaret() {
      caret.classList.remove(CARET_VISIBLE_CLASS);
    }

    function positionCaret() {
      if (
        composing ||
        document.activeElement !== textarea ||
        textarea.selectionStart !== textarea.selectionEnd ||
        textarea.classList.contains(HIDDEN_CLASS)
      ) {
        hideCaret();
        return;
      }

      mirror.replaceChildren(
        document.createTextNode(textarea.value.slice(0, textarea.selectionStart)),
      );
      mirror.appendChild(marker);

      const markerRect = marker.getBoundingClientRect();
      const editorRect = editor.getBoundingClientRect();
      const left = markerRect.left - textarea.scrollLeft;
      const top = markerRect.top - textarea.scrollTop;

      // Keep the fixed overlay inside the editor when the insertion point has
      // scrolled behind the editor header or footer.
      if (
        top + markerRect.height < editorRect.top ||
        top > editorRect.bottom ||
        left < editorRect.left ||
        left > editorRect.right
      ) {
        hideCaret();
        return;
      }

      caret.style.left = left + "px";
      caret.style.top = top + "px";
      caret.style.height = markerRect.height + "px";
      caret.classList.add(CARET_VISIBLE_CLASS);
    }

    function enableCustomCaret() {
      textarea.classList.add(CUSTOM_CARET_CLASS);
      window.requestAnimationFrame(positionCaret);
    }

    textarea.addEventListener("focus", enableCustomCaret);
    textarea.addEventListener("blur", hideCaret);
    textarea.addEventListener("input", function () {
      window.requestAnimationFrame(positionCaret);
    });
    textarea.addEventListener("click", positionCaret);
    textarea.addEventListener("keyup", positionCaret);
    textarea.addEventListener("compositionstart", function () {
      composing = true;
      textarea.classList.remove(CUSTOM_CARET_CLASS);
      hideCaret();
    });
    textarea.addEventListener("compositionend", function () {
      composing = false;
      enableCustomCaret();
    });
    document.addEventListener("selectionchange", function () {
      if (document.activeElement === textarea) positionCaret();
    });
    editor.addEventListener("scroll", positionCaret, { passive: true });
    window.addEventListener("resize", positionCaret);

    if (document.activeElement === textarea) enableCustomCaret();

    return function repositionCaret() {
      window.requestAnimationFrame(positionCaret);
    };
  }

  /** @returns {Object.<string, function(Object): ToolbarEdit>} */
  function createToolbarActions() {
    return {
      bold: (selection) =>
        window.NoteToolbar.wrapInline(selection.value, selection.start, selection.end, "**"),
      italic: (selection) =>
        window.NoteToolbar.wrapInline(selection.value, selection.start, selection.end, "_"),
      strikethrough: (selection) =>
        window.NoteToolbar.wrapInline(selection.value, selection.start, selection.end, "~~"),
      h1: (selection) =>
        window.NoteToolbar.setHeading(selection.value, selection.start, selection.end, 1),
      h2: (selection) =>
        window.NoteToolbar.setHeading(selection.value, selection.start, selection.end, 2),
      h3: (selection) =>
        window.NoteToolbar.setHeading(selection.value, selection.start, selection.end, 3),
      h4: (selection) =>
        window.NoteToolbar.setHeading(selection.value, selection.start, selection.end, 4),
      h5: (selection) =>
        window.NoteToolbar.setHeading(selection.value, selection.start, selection.end, 5),
      h6: (selection) =>
        window.NoteToolbar.setHeading(selection.value, selection.start, selection.end, 6),
      bullets: (selection) =>
        window.NoteToolbar.prefixLines(
          selection.value,
          selection.start,
          selection.end,
          "- ",
          false,
        ),
      numbers: (selection) =>
        window.NoteToolbar.prefixLines(selection.value, selection.start, selection.end, "", true),
      tasks: (selection) =>
        window.NoteToolbar.prefixLines(
          selection.value,
          selection.start,
          selection.end,
          "- [ ] ",
          false,
        ),
      quote: (selection) =>
        window.NoteToolbar.prefixLines(
          selection.value,
          selection.start,
          selection.end,
          "> ",
          false,
        ),
      code: (selection) =>
        window.NoteToolbar.fenceCodeBlock(selection.value, selection.start, selection.end),
    };
  }

  /**
   * Route native undo/redo entry points to an external history owner.
   *
   * keydown covers keyboard shortcuts. beforeinput covers entry points with no
   * keydown, such as the browser context menu's Undo. Composition is left alone
   * because cancelling mid-IME history events breaks composition state.
   *
   * @param {HTMLTextAreaElement} textarea
   * @param {ExternalHistory|null|undefined} history
   */
  function interceptNativeHistory(textarea, history) {
    if (!history) return;

    textarea.addEventListener("keydown", function (event) {
      if (event.isComposing) return;
      if (!(event.ctrlKey || event.metaKey) || event.altKey) return;

      const key = event.key.toLowerCase();
      if (key === "z" && !event.shiftKey) {
        event.preventDefault();
        history.undo();
      } else if ((key === "z" && event.shiftKey) || key === "y") {
        event.preventDefault();
        history.redo();
      }
    });

    textarea.addEventListener("beforeinput", function (event) {
      if (event.isComposing) return;
      if (event.inputType === "historyUndo") {
        event.preventDefault();
        history.undo();
      } else if (event.inputType === "historyRedo") {
        event.preventDefault();
        history.redo();
      }
    });
  }

  /**
   * Wire up an editor surface and return the page controller handle.
   *
   * @param {EditorElements} els
   * @returns {Object}
   */
  function init(els) {
    const { textarea, preview, tabEdit, tabPreview, counter, caret, editor, rail, history } = els;
    const encoder = new TextEncoder();
    const inputListeners = [];
    const toolbarActions = createToolbarActions();
    const repositionCaret = setupCustomCaret(textarea, caret, editor);

    /** Render current markdown and display the preview tab. */
    function showPreview() {
      window.NoteMarkdown.renderInto(preview, textarea.value);
      textarea.classList.add(HIDDEN_CLASS);
      preview.classList.remove(HIDDEN_CLASS);
      activateTab(tabPreview, tabEdit);
    }

    /** Display the editable markdown source tab. */
    function showEdit() {
      preview.classList.add(HIDDEN_CLASS);
      textarea.classList.remove(HIDDEN_CLASS);
      activateTab(tabEdit, tabPreview);
      textarea.focus();
    }

    tabEdit.addEventListener("click", showEdit);
    tabPreview.addEventListener("click", showPreview);

    /** @returns {{value: string, start: number, end: number}} */
    function currentSelection() {
      return {
        value: textarea.value,
        start: textarea.selectionStart,
        end: textarea.selectionEnd,
      };
    }

    function notifyInput() {
      inputListeners.forEach(function (listener) {
        listener(textarea.value);
      });
    }

    // Keep the textarea scrollbar-free; the outer editor owns scrolling.
    function autosize() {
      textarea.style.height = "auto";
      textarea.style.height = textarea.scrollHeight + "px";
    }

    function updateCounter() {
      const characterCount = textarea.value.length;
      const byteCount = encoder.encode(textarea.value).length;
      const kib = (byteCount / BYTES_PER_KIB).toFixed(1);

      counter.textContent = characterCount.toLocaleString() + " characters / " + kib + " kb";
      counter.classList.toggle(OVER_LIMIT_CLASS, byteCount > MAX_NOTE_PLAINTEXT_BYTES);
      autosize();
    }

    /**
     * Apply a NoteToolbar result to the textarea.
     *
     * Only the changed slice is inserted through execCommand("insertText") so
     * native undo keeps working. execCommand is deprecated but remains the only
     * zero-dependency browser API that preserves textarea undo history; the
     * setRangeText fallback keeps the edit correct when execCommand fails.
     *
     * @param {ToolbarEdit} nextEdit Result returned by window.NoteToolbar.
     */
    function applyEdit(nextEdit) {
      const previousValue = textarea.value;
      if (nextEdit.value !== previousValue) {
        const change = findChangedRange(previousValue, nextEdit.value);
        const replacement = nextEdit.value.slice(change.start, change.endNext);

        textarea.focus();
        textarea.setSelectionRange(change.start, change.endPrevious);

        let insertedWithUndo = false;
        try {
          insertedWithUndo = document.execCommand("insertText", false, replacement);
        } catch (error) {
          insertedWithUndo = false;
        }

        if (!insertedWithUndo || textarea.value !== nextEdit.value) {
          textarea.setRangeText(replacement, change.start, change.endPrevious);
        }
        notifyInput();
      }

      textarea.focus();
      textarea.setSelectionRange(nextEdit.selStart, nextEdit.selEnd);
      updateCounter();
    }

    /** @param {"undo"|"redo"} action */
    function handleHistoryAction(action) {
      if (history) {
        // External history (Y.UndoManager): the document change replays into
        // the textarea via the page's delta path, so do not notify input
        // listeners here or the edit would be queued again as local input.
        textarea.focus();
        history[action]();
        return;
      }

      textarea.focus();
      try {
        document.execCommand(action);
      } catch (error) {
        /* no-op: undo/redo unavailable */
      }
      notifyInput();
      updateCounter();
    }

    /** @param {string|undefined} action */
    function handleRailAction(action) {
      if (action === "undo" || action === "redo") {
        handleHistoryAction(action);
        return;
      }
      if (action === "download") {
        downloadMarkdown();
        return;
      }

      const toolbarAction = toolbarActions[action];
      if (!toolbarAction) return; // Page-specific actions, such as "save", are wired by the page.

      showEdit();
      applyEdit(toolbarAction(currentSelection()));
    }

    rail.querySelectorAll("[data-action]").forEach(function (button) {
      button.addEventListener("click", function () {
        handleRailAction(button.dataset.action);
      });
    });

    textarea.addEventListener("input", function () {
      updateCounter();
      notifyInput();
    });
    updateCounter();
    interceptNativeHistory(textarea, history);

    /** Download the current buffer as a Markdown file. */
    function downloadMarkdown() {
      const markdownBlob = new Blob([textarea.value], { type: "text/markdown" });
      const objectUrl = URL.createObjectURL(markdownBlob);
      const anchor = document.createElement("a");

      anchor.href = objectUrl;
      anchor.download = window.NoteMarkdown.titleSlug(textarea.value) + ".md";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    }

    /**
     * @returns {boolean} True when the note exceeds the plaintext size limit.
     */
    function noteTooLarge() {
      const byteCount = encoder.encode(textarea.value).length;
      if (byteCount > MAX_NOTE_PLAINTEXT_BYTES) {
        const limitKib = Math.floor(MAX_NOTE_PLAINTEXT_BYTES / BYTES_PER_KIB);
        const noteKib = Math.ceil(byteCount / BYTES_PER_KIB);

        window.Notify.show(
          "Note too large: the limit is " + limitKib + " KiB and this note is " + noteKib + " KiB.",
          "error",
        );
        return true;
      }
      return false;
    }

    return {
      getValue: function () {
        return textarea.value;
      },
      /**
       * Replace the buffer without firing input listeners.
       *
       * @param {string} text
       */
      setValue: function (text) {
        textarea.value = text;
        updateCounter();
      },
      /**
       * Apply remote splices and restore the supplied selection.
       *
       * The splices arrive in ascending pre-change coordinates (see
       * NoteLiveBinding.spliceListFromDelta) and are applied in reverse order so
       * no index rebasing is needed. Like setValue, this deliberately does not
       * fire input listeners: remote edits must never be re-queued as local ones.
       * setRangeText also bypasses native undo, which is why pages using this
       * path must supply the external history handle.
       *
       * @param {Array<RemoteSplice>} splices
       * @param {number} selStart
       * @param {number} selEnd
       */
      applyRemoteSplices: function (splices, selStart, selEnd) {
        for (let i = splices.length - 1; i >= 0; i--) {
          const remoteSplice = splices[i];
          textarea.setRangeText(
            remoteSplice.insert,
            remoteSplice.index,
            remoteSplice.index + remoteSplice.remove,
          );
        }
        textarea.setSelectionRange(selStart, selEnd);
        updateCounter();
        if (!preview.classList.contains(HIDDEN_CLASS)) {
          window.NoteMarkdown.renderInto(preview, textarea.value);
        }
        repositionCaret();
      },
      showEdit,
      showPreview,
      updateCounter,
      downloadMarkdown,
      noteTooLarge,
      /**
       * Register a callback fired after every local user edit.
       *
       * @param {function(string): void} listener
       */
      onInput: function (listener) {
        inputListeners.push(listener);
      },
    };
  }

  window.NoteEditorCore = {
    MAX_NOTE_PLAINTEXT_BYTES,
    init,
  };
})();
