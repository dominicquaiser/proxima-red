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
  const TOOLBAR_EXPANDED_CLASS = "note-toolbar--expanded";
  const TOOL_PRESSED_CLASS = "tool--pressed";
  const TOOL_MIN_PRESS_MS = 85;
  const MOBILE_EDITOR_QUERY = "(max-width: 768px)";
  // Ignore small visualViewport scale drift when deciding whether the page is zoomed.
  const MAX_UNZOOMED_SCALE_DELTA = 0.01;
  const CARET_BOTTOM_GAP_PX = 6;

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
   * @typedef {Object} EditorHandle
   * @property {function(): string} getValue Read the current buffer.
   * @property {function(string): void} setValue Replace text without notifying input listeners.
   * @property {function(RemoteSplice[], number, number): void} applyRemoteSplices
   *   Apply remote edits and selection without notifying input listeners.
   * @property {function(): void} showEdit Select and focus the source tab.
   * @property {function(): void} showPreview Render and select the preview tab.
   * @property {function(): void} updateCounter Update size metadata and textarea height.
   * @property {function(): void} downloadMarkdown Download the current buffer.
   * @property {function(): boolean} noteTooLarge Check the byte limit and report violations.
   * @property {function(function(string): void): void} onInput Register a local input listener.
   */

  /**
   * Find the smallest replacement window that turns previousValue into nextValue.
   *
   * String indexes use UTF-16 code units, matching textarea selections and Y.Text deltas.
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
   * Update tab styling and accessibility state.
   *
   * @param {HTMLElement} activeTab Tab to select.
   * @param {HTMLElement} inactiveTab Tab to deselect.
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
   * @returns {function(boolean=): void} Schedules a caret remeasure, optionally
   *   scrolling the mobile editor to reveal it.
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

    function positionCaret(reveal = false) {
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
      let top = markerRect.top - textarea.scrollTop;

      if (reveal === true && document.body.classList.contains("mobile-note-editor")) {
        const previousScrollTop = editor.scrollTop;
        const bottomOverflow =
          top + markerRect.height + CARET_BOTTOM_GAP_PX - editorRect.bottom;
        if (bottomOverflow > 0) {
          editor.scrollTop += bottomOverflow;
        } else if (top < editorRect.top) {
          editor.scrollTop += top - editorRect.top;
        }
        top -= editor.scrollTop - previousScrollTop;
      }

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

    function resetCaretBlink() {
      // Restart at the visible frame on each edit or cursor movement.
      caret.getAnimations().forEach(function (animation) {
        animation.currentTime = 0;
      });
    }

    function positionAndResetCaret() {
      positionCaret();
      resetCaretBlink();
    }

    function enableCustomCaret() {
      textarea.classList.add(CUSTOM_CARET_CLASS);
      window.requestAnimationFrame(positionAndResetCaret);
    }

    textarea.addEventListener("focus", enableCustomCaret);
    textarea.addEventListener("blur", hideCaret);
    textarea.addEventListener("keydown", resetCaretBlink);
    textarea.addEventListener("input", function () {
      window.requestAnimationFrame(() => {
        positionCaret(true);
        resetCaretBlink();
      });
    });
    textarea.addEventListener("click", positionAndResetCaret);
    textarea.addEventListener("keyup", positionAndResetCaret);
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
      if (document.activeElement === textarea) positionAndResetCaret();
    });
    editor.addEventListener("scroll", positionCaret, { passive: true });
    window.addEventListener("resize", positionCaret);

    if (document.activeElement === textarea) enableCustomCaret();

    return function repositionCaret(reveal = false) {
      window.requestAnimationFrame(() => positionCaret(reveal));
    };
  }

  /**
   * Arrange the mobile editor and wire its editing toolbar.
   *
   * @param {HTMLTextAreaElement} textarea Editable note source.
   * @param {HTMLElement} editor Scrolling editor container.
   * @param {function(): void} revealCaret Scroll the insertion point into view.
   * @param {function(string|undefined): void} handleRailAction Run a shared editing action.
   * @param {function(): void} showEdit Switch to the editable source.
   * @returns {void}
   */
  function setupMobileToolbar(textarea, editor, revealCaret, handleRailAction, showEdit) {
    const toolbar = document.getElementById("note-toolbar");
    const header = document.querySelector(".note-editor > .header, .note-editor > .topbar");
    const headerParent = header.parentElement;
    const headerNextSibling = header.nextSibling;
    const moreButton = document.getElementById("note-more-tools");
    const extraTools = document.getElementById("note-extra-tools");
    const visualViewport = window.visualViewport;
    const mobileMediaQuery = window.matchMedia(MOBILE_EDITOR_QUERY);
    const body = document.body;
    let pressedTool = null;

    /**
     * Sync the toolbar layout and accessibility state for the animated row.
     *
     * @param {boolean} expanded Whether the extra tools are available.
     * @returns {void}
     */
    function setExpanded(expanded) {
      const collapsed = !expanded;
      toolbar.classList.toggle(TOOLBAR_EXPANDED_CLASS, expanded);
      // The row stays in the DOM for its exit animation. Disable it immediately.
      extraTools.inert = collapsed;
      extraTools.setAttribute("aria-hidden", String(collapsed));
      moreButton.setAttribute("aria-expanded", String(expanded));
      if (collapsed && extraTools.contains(document.activeElement)) moreButton.focus();
      if (document.activeElement === textarea) revealCaret();
    }

    function clearPress() {
      if (!pressedTool) return;
      window.clearTimeout(pressedTool.releaseTimer);
      pressedTool.button.classList.remove(TOOL_PRESSED_CLASS);
      pressedTool = null;
    }

    function startPress(button, pointerId = null) {
      clearPress();
      pressedTool = { button, pointerId, startedAt: performance.now() };
      button.classList.add(TOOL_PRESSED_CLASS);
    }

    function releasePress() {
      // Let quick taps show the pressed state for a few frames.
      const heldFor = performance.now() - pressedTool.startedAt;
      const remaining = Math.max(0, TOOL_MIN_PRESS_MS - heldFor);
      pressedTool.releaseTimer = window.setTimeout(clearPress, remaining);
    }

    function updateMobileLayout() {
      const zoomed =
        visualViewport && Math.abs(visualViewport.scale - 1) > MAX_UNZOOMED_SCALE_DELTA;
      const active = mobileMediaQuery.matches && !zoomed;

      if (mobileMediaQuery.matches && header.parentElement !== editor) {
        editor.prepend(header);
      }
      if (!mobileMediaQuery.matches && header.parentElement === editor) {
        headerParent.insertBefore(header, headerNextSibling);
      }
      body.classList.toggle("mobile-note-editor", active);
      if (!active) {
        clearPress();
        body.style.removeProperty("--visible-height");
        body.style.removeProperty("--visible-top");
        return;
      }

      body.style.setProperty(
        "--visible-height",
        (visualViewport?.height ?? window.innerHeight) + "px",
      );
      body.style.setProperty("--visible-top", (visualViewport?.offsetTop ?? 0) + "px");
      if (document.activeElement === textarea) revealCaret();
    }

    /** @param {string} symbol Markdown character to insert at the selection. */
    function insertSymbol(symbol) {
      showEdit();
      textarea.focus({ preventScroll: true });

      // Both paths emit input, so live sync and vault dirty tracking see the edit.
      if (!document.execCommand?.("insertText", false, symbol)) {
        textarea.setRangeText(symbol, textarea.selectionStart, textarea.selectionEnd, "end");
        textarea.dispatchEvent(new Event("input", { bubbles: true }));
      }
    }

    moreButton.addEventListener("click", () =>
      setExpanded(!toolbar.classList.contains(TOOLBAR_EXPANDED_CLASS)),
    );
    toolbar.addEventListener("keydown", (event) => {
      if (event.key !== "Escape" || !toolbar.classList.contains(TOOLBAR_EXPANDED_CLASS)) return;
      setExpanded(false);
      moreButton.focus();
    });

    toolbar.addEventListener("pointerdown", (event) => {
      const button = event.target.closest("button.tool:enabled");
      if (!button) return;

      // Editing tools leave the insertion point and IME attached. Sharing
      // lets the browser move focus into the popover.
      if (document.activeElement === textarea && !button.hasAttribute("popovertarget")) {
        event.preventDefault();
      }
      if (event.isPrimary && event.button === 0) startPress(button, event.pointerId);
    });
    window.addEventListener("pointerup", (event) => {
      if (event.pointerId === pressedTool?.pointerId) releasePress();
    });
    window.addEventListener("pointercancel", (event) => {
      if (event.pointerId === pressedTool?.pointerId) clearPress();
    });
    window.addEventListener("blur", clearPress);

    toolbar.addEventListener("click", (event) => {
      const button = event.target.closest("button.tool:enabled");
      if (!button) return;

      // Keyboard and assistive clicks arrive without a pointer press.
      if (event.detail === 0) {
        startPress(button);
        releasePress();
      }

      const { action, symbol } = button.dataset;
      if (action) {
        handleRailAction(action);
        if (document.activeElement === textarea) revealCaret();
        return;
      }

      if (!symbol || textarea.readOnly || textarea.disabled) return;
      insertSymbol(symbol);
    });

    textarea.addEventListener("focus", updateMobileLayout);
    window.addEventListener("resize", updateMobileLayout);
    visualViewport?.addEventListener("resize", updateMobileLayout);
    visualViewport?.addEventListener("scroll", updateMobileLayout);
    updateMobileLayout();
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
   * @param {EditorElements} els Editor DOM elements and optional history controller.
   * @returns {EditorHandle} Buffer, display, and local input controls.
   */
  function init(els) {
    const { textarea, preview, tabEdit, tabPreview, counter, caret, editor, rail, history } = els;
    const encoder = new TextEncoder();
    const inputListeners = [];
    const toolbarActions = createToolbarActions();
    const repositionCaret = setupCustomCaret(textarea, caret, editor);

    const modeButton = document.getElementById("note-mode");
    let sourceScroll = 0;

    function updateModeButton(previewing) {
      const label = previewing ? "Edit note" : "Preview note";
      modeButton.setAttribute("aria-label", label);
      modeButton.title = label;
      modeButton.querySelector(".note-book").classList.toggle(HIDDEN_CLASS, previewing);
      modeButton.querySelector(".nicon").classList.toggle(HIDDEN_CLASS, !previewing);
    }

    /** Render current markdown and display the preview tab. */
    function showPreview() {
      sourceScroll = editor.scrollTop;
      textarea.blur();
      window.NoteMarkdown.renderInto(preview, textarea.value);
      textarea.classList.add(HIDDEN_CLASS);
      preview.classList.remove(HIDDEN_CLASS);
      activateTab(tabPreview, tabEdit);
      updateModeButton(true);
    }

    /** Display the editable markdown source tab. */
    function showEdit() {
      const wasPreviewing = !preview.classList.contains(HIDDEN_CLASS);
      preview.classList.add(HIDDEN_CLASS);
      textarea.classList.remove(HIDDEN_CLASS);
      activateTab(tabEdit, tabPreview);
      updateModeButton(false);
      if (wasPreviewing) {
        autosize();
        editor.scrollTop = sourceScroll;
      }
      textarea.focus({ preventScroll: true });
    }

    modeButton.addEventListener("click", () => {
      if (preview.classList.contains(HIDDEN_CLASS)) showPreview();
      else showEdit();
    });

    setupMobileToolbar(textarea, editor, () => repositionCaret(true), handleRailAction, showEdit);

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

    function autosize() {
      const doc = textarea.parentElement;
      doc.style.minHeight = doc.getBoundingClientRect().height + "px";
      textarea.style.height = "auto";
      textarea.style.height = textarea.scrollHeight + "px";
      doc.style.minHeight = "";
    }

    /**
     * Repaint the character/size readout and flag it once over the byte limit.
     *
     * The UTF-8 byte limit leaves room for encryption and Base64 encoding under
     * the server's ciphertext character cap.
     */
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
     * Insert only the changed slice through execCommand("insertText") to retain
     * native undo history. Fall back to setRangeText if the command fails.
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
        // Yjs replays this change via remote splices; notifying input would queue it twice.
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
      if (action === "download") {
        downloadMarkdown();
        return;
      }
      if (textarea.readOnly || textarea.disabled) return;
      if (action === "undo" || action === "redo") {
        showEdit();
        handleHistoryAction(action);
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
     * Report size-limit violations to the user.
     *
     * @returns {boolean} True when the note exceeds the plaintext byte limit.
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
      /** @returns {string} Current editor contents, including unsaved edits. */
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
       * Apply ascending pre-change offsets in reverse order to avoid rebasing.
       * Input listeners are not fired, preventing remote edits from being queued
       * as local input. Callers must supply external history because setRangeText
       * bypasses the native undo stack.
       *
       * @param {Array<RemoteSplice>} splices Edits in ascending pre-change coordinates.
       * @param {number} selStart Selection start in the updated buffer, in UTF-16 code units.
       * @param {number} selEnd Selection end in the updated buffer, in UTF-16 code units.
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
