/**
 * @fileoverview Controller for the note editor page ([note·] /create).
 *
 * Wires the EDIT/PREVIEW tabs, the tool rail (via the pure functions in
 * toolbar.js), the character/byte counter, the .md download, and the share
 * popover. Sharing encrypts client-side by default (AES-256-GCM via the
 * shared CryptoCore; the key travels only in the URL fragment) or POSTs
 * plain text after an explicit confirmation.
 *
 * Load order (all deferred): shared utils, shared/js/crypto.js,
 * vendor/marked.min.js, vendor/purify.min.js, markdown.js, toolbar.js, then
 * this file.
 */
(function () {
  "use strict";

  // Client-side plaintext bound. Contract with the server: the Base64
  // ciphertext of this many UTF-8 bytes (+16-byte GCM tag) stays under
  // MAX_NOTE_CONTENT_LENGTH in apps/note/constants.py (200,000 chars).
  const MAX_NOTE_PLAINTEXT_BYTES = 131072; // 128 KiB

  document.addEventListener("DOMContentLoaded", function () {
    const main = document.getElementById("main-content");
    const textarea = document.getElementById("note-content");
    const rail = document.querySelector(".rail");
    if (!main || !textarea || !rail) return;

    const createUrl = main.dataset.createUrl;
    const retrieveUrlBase = main.dataset.retrieveUrlBase;
    const dummyNoteId = main.dataset.dummyNoteId;

    const preview = document.getElementById("note-preview");
    const tabEdit = document.getElementById("tab-edit");
    const tabPreview = document.getElementById("tab-preview");
    const counter = document.getElementById("note-meta");
    const caret = document.getElementById("note-caret");
    const editor = document.querySelector(".editor");
    const popover = document.getElementById("share-pop");
    const shareMenu = document.getElementById("share-menu");
    const shareResult = document.getElementById("share-result");
    const shareLinkInput = document.getElementById("share-link");
    const copyLinkBtn = document.getElementById("copy-link-btn");
    function selectedExpiry() {
      const checked = document.querySelector('input[name="note-expiry"]:checked');
      return checked ? checked.value : "1day";
    }
    const encoder = new TextEncoder();

    function showPreview() {
      window.NoteMarkdown.renderInto(preview, textarea.value);
      textarea.classList.add("hidden");
      preview.classList.remove("hidden");
      tabEdit.classList.remove("editor-tabs__item--active");
      tabPreview.classList.add("editor-tabs__item--active");
      tabEdit.setAttribute("aria-selected", "false");
      tabPreview.setAttribute("aria-selected", "true");
    }

    function showEdit() {
      preview.classList.add("hidden");
      textarea.classList.remove("hidden");
      tabPreview.classList.remove("editor-tabs__item--active");
      tabEdit.classList.add("editor-tabs__item--active");
      tabPreview.setAttribute("aria-selected", "false");
      tabEdit.setAttribute("aria-selected", "true");
      textarea.focus();
    }

    tabEdit.addEventListener("click", showEdit);
    tabPreview.addEventListener("click", showPreview);

    // Browsers expose the native caret's color and shape, but not its width.
    // Mirror the textarea's layout so a two-pixel caret can be placed at the
    // real insertion point without changing the textarea's editing behavior.
    if (caret && editor) {
      const mirror = document.createElement("div");
      const marker = document.createElement("span");
      let composing = false;

      mirror.className = "editor__text editor__caret-mirror";
      mirror.setAttribute("aria-hidden", "true");
      marker.textContent = "\u200b";
      textarea.insertAdjacentElement("afterend", mirror);

      function hideCaret() {
        caret.classList.remove("editor__caret--visible");
      }

      function positionCaret() {
        if (
          composing ||
          document.activeElement !== textarea ||
          textarea.selectionStart !== textarea.selectionEnd ||
          textarea.classList.contains("hidden")
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

        // Do not let the fixed overlay escape the editor when its insertion
        // point has scrolled behind the header or footer.
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
        caret.classList.add("editor__caret--visible");
      }

      function enableCustomCaret() {
        textarea.classList.add("editor__text--custom-caret");
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
        textarea.classList.remove("editor__text--custom-caret");
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
    }

    /**
     * Apply a NoteToolbar result to the textarea, replacing only the changed
     * slice via execCommand("insertText") so native undo keeps working.
     * execCommand is deprecated but universally supported and the only
     * zero-dependency way to preserve the textarea's undo stack;
     * setRangeText is the fallback (it loses undo history in some browsers).
     */
    function applyEdit(next) {
      const prev = textarea.value;
      if (next.value !== prev) {
        // Minimal changed slice: trim the common prefix and suffix.
        let start = 0;
        const minLen = Math.min(prev.length, next.value.length);
        while (start < minLen && prev[start] === next.value[start]) start++;
        let endPrev = prev.length;
        let endNext = next.value.length;
        while (
          endPrev > start &&
          endNext > start &&
          prev[endPrev - 1] === next.value[endNext - 1]
        ) {
          endPrev--;
          endNext--;
        }
        const replacement = next.value.slice(start, endNext);

        textarea.focus();
        textarea.setSelectionRange(start, endPrev);
        let ok = false;
        try {
          ok = document.execCommand("insertText", false, replacement);
        } catch (error) {
          ok = false;
        }
        if (!ok || textarea.value !== next.value) {
          textarea.setRangeText(replacement, start, endPrev);
        }
      }
      textarea.focus();
      textarea.setSelectionRange(next.selStart, next.selEnd);
      updateCounter();
    }

    function currentSelection() {
      return {
        value: textarea.value,
        start: textarea.selectionStart,
        end: textarea.selectionEnd,
      };
    }

    const toolbarActions = {
      bold: (s) => window.NoteToolbar.wrapInline(s.value, s.start, s.end, "**"),
      italic: (s) => window.NoteToolbar.wrapInline(s.value, s.start, s.end, "_"),
      strikethrough: (s) => window.NoteToolbar.wrapInline(s.value, s.start, s.end, "~~"),
      h1: (s) => window.NoteToolbar.setHeading(s.value, s.start, s.end, 1),
      h2: (s) => window.NoteToolbar.setHeading(s.value, s.start, s.end, 2),
      h3: (s) => window.NoteToolbar.setHeading(s.value, s.start, s.end, 3),
      h4: (s) => window.NoteToolbar.setHeading(s.value, s.start, s.end, 4),
      h5: (s) => window.NoteToolbar.setHeading(s.value, s.start, s.end, 5),
      h6: (s) => window.NoteToolbar.setHeading(s.value, s.start, s.end, 6),
      bullets: (s) => window.NoteToolbar.prefixLines(s.value, s.start, s.end, "- ", false),
      numbers: (s) => window.NoteToolbar.prefixLines(s.value, s.start, s.end, "", true),
      tasks: (s) => window.NoteToolbar.prefixLines(s.value, s.start, s.end, "- [ ] ", false),
      quote: (s) => window.NoteToolbar.prefixLines(s.value, s.start, s.end, "> ", false),
      code: (s) => window.NoteToolbar.fenceCodeBlock(s.value, s.start, s.end),
    };

    rail.querySelectorAll("[data-action]").forEach(function (button) {
      button.addEventListener("click", function () {
        const action = button.dataset.action;

        if (action === "undo" || action === "redo") {
          textarea.focus();
          try {
            document.execCommand(action);
          } catch (error) {
            /* no-op: undo/redo unavailable */
          }
          updateCounter();
          return;
        }
        if (action === "download") {
          downloadMarkdown();
          return;
        }

        const handler = toolbarActions[action];
        if (!handler) return;
        showEdit();
        applyEdit(handler(currentSelection()));
      });
    });

    // Keep the textarea scrollbar-free; the outer editor owns scrolling.
    function autosize() {
      textarea.style.height = "auto";
      textarea.style.height = textarea.scrollHeight + "px";
    }

    function updateCounter() {
      const chars = textarea.value.length;
      const bytes = encoder.encode(textarea.value).length;
      const kb = (bytes / 1024).toFixed(1);
      counter.textContent = chars.toLocaleString() + " characters / " + kb + " kb";
      counter.classList.toggle("meta--over", bytes > MAX_NOTE_PLAINTEXT_BYTES);
      autosize();
    }

    textarea.addEventListener("input", updateCounter);
    updateCounter();

    function downloadMarkdown() {
      const blob = new Blob([textarea.value], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = window.NoteMarkdown.titleSlug(textarea.value) + ".md";
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    }

    function noteTooLarge() {
      const bytes = encoder.encode(textarea.value).length;
      if (bytes > MAX_NOTE_PLAINTEXT_BYTES) {
        window.Notify.show(
          "Note too large: the limit is " +
            Math.floor(MAX_NOTE_PLAINTEXT_BYTES / 1024) +
            " KiB and this note is " +
            Math.ceil(bytes / 1024) +
            " KiB.",
          "error",
        );
        return true;
      }
      return false;
    }

    async function postNote(fields) {
      const params = new URLSearchParams(fields);
      params.set("expiry_time", selectedExpiry());
      const { response, result } = await window.Http.postForm(createUrl, params);
      if (!response.ok || !result.success) {
        throw new Error(window.Http.firstError(result));
      }
      return result;
    }

    function showShareLink(noteId, fragmentKey) {
      const url =
        retrieveUrlBase.replace(dummyNoteId, noteId) + (fragmentKey ? "#" + fragmentKey : "");
      shareLinkInput.value = url;
      shareMenu.classList.add("hidden");
      shareResult.classList.remove("hidden");
    }

    async function shareEncrypted() {
      if (!textarea.value.trim()) {
        window.Notify.show("Nothing to share yet - the note is empty.", "error");
        return;
      }
      if (noteTooLarge()) return;

      try {
        const key = await window.CryptoCore.generateEncryptionKey();
        const payload = await window.CryptoCore.encryptWithKey(textarea.value, key);
        const fragmentKey = await window.CryptoCore.exportKeyToBase64(key);

        const result = await postNote({
          content: payload.encryptedData,
          iv: payload.iv,
          is_encrypted: "1",
        });
        showShareLink(result.note_id, fragmentKey);
      } catch (error) {
        window.Notify.show(error.message || "Failed to create the share link.", "error");
      }
    }

    async function sharePlainText() {
      if (!textarea.value.trim()) {
        window.Notify.show("Nothing to share yet - the note is empty.", "error");
        return;
      }
      if (noteTooLarge()) return;

      try {
        const result = await postNote({
          content: textarea.value,
          is_encrypted: "0",
        });
        showShareLink(result.note_id, "");
      } catch (error) {
        window.Notify.show(error.message || "Failed to create the share link.", "error");
      }
    }

    document.getElementById("share-encrypted-btn").addEventListener("click", shareEncrypted);
    document.getElementById("share-plain-btn").addEventListener("click", sharePlainText);

    window.ClipboardUtil.setupButton(copyLinkBtn, () => shareLinkInput.value);

    // Reset the popover back to the menu when it closes, so reopening it
    // offers the share options again (the previous link stays valid).
    if (popover) {
      popover.addEventListener("toggle", function (event) {
        if (event.newState === "closed") {
          shareMenu.classList.remove("hidden");
          shareResult.classList.add("hidden");
        }
      });
    }
  });
})();
