/**
 * @fileoverview Live-note page controller: fragment-key handling, Y.Doc to
 * editor binding, sync status, presence, and expiry countdown.
 *
 * Fragment keys are scrubbed from the URL and stashed in tab sessionStorage
 * so refresh does not strand an active editing session.
 */
(function () {
  "use strict";

  const STATUS_LABELS = {
    loading: "loading",
    synced: "synced",
    syncing: "syncing",
    offline: "offline",
    expired: "expired",
    error: "error",
  };

  const KEY_STASH_PREFIX = "noteLiveKey:";
  const SIZE_WARNING =
    "This note is over the size limit and edits may stop saving. " +
    "Shorten it, or copy your work somewhere safe.";
  const COUNTDOWN_INTERVAL_MS = 1000;
  const EDITOR_PLACEHOLDER = "# Write your markdown here";

  /**
   * Format a remaining span as "2d 5h 3m 10s", dropping leading zero units.
   *
   * @param {number} remainingMs
   * @returns {string}
   */
  function expiryText(remainingMs) {
    const { days, hours, minutes, seconds } = window.TimeFmt.breakdown(remainingMs);
    const parts = [];
    if (days > 0) parts.push(days + "d");
    if (days > 0 || hours > 0) parts.push(hours + "h");
    parts.push(minutes + "m", seconds + "s");
    return parts.join(" ");
  }

  /**
   * Boot the live-note page: adopt the document key, bind the Y.Doc to the
   * editor, then start sync, presence, and the expiry countdown.
   *
   * Returns early (leaving the page in a terminal state) whenever the key is
   * missing, unusable, or the initial sync bootstrap fails.
   */
  async function initLiveNote() {
    const main = document.getElementById("main-content");
    const textarea = document.getElementById("note-content");
    const rail = document.querySelector(".rail");
    const statusPill = document.getElementById("live-status");
    const countdown = document.getElementById("live-countdown");
    if (!main || !textarea || !rail || !window.Y) return;

    const noteId = main.dataset.noteId;
    let countdownInterval = null;
    let terminal = false;
    let presence = null;

    function paintStatus(status) {
      if (!statusPill) return;
      statusPill.textContent = STATUS_LABELS[status] || status;
      statusPill.className = "live-status live-status--" + status;
    }

    /**
     * Freeze editing and sync while leaving the buffer readable and copyable.
     *
     * The text may exist nowhere else, so an expired or broken note stops
     * accepting edits rather than clearing or navigating away from them.
     * Idempotent: the first caller wins, so a later expiry cannot overwrite the
     * error that actually stopped the session.
     *
     * @param {"expired"|"error"} kind
     * @param {string} [message] Shown as a toast when given.
     */
    function enterTerminalState(kind, message) {
      if (terminal) return;
      terminal = true;
      textarea.readOnly = true;
      paintStatus(kind);
      if (countdown && kind === "expired") countdown.textContent = "expired";
      if (countdownInterval) clearInterval(countdownInterval);
      if (presence) presence.destroy();
      if (message) window.Notify.show(message, "error");
    }

    const doc = new window.Y.Doc();
    const ytext = doc.getText("content");

    let key = null;
    const keyStash = KEY_STASH_PREFIX + noteId;

    let fragmentKey = window.location.hash.slice(1);
    if (fragmentKey) {
      history.replaceState(null, document.title, window.location.pathname);
    } else {
      fragmentKey = sessionStorage.getItem(keyStash) || "";
    }

    if (fragmentKey) {
      try {
        key = await window.CryptoCore.importKeyFromBase64(decodeURIComponent(fragmentKey), [
          "encrypt",
          "decrypt",
        ]);
        try {
          sessionStorage.setItem(keyStash, fragmentKey);
        } catch (error) {
          /* storage unavailable */
        }
      } catch (error) {
        enterTerminalState("error", "The key in the link is not valid.");
        return;
      }
    } else {
      paintStatus("error");
      textarea.placeholder =
        "The decryption key is missing from the link. Open the complete " +
        "link, including everything after the # character.";
      enterTerminalState("error", "The decryption key is missing from the link.");
      return;
    }

    // Undo/redo lives in Yjs, not the textarea: only "local" transactions are
    // undoable (remote edits never are), and Yjs rebases undo items across
    // interleaved remote changes. That is also why the native textarea stack is
    // suppressed wholesale through the `history` handle passed to editor-core
    // below: remote splices land via setRangeText, which corrupts that stack.
    const undoManager = new window.Y.UndoManager(ytext, {
      trackedOrigins: new Set(["local"]),
    });

    // Store undo selection as relative positions so remote edits rebase it.
    undoManager.on("stack-item-added", function (event) {
      event.stackItem.meta.set("cursor", {
        anchor: window.Y.createRelativePositionFromTypeIndex(ytext, textarea.selectionStart),
        head: window.Y.createRelativePositionFromTypeIndex(ytext, textarea.selectionEnd),
      });
    });
    let poppedCursor = null;
    undoManager.on("stack-item-popped", function (event) {
      poppedCursor = event.stackItem.meta.get("cursor") || null;
    });

    /**
     * Turn a stored relative position back into a current offset.
     *
     * @param {Object} relative Y relative position captured when the undo item
     *   was pushed.
     * @param {number} fallback Used when the position no longer resolves, e.g.
     *   a peer deleted the text it pointed at.
     * @returns {number}
     */
    function resolveOffset(relative, fallback) {
      const abs = window.Y.createAbsolutePositionFromRelativePosition(relative, doc);
      return abs && abs.type === ytext ? abs.index : fallback;
    }

    /**
     * Run one undo or redo and restore the selection it was recorded with.
     *
     * @param {"undo"|"redo"} kind
     */
    function runHistory(kind) {
      if (terminal) return;
      poppedCursor = null;
      undoManager[kind]();
      if (!poppedCursor) return;
      const anchor = resolveOffset(poppedCursor.anchor, textarea.selectionStart);
      const head = resolveOffset(poppedCursor.head, textarea.selectionEnd);
      textarea.setSelectionRange(Math.min(anchor, head), Math.max(anchor, head));
      poppedCursor = null;
    }

    const core = window.NoteEditorCore.init({
      textarea,
      preview: document.getElementById("note-preview"),
      tabEdit: document.getElementById("tab-edit"),
      tabPreview: document.getElementById("tab-preview"),
      counter: document.getElementById("note-meta"),
      caret: document.getElementById("note-caret"),
      editor: main,
      rail,
      history: {
        undo: function () {
          runHistory("undo");
        },
        redo: function () {
          runHistory("redo");
        },
      },
    });

    // The static editors gate on size at share/save time; a live note has no
    // submit, so nothing was checking it and the first sign of trouble was
    // the server refusing an update. Warn on the way past the limit instead.
    // Deliberately advisory, not a block: the sync client halts and says so
    // if the server does refuse, and taking the keyboard away mid-sentence
    // would strand text the user still needs to copy out.
    const sizeLimitBytes = window.NoteEditorCore.MAX_NOTE_PLAINTEXT_BYTES;
    const encoder = new TextEncoder();
    let warnedTooLarge = false;

    /**
     * Warn once per crossing when the document passes the plaintext limit.
     *
     * @param {string} value Current buffer contents.
     */
    function checkSize(value) {
      const over = encoder.encode(value).length > sizeLimitBytes;
      // Re-arms when the note drops back under, so a user who trims and then
      // grows past the limit again is warned again rather than once a page.
      if (!over) {
        warnedTooLarge = false;
        return;
      }
      if (warnedTooLarge) return;
      warnedTooLarge = true;
      window.Notify.show(SIZE_WARNING, "error");
    }

    const sync = window.NoteLiveSync.create({
      doc,
      ytext,
      key,
      urls: {
        state: main.dataset.stateUrl,
        updates: main.dataset.updatesUrl,
        snapshot: main.dataset.snapshotUrl,
        ws: window.NoteLiveSync.wsUrlFromPath(main.dataset.wsPath, window.location),
      },
      onRemoteDelta: function (delta) {
        const splices = window.NoteLiveBinding.spliceListFromDelta(delta);
        if (!splices.length) return;
        const selStart = window.NoteLiveBinding.transformOffset(textarea.selectionStart, splices);
        const selEnd = window.NoteLiveBinding.transformOffset(textarea.selectionEnd, splices);
        core.applyRemoteSplices(splices, selStart, selEnd);
        // A collaborator's paste can push the document over the limit just as
        // easily as our own typing, and it is our updates that stop saving.
        checkSize(textarea.value);
      },
      onStatus: paintStatus,
      onFatal: enterTerminalState,
      onAwareness: function (payload, iv) {
        if (presence) presence.applyRemote(payload, iv);
      },
    });

    // Local edits enter Y.Text under "local" so sync queues them.
    core.onInput(function (value) {
      if (terminal) return;
      checkSize(value);
      const diff = window.NoteLiveBinding.diffText(ytext.toString(), value);
      if (!diff) return;
      doc.transact(function () {
        if (diff.removed) ytext.delete(diff.index, diff.removed.length);
        if (diff.inserted) ytext.insert(diff.index, diff.inserted);
      }, "local");
    });

    if (!(await sync.start())) return;

    core.setValue(ytext.toString());
    // The document may already be over the limit before we typed anything.
    checkSize(textarea.value);
    textarea.readOnly = false;
    textarea.placeholder = EDITOR_PLACEHOLDER;

    // Presence is encrypted and WebSocket-only; polling mode silently ages out.
    if (window.NoteLivePresence) {
      presence = window.NoteLivePresence.create({
        doc,
        ytext,
        textarea,
        editor: main,
        key,
        send: sync.sendAwareness,
      });
    }

    // Best-effort goodbye so peers drop our caret promptly.
    window.addEventListener("pagehide", function () {
      if (presence) presence.shutdown();
    });

    const expiresAtMs = Date.parse(main.dataset.expiresAt);

    /** Repaint the countdown, entering the terminal expired state at zero. */
    function updateExpiryCountdown() {
      if (!countdown || Number.isNaN(expiresAtMs)) return;
      const remainingMs = expiresAtMs - Date.now();
      if (remainingMs <= 0) {
        sync.stop();
        enterTerminalState(
          "expired",
          "This live note has expired. You can still copy or download the text.",
        );
        return;
      }
      countdown.textContent = expiryText(remainingMs);
    }

    updateExpiryCountdown();
    countdownInterval = setInterval(updateExpiryCountdown, COUNTDOWN_INTERVAL_MS);

    // Unsent local edits: warn before the tab goes away (the sync client
    // also best-effort keepalive-flushes on visibilitychange).
    window.addEventListener("beforeunload", function (event) {
      if (sync.hasPendingLocal()) {
        event.preventDefault();
        event.returnValue = "";
      }
    });
  }

  document.addEventListener("DOMContentLoaded", initLiveNote);
})();
