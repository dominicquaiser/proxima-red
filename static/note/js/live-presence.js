/**
 * @fileoverview Encrypted live-note presence: remote carets, selections, and
 * anonymous session identities.
 *
 * Cursor positions use Yjs relative positions so they survive concurrent
 * edits. Frames are WebSocket-only and encrypted under the document key.
 */
(function () {
  "use strict";

  const CURSOR_ANNOUNCE_MS = 150;
  const REANNOUNCE_MS = 20000;
  const MIRROR_CLASS = "editor__text editor__caret-mirror";
  const LAYER_CLASS = "presence-layer";
  const SELECTION_CLASS = "presence-selection";
  const CARET_CLASS = "presence-caret";
  const DEFAULT_PEER_NAME = "Peer";
  const MIN_SELECTION_WIDTH = 3;
  const ZERO_WIDTH_SPACE = "\u200b";

  const GREEK_NAMES = [
    "Alpha",
    "Beta",
    "Gamma",
    "Delta",
    "Epsilon",
    "Zeta",
    "Eta",
    "Theta",
    "Iota",
    "Kappa",
    "Lambda",
    "Mu",
    "Nu",
    "Xi",
    "Omicron",
    "Pi",
    "Rho",
    "Sigma",
    "Tau",
    "Upsilon",
    "Phi",
    "Chi",
    "Psi",
    "Omega",
  ];
  const PALETTE_SIZE = 8;

  /**
   * Deterministic anonymous identity for a Yjs clientID.
   *
   * @param {number} clientId
   * @returns {{name: string, colorIndex: number}}
   */
  function identityFor(clientId) {
    const nameHash = Math.imul(clientId, 0x9e3779b1) >>> 0;
    const colorHash = Math.imul(clientId, 0x85ebca6b) >>> 0;
    return {
      name: GREEK_NAMES[((nameHash >>> 16) * GREEK_NAMES.length) >>> 16],
      colorIndex: colorHash >>> 29, // top 3 bits: 0..7
    };
  }

  /**
   * Encode a textarea selection as JSON-safe relative positions.
   *
   * @param {Y.Text} ytext
   * @param {number} anchor
   * @param {number} head
   * @returns {{anchor: string, head: string}}
   */
  function encodeCursorState(ytext, anchor, head) {
    const encode = function (offset) {
      const rel = window.Y.createRelativePositionFromTypeIndex(ytext, offset);
      return window.CryptoCore.bufferToBase64(window.Y.encodeRelativePosition(rel));
    };
    return { anchor: encode(anchor), head: encode(head) };
  }

  /**
   * Resolve an encoded cursor against the local document.
   *
   * @param {Y.Doc} doc
   * @param {Y.Text} ytext
   * @param {?{anchor: string, head: string}} cursor
   * @returns {?{anchor: number, head: number}}
   */
  function resolveCursorState(doc, ytext, cursor) {
    if (!cursor || !cursor.anchor || !cursor.head) return null;
    const resolve = function (encoded) {
      let rel;
      try {
        rel = window.Y.decodeRelativePosition(
          new Uint8Array(window.CryptoCore.base64ToBuffer(encoded)),
        );
      } catch (error) {
        return null;
      }
      const abs = window.Y.createAbsolutePositionFromRelativePosition(rel, doc);
      return abs && abs.type === ytext ? abs.index : null;
    };
    const anchor = resolve(cursor.anchor);
    const head = resolve(cursor.head);
    if (anchor === null || head === null) return null;
    return { anchor: anchor, head: head };
  }

  /** Wire presence for one live-note session. */
  function create(opts) {
    const { doc, ytext, textarea, editor, send } = opts;
    const key = opts.key;

    const awareness = new window.Y.awareness.Awareness(doc);
    const identity = identityFor(doc.clientID);
    awareness.setLocalState({
      user: { name: identity.name, color: identity.colorIndex },
      cursor: null,
    });

    // Hidden layout replica for caret/selection measurement.
    const mirror = document.createElement("div");
    mirror.className = MIRROR_CLASS;
    mirror.setAttribute("aria-hidden", "true");
    textarea.insertAdjacentElement("afterend", mirror);

    const layer = document.createElement("div");
    layer.className = LAYER_CLASS;
    layer.setAttribute("aria-hidden", "true");
    textarea.insertAdjacentElement("afterend", layer);

    let destroyed = false;
    let announceTimer = null;
    let announceInFlight = false;
    let announceAgain = false;
    let renderQueued = false;
    let lastCursorKey = "";

    async function announce() {
      if (destroyed) return;
      if (announceInFlight) {
        announceAgain = true;
        return;
      }
      announceInFlight = true;
      try {
        const update = window.Y.awareness.encodeAwarenessUpdate(awareness, [doc.clientID]);
        const payload = await window.CryptoCore.encryptBytesWithKey(update, key);
        send(payload.encryptedData, payload.iv);
      } catch (error) {
      } finally {
        announceInFlight = false;
        if (announceAgain) {
          announceAgain = false;
          announce();
        }
      }
    }

    function throttledAnnounce() {
      if (destroyed || announceTimer) return;
      announceTimer = setTimeout(function () {
        announceTimer = null;
        announce();
      }, CURSOR_ANNOUNCE_MS);
    }

    function updateLocalCursor() {
      if (destroyed) return;
      let cursor = null;
      if (document.activeElement === textarea) {
        // anchor/head from the DOM's directionality so backward selections
        // carry the caret at the correct end.
        const backward = textarea.selectionDirection === "backward";
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        cursor = backward
          ? encodeCursorState(ytext, end, start)
          : encodeCursorState(ytext, start, end);
      }
      const cursorKey = cursor ? cursor.anchor + "|" + cursor.head : "";
      if (cursorKey === lastCursorKey) return;
      lastCursorKey = cursorKey;
      awareness.setLocalStateField("cursor", cursor);
      throttledAnnounce();
    }

    const reannounceInterval = setInterval(function () {
      // Refresh the awareness clock; peers prune silent clients after 30s.
      const state = awareness.getLocalState();
      if (!state) return;
      awareness.setLocalStateField("user", state.user);
      announce();
    }, REANNOUNCE_MS);

    async function applyRemote(payload, iv) {
      if (destroyed) return;
      try {
        const bytes = await window.CryptoCore.decryptBytes(payload, iv, key);
        window.Y.awareness.applyAwarenessUpdate(awareness, bytes, "remote");
      } catch (error) {
        // Undecryptable presence is dropped silently: it is ephemeral, and
        // warning here would spam (unlike a persisted update row).
      }
    }

    function scheduleRender() {
      if (destroyed || renderQueued) return;
      renderQueued = true;
      window.requestAnimationFrame(function () {
        renderQueued = false;
        render();
      });
    }

    /**
     * Measure one remote cursor in the hidden mirror.
     *
     * @param {number} anchor
     * @param {number} head
     * @returns {{caret: ?DOMRect, lines: DOMRect[]}}
     */
    function measureCursor(anchor, head) {
      const value = textarea.value;
      const start = Math.min(anchor, head);
      const end = Math.max(anchor, head);
      const marker = document.createElement("span");
      marker.textContent = ZERO_WIDTH_SPACE;

      if (start === end) {
        mirror.replaceChildren(
          document.createTextNode(value.slice(0, start)),
          marker,
          document.createTextNode(value.slice(start)),
        );
        return { caret: marker.getBoundingClientRect(), lines: [] };
      }

      const selectionSpan = document.createElement("span");
      selectionSpan.textContent = value.slice(start, end);
      const children = [document.createTextNode(value.slice(0, start))];
      if (head === start) children.push(marker, selectionSpan);
      else children.push(selectionSpan, marker);
      children.push(document.createTextNode(value.slice(end)));
      mirror.replaceChildren.apply(mirror, children);

      return {
        caret: marker.getBoundingClientRect(),
        lines: Array.prototype.slice.call(selectionSpan.getClientRects()),
      };
    }

    function render() {
      if (destroyed) return;
      layer.replaceChildren();
      const editorRect = editor.getBoundingClientRect();
      const states = awareness.getStates();

      states.forEach(function (state, clientId) {
        if (clientId === doc.clientID || !state || !state.cursor) return;
        const offsets = resolveCursorState(doc, ytext, state.cursor);
        if (!offsets) return;

        const user = state.user || {};
        const colorIndex = normalizeColorIndex(user.color);
        const colorVar = "var(--presence-" + colorIndex + ")";
        const name = typeof user.name === "string" ? user.name.slice(0, 16) : DEFAULT_PEER_NAME;
        const geometry = measureCursor(offsets.anchor, offsets.head);

        for (const line of geometry.lines) {
          if (line.bottom < editorRect.top || line.top > editorRect.bottom) continue;
          const highlight = document.createElement("div");
          highlight.className = SELECTION_CLASS;
          highlight.style.setProperty("--cc", colorVar);
          highlight.style.left = line.left + "px";
          highlight.style.top = line.top + "px";
          highlight.style.width = Math.max(line.width, MIN_SELECTION_WIDTH) + "px";
          highlight.style.height = line.height + "px";
          layer.appendChild(highlight);
        }

        const caretRect = geometry.caret;
        if (
          caretRect &&
          caretRect.top + caretRect.height >= editorRect.top &&
          caretRect.top <= editorRect.bottom &&
          caretRect.left >= editorRect.left &&
          caretRect.left <= editorRect.right
        ) {
          const caret = document.createElement("div");
          caret.className = CARET_CLASS;
          caret.dataset.name = name;
          caret.style.setProperty("--cc", colorVar);
          caret.style.left = caretRect.left + "px";
          caret.style.top = caretRect.top + "px";
          caret.style.height = caretRect.height + "px";
          layer.appendChild(caret);
        }
      });

      mirror.replaceChildren();
    }

    function normalizeColorIndex(color) {
      return typeof color === "number" ? ((color % PALETTE_SIZE) + PALETTE_SIZE) % PALETTE_SIZE : 0;
    }

    function onSelectionChange() {
      if (document.activeElement === textarea) updateLocalCursor();
    }
    function onBlur() {
      updateLocalCursor();
    }
    function onDocUpdate() {
      scheduleRender();
    }
    function onAwarenessChange() {
      scheduleRender();
    }

    document.addEventListener("selectionchange", onSelectionChange);
    textarea.addEventListener("focus", updateLocalCursor);
    textarea.addEventListener("blur", onBlur);
    textarea.addEventListener("keyup", onSelectionChange);
    textarea.addEventListener("click", onSelectionChange);
    editor.addEventListener("scroll", scheduleRender, { passive: true });
    window.addEventListener("resize", scheduleRender);
    awareness.on("change", onAwarenessChange);
    doc.on("update", onDocUpdate);

    // First hello: name/colour with no cursor yet.
    announce();

    /** Best-effort goodbye so peers drop this cursor promptly. */
    function shutdown() {
      if (destroyed) return;
      awareness.setLocalState(null);
      // Synchronous best effort: encode + send may not finish encryption
      // before the page dies; peers fall back to the 30s timeout.
      announce();
    }

    function destroy() {
      if (destroyed) return;
      destroyed = true;
      clearInterval(reannounceInterval);
      if (announceTimer) clearTimeout(announceTimer);
      document.removeEventListener("selectionchange", onSelectionChange);
      textarea.removeEventListener("focus", updateLocalCursor);
      textarea.removeEventListener("blur", onBlur);
      textarea.removeEventListener("keyup", onSelectionChange);
      textarea.removeEventListener("click", onSelectionChange);
      editor.removeEventListener("scroll", scheduleRender);
      window.removeEventListener("resize", scheduleRender);
      awareness.off("change", onAwarenessChange);
      doc.off("update", onDocUpdate);
      awareness.destroy();
      layer.remove();
      mirror.remove();
    }

    return {
      awareness: awareness,
      applyRemote: applyRemote,
      announce: announce,
      shutdown: shutdown,
      destroy: destroy,
    };
  }

  window.NoteLivePresence = {
    create,
    // Pure helpers, exposed for the Node tests (tests/js/live-presence.test.js).
    identityFor,
    encodeCursorState,
    resolveCursorState,
    GREEK_NAMES,
    PALETTE_SIZE,
    CURSOR_ANNOUNCE_MS,
    REANNOUNCE_MS,
  };
})();
