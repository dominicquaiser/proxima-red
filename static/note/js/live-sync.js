/**
 * @fileoverview Encrypted live-note sync client: WebSocket-first transport,
 * HTTP polling fallback, debounced Yjs update flushes, and compaction.
 *
 * Only ciphertext crosses the wire. The server stores/relays opaque update
 * blobs, while all merge logic stays in the browser/Yjs document.
 *
 * Cursor rules mirror apps/note/services.py: GET responses advance polling
 * cursors; WebSocket prev_seq/seq pairs expose gaps; 404 is terminal; bad
 * ciphertext rows are skipped once so convergence can continue.
 */
(function () {
  "use strict";

  const FLUSH_DEBOUNCE_MS = 1500;
  // Socket frames are cheap; keep remote carets near-live while merging bursts.
  const FLUSH_DEBOUNCE_WS_MS = 400;
  const POLL_VISIBLE_MS = 2500;
  const POLL_HIDDEN_MS = 30000;
  const POLL_JITTER_MS = 500;
  const BACKOFF_MIN_MS = 5000;
  const BACKOFF_MAX_MS = 60000;
  // If an update frame is never acked, close the socket and retry via HTTP.
  const WS_ACK_TIMEOUT_MS = 10000;
  // Server close codes (apps/note/constants.py).
  const WS_CLOSE_NOT_FOUND = 4404;
  const WS_CLOSE_ABUSE = 4429;
  // Jitter staggers concurrent compactors; server covers_seq settles races.
  const COMPACT_PENDING_THRESHOLD = 64;
  const COMPACT_JITTER_SPAN = 16;
  // Warn after repeated failures, before the pending tail reaches the server cap.
  const COMPACT_FAILURE_LIMIT = 4;
  // Browser keepalive bodies are capped around 64KB.
  const KEEPALIVE_BODY_LIMIT = 60000;

  /**
   * Next retry delay: BACKOFF_MIN_MS, then doubling to BACKOFF_MAX_MS.
   *
   * @param {number} previousMs
   * @returns {number}
   */
  function nextBackoffMs(previousMs) {
    if (!previousMs) return BACKOFF_MIN_MS;
    return Math.min(previousMs * 2, BACKOFF_MAX_MS);
  }

  /**
   * Poll delay for current tab visibility, with jitter.
   *
   * @param {boolean} hidden
   * @param {number} rand Random number in [0, 1).
   * @returns {number}
   */
  function pollDelayMs(hidden, rand) {
    const base = hidden ? POLL_HIDDEN_MS : POLL_VISIBLE_MS;
    return base + Math.round((rand * 2 - 1) * POLL_JITTER_MS);
  }

  /**
   * Whether this jittered client should compact now.
   *
   * @param {number} pending
   * @param {number} jitterOffset
   * @returns {boolean}
   */
  function shouldCompact(pending, jitterOffset) {
    return pending >= COMPACT_PENDING_THRESHOLD + jitterOffset;
  }

  /**
   * Advance the sync cursor for one WebSocket push or ack.
   *
   * prevSeq ahead of cursor means a missed frame; seq at/below cursor is an
   * already-applied row from poll overlap or own echo.
   *
   * @param {number} cursor
   * @param {number} prevSeq
   * @param {number} seq
   * @returns {{cursor: number, gap: boolean, stale: boolean}}
   */
  function advanceCursor(cursor, prevSeq, seq) {
    if (prevSeq > cursor) return { cursor, gap: true, stale: false };
    if (seq <= cursor) return { cursor, gap: false, stale: true };
    return { cursor: seq, gap: false, stale: false };
  }

  /**
   * Identify client errors that should halt retries of the current payload.
   *
   * Callers handle 404 (expired) and 409 (compaction needed) separately.
   * Timeouts, rate limits, and server failures remain retryable.
   *
   * @param {number} status HTTP response status.
   * @returns {boolean} True for a 4xx status other than 408 or 429.
   */
  function isPermanentStatus(status) {
    if (status === 408 || status === 429) return false;
    return status >= 400 && status < 500;
  }

  /**
   * Identify WebSocket errors that should halt retries of the current payload.
   *
   * A full pending tail triggers compaction; rate limits and server errors back off.
   *
   * @param {string} code Server error-frame code.
   * @returns {boolean} True for oversized updates or invalid frames.
   */
  function isPermanentErrorCode(code) {
    return code === "update_too_large" || code === "invalid_frame";
  }

  /**
   * Build the WebSocket URL for a socket path on the current origin.
   *
   * @param {string} path
   * @param {{protocol: string, host: string}} location
   * @returns {string}
   */
  function wsUrlFromPath(path, location) {
    if (!path) return "";
    const scheme = location.protocol === "https:" ? "wss://" : "ws://";
    return scheme + location.host + path;
  }

  /**
   * POST JSON with standard headers. Local because flush-on-hide needs keepalive.
   *
   * @param {string} url
   * @param {Object} body
   * @param {boolean} [keepalive=false]
   * @returns {Promise<{response: Response, result: ?Object}>}
   */
  async function postJson(url, body, keepalive) {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": window.Http.getCsrfToken() || "",
        "X-Requested-With": "XMLHttpRequest",
      },
      body: JSON.stringify(body),
      credentials: "same-origin",
      keepalive: !!keepalive,
    });
    let result = null;
    try {
      result = await response.json();
    } catch (error) {
      /* non-JSON reply (proxy error page); callers treat as failure */
    }
    return { response, result };
  }

  /**
   * @typedef {Object} SyncOptions
   * @property {Y.Doc} doc Document every update is applied to.
   * @property {Y.Text} ytext The document's shared text, observed for replay.
   * @property {CryptoKey} key Document key; every payload crosses the wire
   *   encrypted under it, and the server never holds it.
   * @property {{state: string, updates: string, snapshot: string, ws: string}} urls
   *   Endpoints for bootstrap, poll/POST, compaction, and the socket.
   * @property {function(Array<Object>): void} [onRemoteDelta] Y.Text delta for a
   *   change that did not originate in this tab.
   * @property {function(string): void} [onStatus] Status transitions, one of
   *   loading/synced/syncing/offline/expired/error.
   * @property {function(string, string): void} [onFatal] Terminal state: the page
   *   freezes the editor but keeps the buffer readable.
   * @property {function(string, string): void} [onAwareness] Encrypted presence
   *   frame (payload, iv) relayed from a peer.
   */

  /**
   * Create a sync client for one live note.
   *
   * @param {SyncOptions} opts
   * @returns {{start: function(): Promise<boolean>, stop: function(): void,
   *   hasPendingLocal: function(): boolean, isRealtime: function(): boolean,
   *   sendAwareness: function(string, string): void}}
   */
  function create(opts) {
    const {
      doc,
      ytext,
      key: initialKey,
      urls,
      onRemoteDelta,
      onStatus,
      onFatal,
      onAwareness,
    } = opts;

    const key = initialKey;

    const compactJitter = Math.floor(Math.random() * COMPACT_JITTER_SPAN);

    let cursor = 0;
    let pending = 0;
    let outbox = [];
    let stopped = false;
    let flushTimer = null;
    let flushInFlight = false;
    let compactInFlight = false;
    let pollTimer = null;
    let backoffMs = 0;
    let status = "loading";
    let warnedBadRow = false;
    let warnedBadSnapshot = false;
    // Compaction failures are counted consecutively; the warning is shown once.
    let compactFailures = 0;
    let warnedCompactStuck = false;
    // Halt retries of rejected updates while retaining unsaved content in outbox.
    let flushHalted = false;

    // WebSocket transport state. `ws` is non-null from construction attempt
    // to close; only an OPEN socket carries traffic (wsIsOpen).
    let ws = null;
    let wsBackoffMs = 0;
    let wsReconnectTimer = null;
    let wsGaveUp = false; // server said 4429: stay on polling for good
    let txnCounter = 0;
    let wsFlush = null; // {txn, count} awaiting its ack
    let ackTimer = null;
    let gapFillInFlight = false;
    // Serialize decryption and cursor advancement to avoid false sequence gaps.
    let wsInbox = Promise.resolve();

    function wsIsOpen() {
      return !!ws && ws.readyState === WebSocket.OPEN;
    }

    /** Clear acknowledgement state, retaining outbox updates for the caller to settle. */
    function clearWsFlushWait() {
      wsFlush = null;
      if (ackTimer) {
        clearTimeout(ackTimer);
        ackTimer = null;
      }
      flushInFlight = false;
    }

    function setStatus(next) {
      if (stopped && next !== "expired" && next !== "error") return;
      if (status === next) return;
      status = next;
      if (onStatus) onStatus(next);
    }

    function refreshStatus() {
      if (stopped) return;
      // A rejected local update keeps the error status even as remote edits arrive.
      if (flushHalted) return setStatus("error");
      if (backoffMs) setStatus("offline");
      else if (outbox.length || flushInFlight) setStatus("syncing");
      else setStatus("synced");
    }

    /**
     * Stop retrying rejected local updates, retaining the outbox for unsaved-work checks.
     * Remote sync and editing continue so the user can copy or download the buffer.
     */
    function haltFlush() {
      if (flushHalted) return;
      flushHalted = true;
      if (flushTimer) {
        clearTimeout(flushTimer);
        flushTimer = null;
      }
      clearWsFlushWait();
      setStatus("error");
      window.Notify.show(
        "This note's edits could not be saved and syncing has stopped. " +
          "Copy or download your work before closing this tab.",
        "error",
      );
    }

    function fatal(kind, message) {
      stop();
      setStatus(kind);
      if (onFatal) onFatal(kind, message);
    }

    function stop() {
      stopped = true;
      if (flushTimer) clearTimeout(flushTimer);
      if (pollTimer) clearTimeout(pollTimer);
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
      if (ackTimer) clearTimeout(ackTimer);
      flushTimer = null;
      pollTimer = null;
      wsReconnectTimer = null;
      ackTimer = null;
      if (ws) {
        const socket = ws;
        ws = null;
        try {
          socket.close();
        } catch (error) {
          /* already closing */
        }
      }
    }

    // --- Document wiring ---

    doc.on("update", function (update, origin) {
      if (stopped || origin === "remote") return;
      outbox.push(update);
      refreshStatus();
      scheduleFlush();
    });

    // Replay doc changes the textarea does not already contain.
    ytext.observe(function (event) {
      if (event.transaction.origin === "local") return;
      if (onRemoteDelta) onRemoteDelta(event.delta);
    });

    // Bad ciphertext is skipped once so tamper cannot block convergence.
    async function applyRow(row) {
      try {
        const bytes = await window.CryptoCore.decryptBytes(row.payload, row.iv, key);
        window.Y.applyUpdate(doc, bytes, "remote");
      } catch (error) {
        if (!warnedBadRow) {
          warnedBadRow = true;
          window.Notify.show(
            "Skipped an update that could not be decrypted (it may have been " +
              "tampered with). The rest of the document stays live.",
            "error",
          );
        }
      }
    }

    /**
     * Apply a server snapshot and update tail, then advance the polling cursor.
     *
     * @param {Object} body State or updates response.
     * @returns {Promise<boolean>} False when the snapshot cannot be read;
     *   the cursor stays unchanged so the missing history can be fetched again.
     */
    async function applyServerBody(body) {
      if (body.snapshot) {
        // Our cursor predates compaction; a Yjs snapshot update is CRDT-safe.
        try {
          const bytes = await window.CryptoCore.decryptBytes(body.snapshot, body.snapshot_iv, key);
          window.Y.applyUpdate(doc, bytes, "remote");
        } catch (error) {
          // A snapshot contains the missing history; advancing would skip it entirely.
          if (!warnedBadSnapshot) {
            warnedBadSnapshot = true;
            window.Notify.show(
              "Could not read this note's stored history with the current " +
                "key. Recent edits from others may be missing.",
              "error",
            );
          }
          return false;
        }
      }
      for (const row of body.updates) {
        await applyRow(row);
      }
      // A WebSocket push may have advanced cursor while this request was in flight.
      cursor = Math.max(cursor, body.seq);
      pending = body.pending;
      return true;
    }

    // --- Outbox flush ---

    /**
     * Schedule a flush in the shared timer slot, preserving backoff in flush's finally block.
     *
     * @param {number} delayMs Delay before retrying, in milliseconds.
     */
    function scheduleFlushAfter(delayMs) {
      if (stopped || flushHalted || flushTimer) return;
      flushTimer = setTimeout(function () {
        flushTimer = null;
        flush(false);
      }, delayMs);
    }

    function scheduleFlush() {
      scheduleFlushAfter(wsIsOpen() ? FLUSH_DEBOUNCE_WS_MS : FLUSH_DEBOUNCE_MS);
    }

    /**
     * Retry promptly after compaction succeeds; otherwise back off against a full tail.
     *
     * @param {boolean} drained Whether compaction stored a snapshot.
     */
    function scheduleFlushAfterCompact(drained) {
      if (stopped) return;
      if (drained) {
        scheduleFlush();
        return;
      }
      backoffFlush(true);
    }

    // Keep the outbox intact and reserve the one flushTimer slot for retry.
    function backoffFlush(refresh) {
      backoffMs = nextBackoffMs(backoffMs);
      if (refresh) refreshStatus();
      scheduleFlushAfter(backoffMs);
    }

    // Send merged outbox over WS; clear it only after the ack.
    async function flushOverWs(count) {
      try {
        const merged = window.Y.mergeUpdates(outbox.slice(0, count));
        const payload = await window.CryptoCore.encryptBytesWithKey(merged, key);
        if (!wsIsOpen()) throw new Error("socket closed during encrypt");
        wsFlush = { txn: ++txnCounter, count };
        ws.send(
          JSON.stringify({
            type: "update",
            txn: wsFlush.txn,
            payload: payload.encryptedData,
            iv: payload.iv,
          }),
        );
        ackTimer = setTimeout(function () {
          // No ack: close so onclose falls back to HTTP with outbox intact.
          if (ws) ws.close();
        }, WS_ACK_TIMEOUT_MS);
      } catch (error) {
        wsFlush = null;
        flushInFlight = false;
        refreshStatus();
        if (!stopped) scheduleFlush();
      }
    }

    async function postOutbox(count, keepalive) {
      const merged = window.Y.mergeUpdates(outbox.slice(0, count));
      const payload = await window.CryptoCore.encryptBytesWithKey(merged, key);
      const useKeepalive = keepalive && payload.encryptedData.length < KEEPALIVE_BODY_LIMIT;
      return postJson(
        urls.updates,
        { payload: payload.encryptedData, iv: payload.iv },
        useKeepalive,
      );
    }

    async function handleHttpFlushResponse(response, result, count) {
      if (response.status === 404) {
        fatal("expired", "This live note has expired.");
        return;
      }
      if (response.status === 409) {
        // Pending tail full: compact to drain it, then retry the flush.
        flushInFlight = false;
        scheduleFlushAfterCompact(await compact());
        return;
      }
      if (isPermanentStatus(response.status)) {
        haltFlush();
        return;
      }
      if (!response.ok || !result || !result.success) {
        throw new Error("flush failed");
      }

      // Do not advance cursor from POST result; polling owns that path.
      outbox.splice(0, count);
      pending = result.pending;
      backoffMs = 0;
      maybeCompact();
    }

    async function flushOverHttp(count, keepalive) {
      try {
        const { response, result } = await postOutbox(count, keepalive);
        await handleHttpFlushResponse(response, result, count);
      } catch (error) {
        // Keep the outbox; retry after a backoff (429, network, 5xx).
        backoffFlush();
      } finally {
        flushInFlight = false;
        refreshStatus();
        if (!stopped && outbox.length && !flushTimer) scheduleFlush();
      }
    }

    async function flush(keepalive) {
      // visibilitychange calls flush directly, bypassing the scheduler's guards.
      if (stopped || flushHalted || flushInFlight || !outbox.length) return;
      flushInFlight = true;
      const count = outbox.length;
      refreshStatus();

      if (wsIsOpen() && !keepalive) {
        await flushOverWs(count);
        return; // flushInFlight stays set until the ack (or socket close)
      }
      await flushOverHttp(count, keepalive);
    }

    // --- Compaction ---

    function maybeCompact() {
      if (shouldCompact(pending, compactJitter)) compact();
    }

    /**
     * Store a full snapshot covering all rows through the current cursor.
     *
     * Lost races do not count as failures; repeated refusals trigger a warning
     * because an uncompacted tail eventually prevents further updates.
     *
     * @returns {Promise<boolean>} Whether this request stored the snapshot.
     */
    async function compact() {
      if (stopped || compactInFlight) return false;
      compactInFlight = true;
      try {
        const coversSeq = cursor;
        if (!coversSeq) return false;
        const bytes = window.Y.encodeStateAsUpdate(doc);
        const payload = await window.CryptoCore.encryptBytesWithKey(bytes, key);
        const { response } = await postJson(urls.snapshot, {
          snapshot: payload.encryptedData,
          snapshot_iv: payload.iv,
          covers_seq: coversSeq,
        });
        if (response.status === 404) {
          fatal("expired", "This live note has expired.");
          return false;
        }
        if (response.ok) {
          pending = 0;
          noteCompactOutcome(true);
          return true;
        }
        // A 409 does not count as a failure: another snapshot may already cover us.
        noteCompactOutcome(response.status === 409);
        return false;
      } catch (error) {
        noteCompactOutcome(false);
        return false;
      } finally {
        compactInFlight = false;
      }
    }

    /**
     * Count consecutive compaction failures and warn once at the configured threshold.
     *
     * @param {boolean} ok Whether compaction succeeded or lost a race.
     */
    function noteCompactOutcome(ok) {
      if (ok) {
        compactFailures = 0;
        return;
      }
      compactFailures += 1;
      if (compactFailures < COMPACT_FAILURE_LIMIT || warnedCompactStuck) return;
      warnedCompactStuck = true;
      window.Notify.show(
        "This note's history could not be saved. Editing may stop working - " +
          "copy your work somewhere safe.",
        "error",
      );
    }

    // --- Poll loop (fallback transport; idle while the socket is open) ---

    function schedulePoll(delayMs) {
      if (stopped || wsIsOpen()) return;
      if (pollTimer) clearTimeout(pollTimer);
      pollTimer = setTimeout(poll, delayMs);
    }

    async function poll() {
      if (stopped) return;
      try {
        const { response, result } = await window.Http.getJson(urls.updates + "?since=" + cursor);
        if (response.status === 404) {
          fatal("expired", "This live note has expired.");
          return;
        }
        if (!response.ok || !result.success) {
          throw new Error("poll failed");
        }
        const applied = await applyServerBody(result);
        backoffMs = 0;
        if (applied) maybeCompact();
        refreshStatus();
        schedulePoll(pollDelayMs(document.hidden, Math.random()));
      } catch (error) {
        if (stopped) return;
        backoffMs = nextBackoffMs(backoffMs);
        refreshStatus();
        schedulePoll(backoffMs);
      }
    }

    // --- WebSocket transport (hot path) ---

    // Fill a WS sequence gap with one HTTP fetch inside the inbound queue.
    async function gapFill() {
      if (stopped || gapFillInFlight) return;
      gapFillInFlight = true;
      try {
        const { response, result } = await window.Http.getJson(urls.updates + "?since=" + cursor);
        if (response.status === 404) {
          fatal("expired", "This live note has expired.");
          return;
        }
        if (response.ok && result && result.success) {
          if (await applyServerBody(result)) maybeCompact();
        }
      } catch (error) {
        // Best effort: the next gap or fallback poll retries.
      } finally {
        gapFillInFlight = false;
      }
    }

    function handleAck(msg) {
      if (wsFlush && msg.txn === wsFlush.txn) {
        outbox.splice(0, wsFlush.count);
        clearWsFlushWait();
        pending = msg.pending;
        backoffMs = 0;
      }
      const advanced = advanceCursor(cursor, msg.prev_seq, msg.seq);
      cursor = advanced.cursor;
      refreshStatus();
      maybeCompact();
      if (!stopped && outbox.length && !flushTimer) scheduleFlush();
      return advanced.gap ? gapFill() : null;
    }

    function handleErrorFrame(msg) {
      if (msg.code === "pending_tail_full") {
        // Same recovery as the HTTP 409, backoff included.
        clearWsFlushWait();
        return compact().then(scheduleFlushAfterCompact);
      }
      if (isPermanentErrorCode(msg.code)) {
        haltFlush();
        return null;
      }
      if (wsFlush) {
        // rate_limited / server_error while our flush was pending: keep the
        // outbox, retry after the shared backoff.
        clearWsFlushWait();
        backoffFlush(true);
      }
      return null;
    }

    async function handleWsMessage(raw) {
      if (stopped) return;
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch (error) {
        return;
      }
      if (msg.type === "update") {
        const advanced = advanceCursor(cursor, msg.prev_seq, msg.seq);
        if (advanced.gap) {
          await gapFill(); // fetches this row too
          return;
        }
        if (advanced.stale) return; // already applied (poll overlap)
        await applyRow({ payload: msg.payload, iv: msg.iv });
        cursor = advanced.cursor;
        refreshStatus();
      } else if (msg.type === "ack") {
        await handleAck(msg);
      } else if (msg.type === "awareness") {
        if (onAwareness) onAwareness(msg.payload, msg.iv);
      } else if (msg.type === "error") {
        await handleErrorFrame(msg);
      } else if (msg.type === "expired") {
        fatal("expired", "This live note has expired.");
      }
    }

    function scheduleWsReconnect() {
      if (stopped || wsGaveUp || wsReconnectTimer || !urls.ws) return;
      wsBackoffMs = nextBackoffMs(wsBackoffMs);
      const jitter = Math.random() * 1000;
      wsReconnectTimer = setTimeout(function () {
        wsReconnectTimer = null;
        connectWs();
      }, wsBackoffMs + jitter);
    }

    function connectWs() {
      if (stopped || wsGaveUp || ws || !urls.ws) return;
      if (typeof WebSocket === "undefined") return;

      let socket;
      try {
        socket = new WebSocket(urls.ws);
      } catch (error) {
        scheduleWsReconnect();
        return;
      }
      ws = socket;

      socket.onopen = function () {
        if (stopped || ws !== socket) return;
        wsBackoffMs = 0;
        // Socket is hot path now; park polling and gap-fill missed commits.
        if (pollTimer) {
          clearTimeout(pollTimer);
          pollTimer = null;
        }
        wsInbox = wsInbox.then(function () {
          return gapFill();
        });
        if (outbox.length && !flushTimer && !flushInFlight) scheduleFlush();
      };

      socket.onmessage = function (event) {
        wsInbox = wsInbox
          .then(function () {
            return handleWsMessage(event.data);
          })
          .catch(function () {
            /* a poisoned frame must not stall the queue */
          });
      };

      socket.onclose = function (event) {
        if (ws !== socket) return;
        ws = null;
        // Release only a sent frame. An encrypting flush still owns flushInFlight
        // and clears it on failure; releasing it here could start a concurrent flush.
        if (wsFlush) {
          wsFlush = null;
          flushInFlight = false;
        }
        if (ackTimer) {
          clearTimeout(ackTimer);
          ackTimer = null;
        }
        if (stopped) return;
        if (event.code === WS_CLOSE_NOT_FOUND) {
          fatal("expired", "This live note has expired.");
          return;
        }
        if (event.code === WS_CLOSE_ABUSE) {
          wsGaveUp = true; // server asked us not to come back
        } else {
          scheduleWsReconnect();
        }
        // Fall back to polling without waiting for the next tick.
        schedulePoll(0);
        if (outbox.length && !flushTimer && !flushInFlight) scheduleFlush();
      };
    }

    document.addEventListener("visibilitychange", function () {
      if (stopped) return;
      if (document.hidden) {
        // Push unsaved edits while the request can still outlive the page.
        if (flushTimer) {
          clearTimeout(flushTimer);
          flushTimer = null;
        }
        flush(!wsIsOpen());
      } else if (!wsIsOpen()) {
        schedulePoll(0);
        if (wsReconnectTimer) {
          clearTimeout(wsReconnectTimer);
          wsReconnectTimer = null;
        }
        connectWs();
      }
    });

    // --- Boot ---

    /** @returns {Promise<boolean>} True after bootstrapping the live document. */
    async function start() {
      setStatus("loading");
      let body;
      try {
        const { response, result } = await window.Http.getJson(urls.state);
        if (response.status === 404) {
          fatal("expired", "This live note has expired.");
          return false;
        }
        if (!response.ok || !result.success) throw new Error("state fetch failed");
        body = result;
      } catch (error) {
        fatal("error", "Could not load the live note. Please try again.");
        return false;
      }

      try {
        const bytes = await window.CryptoCore.decryptBytes(body.snapshot, body.snapshot_iv, key);
        window.Y.applyUpdate(doc, bytes, "remote");
      } catch (error) {
        // Seed snapshot failure means wrong/tampered key.
        fatal(
          "error",
          "This link's key does not match the stored note. The link may be " +
            "incomplete, or the data may have been tampered with.",
        );
        return false;
      }

      for (const row of body.updates) {
        await applyRow(row);
      }
      cursor = body.seq;
      pending = body.pending;

      refreshStatus();
      maybeCompact();
      // Polling starts first; the socket parks it on open.
      schedulePoll(pollDelayMs(document.hidden, Math.random()));
      connectWs();
      return true;
    }

    return {
      start,
      stop,
      hasPendingLocal: function () {
        return outbox.length > 0 || flushInFlight;
      },
      isRealtime: wsIsOpen,
      /**
       * Send one encrypted awareness update; drop when socket is down.
       *
       * @param {string} payload
       * @param {string} iv
       */
      sendAwareness: function (payload, iv) {
        if (stopped || !wsIsOpen()) return;
        try {
          ws.send(JSON.stringify({ type: "awareness", payload: payload, iv: iv }));
        } catch (error) {
          /* racing a close; the 20s re-announce recovers */
        }
      },
    };
  }

  window.NoteLiveSync = {
    create,
    // Pure helpers, exposed for the Node tests (tests/js/live-sync.test.js).
    nextBackoffMs,
    pollDelayMs,
    shouldCompact,
    advanceCursor,
    isPermanentStatus,
    isPermanentErrorCode,
    wsUrlFromPath,
    FLUSH_DEBOUNCE_MS,
    FLUSH_DEBOUNCE_WS_MS,
    POLL_VISIBLE_MS,
    POLL_HIDDEN_MS,
    BACKOFF_MIN_MS,
    BACKOFF_MAX_MS,
    COMPACT_PENDING_THRESHOLD,
    COMPACT_JITTER_SPAN,
    WS_ACK_TIMEOUT_MS,
  };
})();
