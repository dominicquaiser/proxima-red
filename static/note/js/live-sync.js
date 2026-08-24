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
  // Consecutive compaction failures before the user is warned. Above a lost
  // race or a transient 5xx, below the server's pending-tail cap, so the
  // warning lands while edits still flow rather than after they stop.
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
  /** Create a sync client for one live note. */
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
      onStaleEpoch,
    } = opts;

    // Mutable so a rekey (M4 revocation) can swap the document key + epoch
    // without tearing down the sync client.
    let key = initialKey;
    let epoch = 0;

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
    // Consecutive failed compactions, and whether the user has been told the
    // document can no longer be compacted (see noteCompactOutcome).
    let compactFailures = 0;
    let warnedCompactStuck = false;

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
    // Inbound frames are applied strictly one at a time: decryption is
    // async, and letting frame N+1's gap check run against a cursor that
    // frame N hasn't advanced yet would trigger spurious gap fills.
    let wsInbox = Promise.resolve();

    function wsIsOpen() {
      return !!ws && ws.readyState === WebSocket.OPEN;
    }

    function setStatus(next) {
      if (stopped && next !== "expired" && next !== "error") return;
      if (status === next) return;
      status = next;
      if (onStatus) onStatus(next);
    }

    function refreshStatus() {
      if (stopped) return;
      if (backoffMs) setStatus("offline");
      else if (outbox.length || flushInFlight) setStatus("syncing");
      else setStatus("synced");
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

    // Apply a /state/ or /updates/ body. Returns false when nothing was
    // applied and the cursor was deliberately left where it was, so the same
    // range is refetched rather than skipped.
    async function applyServerBody(body) {
      // Every read echoes the current key generation, which is the only way a
      // client that isn't typing learns it was re-keyed: appends are what
      // trigger stale_epoch, and a passive reader makes none. Left undetected
      // it would keep decrypting rows with a dead key, skipping them all, and
      // still advance its cursor. Bail before applying or advancing: after
      // adoptRekey the next poll refetches this same range under the new key.
      if (typeof body.key_epoch === "number" && body.key_epoch !== epoch) {
        handleStaleEpoch();
        return false;
      }

      if (body.snapshot) {
        // Our cursor predates compaction; a Yjs snapshot update is CRDT-safe.
        try {
          const bytes = await window.CryptoCore.decryptBytes(body.snapshot, body.snapshot_iv, key);
          window.Y.applyUpdate(doc, bytes, "remote");
        } catch (error) {
          // Unlike a single bad row, an unreadable snapshot cannot be skipped
          // past: it *is* the history our cursor is missing. Hold the cursor
          // so a later key adoption can still recover, and say so once
          // instead of backing off silently forever.
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

    // Retry the flush after `delayMs`. Every retry path books the one
    // flushTimer slot, so flush()'s finally-block guard can tell that a retry
    // is already pending: scheduling a backed-off retry any other way lets
    // that guard fire an immediate flush on top of it and the backoff is
    // silently lost.
    function scheduleFlushAfter(delayMs) {
      if (stopped || flushTimer) return;
      flushTimer = setTimeout(function () {
        flushTimer = null;
        flush(false);
      }, delayMs);
    }

    function scheduleFlush() {
      scheduleFlushAfter(wsIsOpen() ? FLUSH_DEBOUNCE_WS_MS : FLUSH_DEBOUNCE_MS);
    }

    // Retry after a compaction that was meant to drain a full pending tail.
    // A drained tail earns a prompt retry; anything else has to back off, or
    // flush and compact ping-pong at the debounce interval against a tail
    // that cannot drain.
    function scheduleFlushAfterCompact(drained) {
      if (stopped) return;
      if (drained) {
        scheduleFlush();
        return;
      }
      backoffMs = nextBackoffMs(backoffMs);
      refreshStatus();
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
            key_epoch: epoch,
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

    async function flush(keepalive) {
      // Appends stay paused while a rekey recovery is pending: our key is
      // known-stale, so every attempt comes straight back as stale_epoch, and
      // the finally-block below would re-arm the next one a debounce later.
      // adoptRekey clears the flag and re-arms the flush itself.
      if (stopped || flushInFlight || staleEpochInFlight || !outbox.length) return;
      flushInFlight = true;
      const count = outbox.length;
      refreshStatus();

      if (wsIsOpen() && !keepalive) {
        await flushOverWs(count);
        return; // flushInFlight stays set until the ack (or socket close)
      }

      try {
        const merged = window.Y.mergeUpdates(outbox.slice(0, count));
        const payload = await window.CryptoCore.encryptBytesWithKey(merged, key);
        const useKeepalive = keepalive && payload.encryptedData.length < KEEPALIVE_BODY_LIMIT;
        const { response, result } = await postJson(
          urls.updates,
          { payload: payload.encryptedData, iv: payload.iv, key_epoch: epoch },
          useKeepalive,
        );

        if (response.status === 404) {
          fatal("expired", "This live note has expired.");
          return;
        }
        if (response.status === 409 && result && result.code === "stale_epoch") {
          // Rekeyed: pause appends and let the page recover the new key.
          flushInFlight = false;
          handleStaleEpoch();
          return;
        }
        if (response.status === 409) {
          // Pending tail full: compact to drain it, then retry the flush.
          flushInFlight = false;
          scheduleFlushAfterCompact(await compact());
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
      } catch (error) {
        // Keep the outbox; retry after a backoff (429, network, 5xx).
        backoffMs = nextBackoffMs(backoffMs);
        scheduleFlushAfter(backoffMs);
      } finally {
        flushInFlight = false;
        refreshStatus();
        if (!stopped && outbox.length && !flushTimer) scheduleFlush();
      }
    }

    // --- Rekey recovery (M4) ---

    let staleEpochInFlight = false;

    // Pause appends and ask the page to recover after a stale key epoch.
    function handleStaleEpoch() {
      if (stopped || staleEpochInFlight) return;
      staleEpochInFlight = true;
      setStatus("syncing");
      if (onStaleEpoch) {
        Promise.resolve(onStaleEpoch()).catch(function () {
          // Recovery failed (e.g. access revoked): the page decides the
          // terminal state; leave appends paused.
        });
      }
    }

    // --- Compaction ---

    function maybeCompact() {
      if (shouldCompact(pending, compactJitter)) compact();
    }

    // Full snapshot covering every row at or below current cursor.
    //
    // Mostly best-effort: losing a compaction race is normal and silent. But
    // a compaction that can never succeed (snapshot over the server cap, the
    // snapshot rate limit, an expired session on a restricted note) strands
    // the document once the pending tail fills, so repeated failures escalate
    // rather than staying quiet. Returns whether the snapshot was stored.
    async function compact() {
      // While a rekey recovery is pending our key is known-stale, so the
      // server would (correctly) refuse this snapshot anyway.
      if (stopped || compactInFlight || staleEpochInFlight) return false;
      compactInFlight = true;
      try {
        const coversSeq = cursor;
        if (!coversSeq) return false;
        const bytes = window.Y.encodeStateAsUpdate(doc);
        const payload = await window.CryptoCore.encryptBytesWithKey(bytes, key);
        const { response, result } = await postJson(urls.snapshot, {
          snapshot: payload.encryptedData,
          snapshot_iv: payload.iv,
          covers_seq: coversSeq,
          key_epoch: epoch,
        });
        if (response.status === 404) {
          fatal("expired", "This live note has expired.");
          return false;
        }
        if (response.status === 409 && result && result.code === "stale_epoch") {
          // Rekeyed: this snapshot is under the old key. Never retry it.
          // Storing it would replace the document with ciphertext no current
          // reader can open. Recover the new key instead.
          handleStaleEpoch();
          return false;
        }
        if (response.ok) {
          pending = 0;
          noteCompactOutcome(true);
          return true;
        }
        // A plain 409 is a lost race or a stale cursor: another client's
        // snapshot already covers us, so this is success by proxy.
        noteCompactOutcome(response.status === 409);
        return false;
      } catch (error) {
        noteCompactOutcome(false);
        return false;
      } finally {
        compactInFlight = false;
      }
    }

    // Escalate a compaction that keeps failing. Silent for the first few
    // attempts (a transient 5xx or a lost race is routine); past the
    // threshold the tail is filling with no way to drain it, which the user
    // needs to know about because their edits stop propagating.
    function noteCompactOutcome(ok) {
      if (ok) {
        compactFailures = 0;
        return;
      }
      compactFailures += 1;
      if (compactFailures < COMPACT_FAILURE_LIMIT || warnedCompactStuck) return;
      warnedCompactStuck = true;
      // Deliberately about the symptom, not the cause: the client cannot tell
      // an oversized snapshot from a rate limit from an expired session, and
      // all three end the same way for the user.
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
        wsFlush = null;
        if (ackTimer) clearTimeout(ackTimer);
        ackTimer = null;
        flushInFlight = false;
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
      if (msg.code === "stale_epoch") {
        wsFlush = null;
        if (ackTimer) clearTimeout(ackTimer);
        ackTimer = null;
        flushInFlight = false;
        handleStaleEpoch();
        return null;
      }
      if (msg.code === "pending_tail_full") {
        // Same recovery as the HTTP 409, backoff included.
        wsFlush = null;
        if (ackTimer) clearTimeout(ackTimer);
        ackTimer = null;
        flushInFlight = false;
        return compact().then(scheduleFlushAfterCompact);
      }
      if (wsFlush) {
        // rate_limited / invalid_frame / server_error while our flush was
        // pending: keep the outbox, retry after the shared backoff.
        wsFlush = null;
        if (ackTimer) clearTimeout(ackTimer);
        ackTimer = null;
        flushInFlight = false;
        backoffMs = nextBackoffMs(backoffMs);
        refreshStatus();
        scheduleFlushAfter(backoffMs);
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
        // Ack never arrived: outbox still has the updates for HTTP retry.
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
      if (typeof body.key_epoch === "number") epoch = body.key_epoch;

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
      /**
       * Current cursor + key epoch for owner rekey.
       *
       * @returns {{cursor: number, epoch: number, hasPending: boolean}}
       */
      rekeyContext: function () {
        return {
          cursor: cursor,
          epoch: epoch,
          hasPending: outbox.length > 0 || flushInFlight,
        };
      },
      /**
       * Flush now and resolve once the outbox has drained.
       *
       * @returns {Promise<boolean>}
       */
      flushNow: async function () {
        if (stopped) return false;
        if (flushTimer) {
          clearTimeout(flushTimer);
          flushTimer = null;
        }
        await flush(false);
        return outbox.length === 0 && !flushInFlight;
      },
      /**
       * Adopt a rotated document key + epoch after rekey recovery.
       *
       * @param {CryptoKey} newKey
       * @param {number} newEpoch
       */
      adoptRekey: function (newKey, newEpoch) {
        key = newKey;
        epoch = newEpoch;
        staleEpochInFlight = false;
        if (!stopped) {
          refreshStatus();
          if (outbox.length) scheduleFlush();
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
