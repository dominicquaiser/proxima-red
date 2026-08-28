/**
 * Tests for the pure helpers of static/note/js/live-sync.js
 * (window.NoteLiveSync): backoff schedule, poll jitter, the compaction
 * predicate, the WebSocket cursor-advance rule, the permanent/transient
 * failure split that decides whether a flush is retried, and the ws URL
 * builder. The
 * networked sync loop itself is exercised end-to-end in the browser; only
 * the deterministic logic is unit-tested here.
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

global.window = globalThis;
const source = fs.readFileSync(
  path.join(__dirname, "..", "..", "static", "note", "js", "live-sync.js"),
  "utf8",
);
vm.runInThisContext(source, { filename: "live-sync.js" });

const Sync = window.NoteLiveSync;

describe("nextBackoffMs", () => {
  test("starts at the minimum after a success (previous = 0)", () => {
    assert.equal(Sync.nextBackoffMs(0), Sync.BACKOFF_MIN_MS);
  });

  test("doubles per failure and caps at the maximum", () => {
    let delay = Sync.nextBackoffMs(0);
    const seen = [delay];
    for (let i = 0; i < 10; i++) {
      delay = Sync.nextBackoffMs(delay);
      seen.push(delay);
    }
    assert.deepEqual(seen.slice(0, 5), [5000, 10000, 20000, 40000, 60000]);
    assert.ok(seen.every((ms) => ms <= Sync.BACKOFF_MAX_MS));
    assert.equal(seen[seen.length - 1], Sync.BACKOFF_MAX_MS);
  });
});

describe("pollDelayMs", () => {
  test("visible tabs poll fast, hidden tabs slow", () => {
    assert.equal(Sync.pollDelayMs(false, 0.5), Sync.POLL_VISIBLE_MS);
    assert.equal(Sync.pollDelayMs(true, 0.5), Sync.POLL_HIDDEN_MS);
  });

  test("jitter stays within ±500ms of the base", () => {
    for (const rand of [0, 0.25, 0.5, 0.75, 0.999]) {
      const delay = Sync.pollDelayMs(false, rand);
      assert.ok(delay >= Sync.POLL_VISIBLE_MS - 500, `low bound for rand=${rand}`);
      assert.ok(delay <= Sync.POLL_VISIBLE_MS + 500, `high bound for rand=${rand}`);
    }
  });
});

describe("shouldCompact", () => {
  test("triggers at the threshold plus the client's jitter offset", () => {
    assert.equal(Sync.shouldCompact(Sync.COMPACT_PENDING_THRESHOLD - 1, 0), false);
    assert.equal(Sync.shouldCompact(Sync.COMPACT_PENDING_THRESHOLD, 0), true);
    assert.equal(Sync.shouldCompact(Sync.COMPACT_PENDING_THRESHOLD, 5), false);
    assert.equal(Sync.shouldCompact(Sync.COMPACT_PENDING_THRESHOLD + 5, 5), true);
  });

  test("client thresholds stay far under the server's hard cap of 512", () => {
    const worstCase = Sync.COMPACT_PENDING_THRESHOLD + Sync.COMPACT_JITTER_SPAN;
    assert.ok(worstCase < 512 / 2);
  });
});

describe("advanceCursor", () => {
  test("a gapless successor advances the cursor to its seq", () => {
    assert.deepEqual(Sync.advanceCursor(5, 5, 6), { cursor: 6, gap: false, stale: false });
  });

  test("prev_seq behind the cursor is fine (rows the poll already covered)", () => {
    assert.deepEqual(Sync.advanceCursor(8, 5, 9), { cursor: 9, gap: false, stale: false });
  });

  test("prev_seq ahead of the cursor flags a gap and does not advance", () => {
    assert.deepEqual(Sync.advanceCursor(5, 7, 8), { cursor: 5, gap: true, stale: false });
  });

  test("an already-applied row is stale and does not regress the cursor", () => {
    assert.deepEqual(Sync.advanceCursor(9, 5, 6), { cursor: 9, gap: false, stale: true });
    assert.deepEqual(Sync.advanceCursor(9, 8, 9), { cursor: 9, gap: false, stale: true });
  });

  test("fresh doc: first row after the seed snapshot (prev_seq 0)", () => {
    assert.deepEqual(Sync.advanceCursor(0, 0, 1), { cursor: 1, gap: false, stale: false });
  });
});

describe("isPermanentStatus", () => {
  test("treats client errors as permanent", () => {
    // A body the server calls malformed or oversized (400), or a rejected
    // CSRF token (403), is refused identically on every retry.
    assert.equal(Sync.isPermanentStatus(400), true);
    assert.equal(Sync.isPermanentStatus(403), true);
    assert.equal(Sync.isPermanentStatus(413), true);
  });

  test("treats rate limits, timeouts and server errors as transient", () => {
    // These are exactly the ones worth a backoff: retrying does work.
    assert.equal(Sync.isPermanentStatus(408), false);
    assert.equal(Sync.isPermanentStatus(429), false);
    assert.equal(Sync.isPermanentStatus(500), false);
    assert.equal(Sync.isPermanentStatus(502), false);
    assert.equal(Sync.isPermanentStatus(503), false);
  });

  test("does not claim success responses are permanent failures", () => {
    assert.equal(Sync.isPermanentStatus(200), false);
    assert.equal(Sync.isPermanentStatus(204), false);
  });
});

describe("isPermanentErrorCode", () => {
  test("a payload the server cannot store is permanent", () => {
    assert.equal(Sync.isPermanentErrorCode("update_too_large"), true);
    assert.equal(Sync.isPermanentErrorCode("invalid_frame"), true);
  });

  test("rate limits and server faults stay retryable", () => {
    assert.equal(Sync.isPermanentErrorCode("rate_limited"), false);
    assert.equal(Sync.isPermanentErrorCode("server_error"), false);
  });

  test("pending_tail_full is not permanent: compaction is its recovery", () => {
    assert.equal(Sync.isPermanentErrorCode("pending_tail_full"), false);
  });
});

describe("wsUrlFromPath", () => {
  test("maps https to wss and http to ws on the page host", () => {
    assert.equal(
      Sync.wsUrlFromPath("/ws/live/abc/", { protocol: "https:", host: "note.proxima.red" }),
      "wss://note.proxima.red/ws/live/abc/",
    );
    assert.equal(
      Sync.wsUrlFromPath("/ws/live/abc/", { protocol: "http:", host: "note.localhost:8000" }),
      "ws://note.localhost:8000/ws/live/abc/",
    );
  });

  test("a missing path yields no URL (socket disabled, polling only)", () => {
    assert.equal(Sync.wsUrlFromPath("", { protocol: "https:", host: "x" }), "");
    assert.equal(Sync.wsUrlFromPath(undefined, { protocol: "https:", host: "x" }), "");
  });
});
