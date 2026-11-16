/**
 * Tests for static/shared/js/save-queue.js (window.SaveQueue): the ordering
 * rules for the vaults' whole-document saves.
 *
 * Each test drives a queue whose saves are settled by hand, so it can pin
 * down what is sent and in which order, and what callers are told. Several
 * cases are the bugs the queue replaced: a change made during a running save
 * that was never sent (password vault), two overlapping saves where the older
 * document landed last (note vault), a failed save rolling back over a later
 * change, and a save from a page that had not finished loading replacing
 * everything stored.
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
vm.runInThisContext(
  fs.readFileSync(
    path.join(__dirname, "..", "..", "static", "shared", "js", "save-queue.js"),
    "utf8",
  ),
  { filename: "save-queue.js" },
);

const { create } = window.SaveQueue;

/** Let pending promise callbacks run. */
const settled = () => new Promise((resolve) => setImmediate(resolve));

/**
 * A queue over an array document whose saves the test finishes by hand.
 *
 * @returns {{queue: Object, sent: Array<{doc: Array, finish: function(*): void,
 *   fail: function(): void}>, shown: Array<Array>, maxInFlight: function(): number}}
 */
function harness() {
  const sent = [];
  const shown = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const queue = create({
    persist: (doc) =>
      new Promise((resolve, reject) => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        sent.push({
          doc,
          finish: (accepted) => {
            inFlight -= 1;
            resolve(accepted);
          },
          fail: () => {
            inFlight -= 1;
            reject(new Error("network down"));
          },
        });
      }),
    show: (doc) => shown.push(doc),
  });
  return { queue, sent, shown, maxInFlight: () => maxInFlight };
}

const add = (item) => (doc) => [...doc, item];

describe("SaveQueue: saving", () => {
  test("a commit shows the change at once and resolves true once saved", async () => {
    const { queue, sent, shown } = harness();
    queue.load([]);

    const outcome = queue.commit(add("a"));
    assert.deepEqual(shown.at(-1), ["a"]);
    await settled();
    assert.equal(sent.length, 1);
    assert.deepEqual(sent[0].doc, ["a"]);

    sent[0].finish(true);
    assert.equal(await outcome, true);
  });

  test("a change made during a running save is sent after it", async () => {
    // The password vault used to answer this second commit with true and never send it.
    const { queue, sent, maxInFlight } = harness();
    queue.load([]);

    const first = queue.commit(add("urgent"));
    await settled();
    const second = queue.commit((doc) => doc.filter((tag) => tag !== "work"));
    await settled();
    assert.equal(sent.length, 1, "the second save must wait for the first");

    sent[0].finish(true);
    assert.equal(await first, true);
    await settled();
    assert.equal(sent.length, 2);
    assert.deepEqual(sent[1].doc, ["urgent"]);

    sent[1].finish(true);
    assert.equal(await second, true);
    assert.equal(maxInFlight(), 1);
  });

  test("changes made during one save share a single follow-up save", async () => {
    const { queue, sent, maxInFlight } = harness();
    queue.load([]);

    const outcomes = [queue.commit(add("a"))];
    await settled();
    outcomes.push(queue.commit(add("b")), queue.commit(add("c")), queue.commit(add("d")));
    sent[0].finish(true);
    await settled();

    assert.equal(sent.length, 2);
    assert.deepEqual(sent[1].doc, ["a", "b", "c", "d"]);
    sent[1].finish(true);
    assert.deepEqual(await Promise.all(outcomes), [true, true, true, true]);
    assert.equal(maxInFlight(), 1);
  });

  test("the newest document is always the one sent last", async () => {
    // The note vault used to send both saves at once; if the first landed
    // last, the server kept the older index.
    const { queue, sent } = harness();
    queue.load([]);

    queue.commit(add("F1"));
    await settled();
    queue.commit(add("F2"));
    sent[0].finish(true);
    await settled();

    assert.deepEqual(sent.at(-1).doc, ["F1", "F2"]);
  });

  test("a commit resolves when its own save finishes, before any follow-up", async () => {
    const { queue, sent } = harness();
    queue.load([]);

    let firstDone = false;
    queue.commit(add("a")).then(() => {
      firstDone = true;
    });
    await settled();
    queue.commit(add("b"));
    sent[0].finish(true);
    await settled();

    assert.equal(firstDone, true);
    assert.equal(sent.length, 2, "the follow-up is still running");
  });

  test("busy covers a running save and changes waiting for one", async () => {
    const { queue, sent } = harness();
    queue.load([]);
    assert.equal(queue.busy, false);

    queue.commit(add("a"));
    queue.commit(add("b"));
    assert.equal(queue.busy, true);
    await settled();
    sent[0].finish(true);
    await settled();
    assert.equal(queue.busy, true, "the follow-up save is running");

    sent[1].finish(true);
    await settled();
    assert.equal(queue.busy, false);
  });

  test("busy ignores a save left over from before a reset", async () => {
    // The password vault locks (reset) before redirecting on sign-out; a
    // stale save must not make leaving the page ask for confirmation.
    const { queue } = harness();
    queue.load([]);

    queue.commit(add("a"));
    await settled();
    queue.reset();
    assert.equal(queue.busy, false);

    queue.load(["fresh"]);
    assert.equal(queue.busy, false);
    queue.commit(add("b"));
    assert.equal(queue.busy, true, "a new change waits behind the stale save");
  });
});

describe("SaveQueue: failed saves", () => {
  test("a failed save restores the saved document and fails every unsaved change", async () => {
    const { queue, sent, shown } = harness();
    queue.load(["x"]);

    const first = queue.commit(add("a"));
    await settled();
    const second = queue.commit(add("b"));
    sent[0].finish(false);

    assert.equal(await first, false);
    assert.equal(await second, false, "the waiting change was built on the failed one");
    assert.deepEqual(shown.at(-1), ["x"]);
    await settled();
    assert.equal(sent.length, 1, "a discarded change is never sent");
  });

  test("a failure restores the newest saved document, not the one before the change", async () => {
    // The vaults used to restore each commit's own snapshot, which could
    // predate a later change that had already been saved.
    const { queue, sent, shown } = harness();
    queue.load([]);

    queue.commit(add("a"));
    await settled();
    sent[0].finish(true);
    await settled();
    const failing = queue.commit(add("b"));
    await settled();
    sent[1].finish(false);

    assert.equal(await failing, false);
    assert.deepEqual(shown.at(-1), ["a"]);
  });

  test("a rejected save counts as failed", async () => {
    const { queue, sent, shown } = harness();
    queue.load(["x"]);

    const outcome = queue.commit(add("a"));
    await settled();
    sent[0].fail();

    assert.equal(await outcome, false);
    assert.deepEqual(shown.at(-1), ["x"]);
  });

  test("only an explicit true counts as accepted", async () => {
    const { queue, sent, shown } = harness();
    queue.load(["x"]);

    const outcome = queue.commit(add("a"));
    await settled();
    sent[0].finish({ success: true });

    assert.equal(await outcome, false);
    assert.deepEqual(shown.at(-1), ["x"]);
  });

  test("saving resumes normally after a failure", async () => {
    const { queue, sent } = harness();
    queue.load(["x"]);

    queue.commit(add("a"));
    await settled();
    sent[0].finish(false);
    await settled();
    const retry = queue.commit(add("b"));
    await settled();

    assert.deepEqual(sent[1].doc, ["x", "b"]);
    sent[1].finish(true);
    assert.equal(await retry, true);
  });
});

describe("SaveQueue: loading and reset", () => {
  test("commits are refused until a document has loaded", async () => {
    // A save from the empty pre-load state would replace everything stored.
    const { queue, sent, shown } = harness();

    assert.equal(queue.ready, false);
    assert.equal(await queue.commit(add("early")), false);
    await settled();
    assert.equal(sent.length, 0);
    assert.equal(shown.length, 0);
  });

  test("load shows the document and makes it the restore point", async () => {
    const { queue, sent, shown } = harness();
    queue.load(["stored"]);
    assert.equal(queue.ready, true);
    assert.deepEqual(shown.at(-1), ["stored"]);

    queue.commit(add("a"));
    await settled();
    sent[0].finish(false);
    await settled();
    assert.deepEqual(shown.at(-1), ["stored"]);
  });

  test("reset refuses further commits and fails the waiting ones", async () => {
    const { queue, sent } = harness();
    queue.load([]);

    queue.commit(add("a"));
    await settled();
    const waiting = queue.commit(add("b"));
    queue.reset();

    assert.equal(await waiting, false);
    assert.equal(queue.ready, false);
    assert.equal(await queue.commit(add("c")), false);
    sent[0].finish(true);
    await settled();
    assert.equal(sent.length, 1, "nothing queued before the reset is sent");
  });

  test("a save that was running at reset reports its outcome but restores nothing", async () => {
    const { queue, sent, shown } = harness();
    queue.load(["x"]);

    const running = queue.commit(add("a"));
    await settled();
    queue.reset();
    const shownAtReset = shown.length;
    sent[0].finish(false);

    assert.equal(await running, false);
    assert.equal(shown.length, shownAtReset, "the locked page's state must not come back");
  });

  test("after a reload, new saves still wait for one left over from before", async () => {
    const { queue, sent, maxInFlight } = harness();
    queue.load([]);

    const stale = queue.commit(add("a"));
    await settled();
    queue.reset();
    queue.load(["fresh"]);
    const fresh = queue.commit(add("b"));
    await settled();
    assert.equal(sent.length, 1, "the new save waits for the stale one");

    sent[0].finish(true);
    assert.equal(await stale, true, "the stale save still reports its real outcome");
    await settled();
    assert.deepEqual(sent[1].doc, ["fresh", "b"]);
    sent[1].finish(true);
    assert.equal(await fresh, true);
    assert.equal(maxInFlight(), 1);
  });

  test("a stale save that succeeds does not become the restore point", async () => {
    const { queue, sent, shown } = harness();
    queue.load([]);

    queue.commit(add("old"));
    await settled();
    queue.load(["fresh"]);
    sent[0].finish(true);
    await settled();
    queue.commit(add("b"));
    await settled();
    sent[1].finish(false);
    await settled();

    assert.deepEqual(shown.at(-1), ["fresh"]);
  });
});
