/**
 * @fileoverview Serialized whole-document saves for the vault pages, exposed as
 * window.SaveQueue. DOM-free, so the ordering rules are Node-tested
 * (tests/js/save-queue.test.js).
 *
 * Both vaults keep one document in memory (the password vault's share list,
 * the note vault's index), show each change at once, and save by replacing the
 * whole encrypted document on the server. With whole-document saves, ordering
 * decides what survives:
 *
 * - One save at a time. Overlapping saves race, and whichever the server
 *   handles last wins, even when it carries the older document.
 * - A change made while a save is running is still sent. Changes made during
 *   a save are coalesced into one follow-up save of the newest document.
 * - A failed save restores the last document the server accepted and fails
 *   every change it did not store. Changes waiting behind the failed save were
 *   built on top of it, so they are discarded with it, and their callers are
 *   told so.
 * - Nothing is saved until the stored document has loaded. A save made from
 *   the empty pre-load state would replace everything stored.
 *
 * commit() resolves true only once the server accepted a document that
 * includes the change, so callers can order follow-up writes and success
 * messages after it.
 */
(function () {
  "use strict";

  /**
   * Create a save queue for one document.
   *
   * @template T
   * @param {Object} options
   * @param {function(T): Promise<boolean>} options.persist Save a whole document
   *   and resolve true once the server accepted it. A rejection counts as a
   *   failed save. Never called while a previous call is still pending.
   * @param {function(T): void} options.show Display a document: assign the
   *   page's state and re-render. Called for every commit, for load(), and when
   *   a failed save restores the last saved document.
   * @returns {{ready: boolean, busy: boolean, load: function(T): void,
   *   reset: function(): void,
   *   commit: function(function(T): T): Promise<boolean>}}
   */
  function create({ persist, show }) {
    let ready = false;
    let saved; // Last document the server accepted, or that was loaded from it.
    let latest; // Newest document, as shown.
    let queued = []; // Resolvers of commits that no started save includes yet.
    let running = false;
    // Bumped by load() and reset(). A save started in an older generation
    // still reports its outcome to its own commits, but no longer touches the
    // document: the page has replaced it since.
    let generation = 0;
    let runningIn = 0; // Generation of the running save.

    const settle = (resolvers, outcome) => {
      resolvers.forEach((resolve) => resolve(outcome));
    };

    const startNextSave = () => {
      if (running || queued.length === 0) return;
      const included = queued;
      queued = [];
      const snapshot = latest;
      const startedIn = generation;
      running = true;
      runningIn = startedIn;
      Promise.resolve()
        .then(() => persist(snapshot))
        .then(
          (accepted) => accepted === true,
          () => false,
        )
        .then((accepted) => {
          running = false;
          if (startedIn === generation) {
            if (accepted) {
              saved = snapshot;
            } else {
              const discarded = queued;
              queued = [];
              latest = saved;
              show(saved);
              settle(discarded, false);
            }
          }
          settle(included, accepted);
          startNextSave();
        });
    };

    return {
      /** @returns {boolean} Whether a document is loaded and commits are accepted. */
      get ready() {
        return ready;
      },

      /**
       * Whether a change shown on the page is not stored yet: a save is running
       * or a change waits for one. A save left over from before load() or
       * reset() doesn't count; the page no longer shows its document.
       *
       * @returns {boolean}
       */
      get busy() {
        return queued.length > 0 || (running && runningIn === generation);
      },

      /**
       * Start from the document the server holds: show it, make it the restore
       * point for failed saves, and accept commits. Commits still waiting from
       * before resolve false and are never sent.
       *
       * @param {T} doc Document as loaded from the server.
       */
      load(doc) {
        generation += 1;
        const dropped = queued;
        queued = [];
        saved = doc;
        latest = doc;
        ready = true;
        show(doc);
        settle(dropped, false);
      },

      /**
       * Forget the document, e.g. because the vault locked. Waiting commits
       * resolve false, and nothing is saved again until the next load().
       */
      reset() {
        generation += 1;
        const dropped = queued;
        queued = [];
        saved = undefined;
        latest = undefined;
        ready = false;
        settle(dropped, false);
      },

      /**
       * Show a change at once and save it after any save already running.
       *
       * @param {function(T): T} mutate Returns the changed document. It must
       *   leave its input unchanged, because the input may be the restore point.
       * @returns {Promise<boolean>} True once the server accepted a document
       *   that includes the change. False when the change was discarded: no
       *   document is loaded, the save failed, or the queue was reset.
       */
      commit(mutate) {
        if (!ready) return Promise.resolve(false);
        latest = mutate(latest);
        show(latest);
        return new Promise((resolve) => {
          queued.push(resolve);
          startNextSave();
        });
      },
    };
  }

  window.SaveQueue = { create };
})();
