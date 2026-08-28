/**
 * @fileoverview DOM-free batching and retry rules for the password-change
 * vault migration, exposed as window.VaultMigration.
 *
 * Extracted from account.js so the bounds can be unit-tested: they are the
 * one place where two client caps (notes per POST, characters per POST) meet
 * two server limits (nginx client_max_body_size, Django
 * DATA_UPLOAD_MAX_MEMORY_SIZE), and a batch that outgrows either aborts the
 * migration mid-flight.
 *
 * That abort is unrecoverable, which is why these bounds are worth pinning.
 * By the time batches are sent the password has already rotated, so the
 * server has replaced vault_salt and the old vault key survives only in the
 * changing page's memory. An abandoned batch strands rows under two keys
 * with no way back, and because the index travels in the final batch it stays
 * under the old key too, locking the whole vault.
 */
(function () {
  "use strict";

  // Each POST must stay under Django's default DATA_UPLOAD_MAX_MEMORY_SIZE
  // (2.5MB) and nginx's client_max_body_size (2m). The character budget is
  // what actually bounds a batch; the note count only matters for small
  // notes, where too low a cap turns a 200-note vault into enough POSTs to
  // run into the migrate rate limit.
  const BATCH_MAX_NOTES = 25;
  const BATCH_MAX_CHARS = 1500000;

  // A rate-limited batch is waited out rather than abandoned (see the file
  // comment on why abandoning is unrecoverable). Roughly one rate-limit
  // window in total.
  const RETRY_DELAYS_MS = [5000, 20000, 60000];

  /**
   * Split re-encrypted note payloads into POST-sized batches.
   *
   * Always returns at least one (possibly empty) batch, so the caller has a
   * final batch for the index payload to ride in even when the vault holds
   * no notes.
   *
   * A note larger than the character budget still goes out alone rather than
   * being dropped: the server caps a single note's ciphertext well below the
   * budget, so this only matters if that cap is ever raised, and losing the
   * note would be far worse than an oversized request.
   *
   * @param {Array<{id: string, content: string, iv: string}>} items
   * @returns {Array<Array<Object>>} Batches in submission order.
   */
  function batchNotePayloads(items) {
    const batches = [[]];
    let chars = 0;
    for (const item of items) {
      const last = batches[batches.length - 1];
      if (
        last.length >= BATCH_MAX_NOTES ||
        (last.length > 0 && chars + item.content.length > BATCH_MAX_CHARS)
      ) {
        batches.push([]);
        chars = 0;
      }
      batches[batches.length - 1].push(item);
      chars += item.content.length;
    }
    return batches;
  }

  /**
   * Whether a failed migration batch is worth sending again.
   *
   * Only a rate limit is: the endpoint answers block=False (JSON 429)
   * specifically so this is distinguishable from a rejected CSRF token or a
   * validation error, neither of which retrying would fix. Retrying a 403
   * would spin against a token that is never going to be accepted.
   *
   * @param {number} status
   * @returns {boolean}
   */
  function isRetryableMigrationStatus(status) {
    return status === 429;
  }

  window.VaultMigration = {
    batchNotePayloads,
    isRetryableMigrationStatus,
    BATCH_MAX_NOTES,
    BATCH_MAX_CHARS,
    RETRY_DELAYS_MS,
  };
})();
