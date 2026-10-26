/**
 * Tests for static/auth/js/vault-migration.js (window.VaultMigration): the
 * batching bounds and retry predicate for the password-change vault
 * migration.
 *
 * These bounds sit between two runtimes, so the interesting assertions are
 * the cross-runtime ones: the server's per-note cap and per-user quota
 * (apps/note/constants.py) decide how many POSTs a full vault needs, and that
 * count has to fit the migrate rate limit while every individual POST stays
 * under nginx's client_max_body_size. Those Python values are read out of the
 * source rather than restated here, so raising a cap or lowering the limit
 * fails this test instead of silently reintroducing the bug it guards:
 * a batch refused mid-migration is unrecoverable, because by then the
 * password has rotated and the old vault key exists only in the changing
 * page's memory.
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");

global.window = globalThis;
vm.runInThisContext(
  fs.readFileSync(path.join(ROOT, "static", "auth", "js", "vault-migration.js"), "utf8"),
  { filename: "vault-migration.js" },
);

const Migration = window.VaultMigration;

// --- The server-side half of the contract ---------------------------------

const notePySource = fs.readFileSync(path.join(ROOT, "apps", "note", "constants.py"), "utf8");

/** Read `NAME: Final[int] = 1_234` out of apps/note/constants.py. */
function pyInt(name) {
  const match = notePySource.match(new RegExp(`^${name}:[^=]*=\\s*([0-9_]+)`, "m"));
  assert.ok(match, `${name} not found in apps/note/constants.py`);
  return Number(match[1].replace(/_/g, ""));
}

/** Read the numerator of a `NAME: Final[str] = "60/m"` rate limit. */
function pyRatePerMinute(name) {
  const match = notePySource.match(new RegExp(`^${name}:[^=]*=\\s*"(\\d+)/m"`, "m"));
  assert.ok(match, `${name} not found (or not per-minute) in apps/note/constants.py`);
  return Number(match[1]);
}

const MAX_VAULT_NOTES_PER_USER = pyInt("MAX_VAULT_NOTES_PER_USER");
const MAX_VAULT_NOTE_CONTENT_LENGTH = pyInt("MAX_VAULT_NOTE_CONTENT_LENGTH");
const RATE_LIMIT_VAULT_MIGRATE = pyRatePerMinute("RATE_LIMIT_VAULT_MIGRATE");

// nginx `client_max_body_size 2m` in deployment/nginx/default.conf.template,
// the tighter of the two body limits (Django's default is 2.5MB).
const NGINX_BODY_LIMIT_BYTES = 2 * 1024 * 1024;

/** A batch of `count` notes whose ciphertext is `size` characters each. */
function notes(count, size) {
  return Array.from({ length: count }, (_, i) => ({
    id: `note-${i}`,
    content: "x".repeat(size),
    iv: "AAAAAAAAAAAAAAAA",
  }));
}

const batchChars = (batch) => batch.reduce((sum, item) => sum + item.content.length, 0);

describe("batchNotePayloads", () => {
  test("returns one empty batch for an empty vault", () => {
    // Not an edge case for its own sake: the re-encrypted index rides the
    // final batch, so a user with an index but no notes still needs one.
    assert.deepEqual(Migration.batchNotePayloads([]), [[]]);
  });

  test("splits on the note count when notes are small", () => {
    const batches = Migration.batchNotePayloads(notes(Migration.BATCH_MAX_NOTES + 1, 10));
    assert.equal(batches.length, 2);
    assert.equal(batches[0].length, Migration.BATCH_MAX_NOTES);
    assert.equal(batches[1].length, 1);
  });

  test("splits on the character budget when notes are large", () => {
    // Well under BATCH_MAX_NOTES items, so only the budget can be splitting.
    const size = Math.floor(Migration.BATCH_MAX_CHARS / 3);
    const batches = Migration.batchNotePayloads(notes(4, size));
    assert.equal(batches.length, 2);
    assert.equal(batches[0].length, 3);
    for (const batch of batches) {
      assert.ok(batchChars(batch) <= Migration.BATCH_MAX_CHARS);
    }
  });

  test("never drops a note, whatever the split", () => {
    const items = [
      ...notes(3, 5),
      ...notes(2, Math.floor(Migration.BATCH_MAX_CHARS / 2)),
      ...notes(30, 100),
    ];
    const flattened = Migration.batchNotePayloads(items).flat();
    assert.equal(flattened.length, items.length);
    assert.deepEqual(
      flattened.map((item) => item.content.length),
      items.map((item) => item.content.length),
    );
  });

  test("sends an over-budget note alone rather than dropping it", () => {
    // Unreachable while the server caps a note below the budget, but losing
    // a note would be far worse than an oversized request, so it must not
    // silently vanish if that cap is ever raised.
    const oversized = notes(1, Migration.BATCH_MAX_CHARS + 1);
    const batches = Migration.batchNotePayloads([...oversized, ...notes(1, 10)]);
    assert.equal(batches[0].length, 1);
    assert.equal(batches.flat().length, 2);
  });
});

describe("migration bounds vs. the server's own limits", () => {
  test("a full vault of max-size notes fits inside one rate-limit window", () => {
    // The regression this whole module exists for: at the old 10/m, a full
    // vault needed ~29 POSTs and the 11th was refused mid-migration.
    const batches = Migration.batchNotePayloads(
      notes(MAX_VAULT_NOTES_PER_USER, MAX_VAULT_NOTE_CONTENT_LENGTH),
    );
    assert.ok(
      batches.length <= RATE_LIMIT_VAULT_MIGRATE,
      `a full vault needs ${batches.length} POSTs but the limit is ` +
        `${RATE_LIMIT_VAULT_MIGRATE}/m`,
    );
  });

  test("a full vault of small notes fits too", () => {
    const batches = Migration.batchNotePayloads(notes(MAX_VAULT_NOTES_PER_USER, 6800));
    assert.ok(batches.length <= RATE_LIMIT_VAULT_MIGRATE);
  });

  test("no batch can exceed the proxy's body limit", () => {
    // Characters are the budget's unit; the ciphertext is Base64, so one
    // character is one byte on the wire. Compared against the raw limit
    // without a JSON-overhead allowance because the budget already leaves
    // ~600KB of headroom.
    const batches = Migration.batchNotePayloads(
      notes(MAX_VAULT_NOTES_PER_USER, MAX_VAULT_NOTE_CONTENT_LENGTH),
    );
    for (const batch of batches) {
      assert.ok(
        batchChars(batch) < NGINX_BODY_LIMIT_BYTES,
        `batch of ${batchChars(batch)} chars exceeds the ${NGINX_BODY_LIMIT_BYTES}-byte limit`,
      );
    }
  });

  test("the character budget leaves room for one whole note", () => {
    // If a single note could not fit the budget, every batch would degrade to
    // one note and the POST count would blow past the rate limit.
    assert.ok(Migration.BATCH_MAX_CHARS >= MAX_VAULT_NOTE_CONTENT_LENGTH);
  });
});

describe("isRetryableMigrationStatus", () => {
  test("retries a rate limit", () => {
    assert.equal(Migration.isRetryableMigrationStatus(429), true);
  });

  test("does not retry a rejected CSRF token or a validation error", () => {
    // The reason /vault/migrate/ answers block=False: an HTML 403 from a
    // block=True limiter would be indistinguishable from a real 403, and
    // retrying a token that will never be accepted just spins.
    assert.equal(Migration.isRetryableMigrationStatus(403), false);
    assert.equal(Migration.isRetryableMigrationStatus(400), false);
    assert.equal(Migration.isRetryableMigrationStatus(401), false);
  });

  test("does not retry a server error or a success", () => {
    // A 5xx here means the transaction rolled back; the flow surfaces it
    // rather than hammering a failing server mid-password-change.
    assert.equal(Migration.isRetryableMigrationStatus(500), false);
    assert.equal(Migration.isRetryableMigrationStatus(200), false);
  });
});
