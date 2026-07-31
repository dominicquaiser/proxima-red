/**
 * Tests for the pure helpers of static/note/js/live-collab.js
 * (window.NoteLiveCollab): the re-key payload assembler and survivor-set
 * computation. The crypto orchestration and DOM panel are exercised in the
 * browser.
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
    path.join(__dirname, "..", "..", "static", "note", "js", "live-collab.js"),
    "utf8",
  ),
  { filename: "live-collab.js" },
);

const Collab = window.NoteLiveCollab;

describe("survivorIds", () => {
  const collaborators = [
    { user_id: "10000001", role: "owner" },
    { user_id: "10000002", role: "editor" },
    { user_id: "10000003", role: "editor" },
  ];

  test("excludes the revoked user", () => {
    assert.deepEqual(Collab.survivorIds(collaborators, "10000002"), [
      "10000001",
      "10000003",
    ]);
  });

  test("a null removal keeps everyone (plain rotation)", () => {
    assert.deepEqual(Collab.survivorIds(collaborators, null), [
      "10000001",
      "10000002",
      "10000003",
    ]);
  });

  test("removing an absent id is a no-op", () => {
    assert.deepEqual(Collab.survivorIds(collaborators, "99999999"), [
      "10000001",
      "10000002",
      "10000003",
    ]);
  });
});

describe("assembleRekeyPayload", () => {
  test("shapes the server body with the next epoch and covers_seq", () => {
    const body = Collab.assembleRekeyPayload({
      coversSeq: 42,
      epoch: 3,
      removeUserId: "10000002",
      snapshot: { snapshot: "c25hcA==", snapshot_iv: "aXY=" },
      wraps: [{ user_id: "10000001", wrapped_key: "dw==", wrap_iv: "aQ==", ephemeral_public_key: "ZQ==" }],
    });
    assert.deepEqual(body, {
      snapshot: "c25hcA==",
      snapshot_iv: "aXY=",
      covers_seq: 42,
      key_epoch: 3,
      remove_user_id: "10000002",
      wraps: [{ user_id: "10000001", wrapped_key: "dw==", wrap_iv: "aQ==", ephemeral_public_key: "ZQ==" }],
    });
  });

  test("a null removal serializes as null (plain rotation)", () => {
    const body = Collab.assembleRekeyPayload({
      coversSeq: 0,
      epoch: 1,
      removeUserId: null,
      snapshot: { snapshot: "c25hcA==", snapshot_iv: "aXY=" },
      wraps: [],
    });
    assert.equal(body.remove_user_id, null);
    assert.equal(body.key_epoch, 1);
    assert.deepEqual(body.wraps, []);
  });
});
