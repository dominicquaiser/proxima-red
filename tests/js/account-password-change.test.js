/**
 * Password-change flow checks against the real account page script.
 * The stand-ins model only its DOM and HTTP boundaries; vault migration
 * batching runs through the real VaultMigration module.
 */

"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.join(__dirname, "..", "..");
const migrationSource = fs.readFileSync(
  path.join(ROOT, "static/auth/js/vault-migration.js"),
  "utf8",
);
const accountSource = fs.readFileSync(path.join(ROOT, "static/auth/js/account.js"), "utf8");

function setup(overrides = {}) {
  const trace = [];
  const notices = [];
  let recoveryVisible = false;
  const fields = Object.fromEntries(
    [
      "id_current_password",
      "id_new_password",
      "id_confirm_new_password",
      "id_current_auth_secret",
      "id_new_auth_secret",
      "id_auth_salt",
      "id_vault_salt",
    ].map((id) => [id, { value: "" }]),
  );
  fields.id_current_password.value = "current password";
  fields.id_new_password.value = "new password";
  fields.id_confirm_new_password.value = "new password";

  const listeners = {};
  const form = {
    action: "/auth/account/password/",
    dataset: {},
    addEventListener: (name, callback) => {
      listeners[name] = callback;
    },
    querySelector: () => ({ disabled: false }),
    querySelectorAll: () => [
      fields.id_current_password,
      fields.id_new_password,
      fields.id_confirm_new_password,
      fields.id_current_auth_secret,
      fields.id_new_auth_secret,
    ],
  };
  const replies = {
    "/vault-data/": { success: true },
    "/vault/index/": { success: true },
    "/vault/notes/?content=1": { success: true, notes: [] },
    ...overrides.replies,
  };
  let ready;
  let migrationAttempts = 0;
  const context = {
    URLSearchParams,
    console: { error: () => {} },
    fetch: () => {},
    setTimeout: (callback) => {
      callback();
      return 1;
    },
    sessionStorage: { getItem: () => "old-key" },
    document: {
      addEventListener: (name, callback) => {
        if (name === "DOMContentLoaded") ready = callback;
      },
      getElementById: (id) => {
        if (id === "vault-recovery")
          return {
            classList: {
              remove: () => {
                recoveryVisible = true;
              },
              add: () => {
                recoveryVisible = false;
              },
            },
          };
        if (id === "change-password-form") return form;
        if (id === "auth-data") {
          return {
            textContent: JSON.stringify({
              auth_salt: "old-auth-salt",
              vault_salt: "old-vault-salt",
            }),
          };
        }
        return fields[id] || null;
      },
      querySelector: () => null,
      querySelectorAll: () => [],
    },
  };
  context.window = context;
  context.FormUi = {
    getMaskedInputValue: (input) => input.value,
    submitWithBusy: async (_button, action, { onError }) => {
      try {
        await action();
      } catch (error) {
        onError(error);
      }
    },
  };
  context.Notify = { show: (message, kind) => notices.push({ message, kind }) };
  context.AuthCrypto = {
    STORAGE_KEYS: { masterKey: "masterKey" },
    validatePassword: () => ({ isValid: true, messages: [] }),
    generateSalt: () => "fresh-salt",
    deriveAuthSecret: async () => "derived-secret",
    importKeyFromBase64: async () => "old-key",
    deriveKeyFromPassword: async () => "new-key",
    decryptAccountData: async (ciphertext) =>
      ciphertext === "index-old" ? { kind: "index" } : { kind: "pass" },
    encryptAccountData: async (data) => ({
      encryptedData: data.kind === "index" ? "index-new" : "pass-new",
      iv: "new-iv",
    }),
    establishSecureSession: async (_password, salt, context) => {
      trace.push({ step: "session-key", salt, context });
    },
  };
  context.PasswordCrypto = { decryptPassword: async (content) => content };
  context.CryptoCore = {
    encryptWithKey: async (content) => ({ encryptedData: `new:${content}`, iv: "new-iv" }),
  };
  context.Http = {
    setVaultIdentity: () => {},
    getJson: async (url) => {
      trace.push({ step: "read", url });
      assert.ok(Object.hasOwn(replies, url), `unexpected GET ${url}`);
      return { response: { ok: true, status: 200 }, result: replies[url] };
    },
    postForm: async (url, payload) => {
      trace.push({ step: "post", url, payload });
      if (url === "/auth/reauth/") {
        if (overrides.reauthReply) return overrides.reauthReply;
        return {
          response: { ok: true, status: 200 },
          result: { success: true, state: { identity: "old-identity" } },
        };
      }
      if (url === "/vault/migrate/") {
        migrationAttempts += 1;
        if (overrides.migrateReply) return overrides.migrateReply(migrationAttempts, payload);
      }
      if (url === form.action) {
        return {
          response: { ok: true, status: 200 },
          result: {
            success: true,
            auth_salt: "new-auth-salt",
            vault_salt: "new-vault-salt",
            state: { identity: "new-identity" },
          },
        };
      }
      return { response: { ok: true, status: 200 }, result: { success: true } };
    },
    firstError: (result) => result.error || "Request failed",
  };

  vm.createContext(context);
  vm.runInContext(migrationSource, context, { filename: "vault-migration.js" });
  vm.runInContext(accountSource, context, { filename: "account.js" });
  ready();

  return {
    fields,
    notices,
    trace,
    recoveryVisible: () => recoveryVisible,
    submit: async () => {
      let prevented = false;
      await listeners.submit({
        preventDefault: () => {
          prevented = true;
        },
      });
      assert.equal(prevented, true);
    },
  };
}

const postsTo = (trace, url) => trace.filter((entry) => entry.step === "post" && entry.url === url);

test("an empty pair of vaults permits the change without migration writes", async () => {
  const page = setup();
  await page.submit();
  assert.equal(postsTo(page.trace, "/auth/account/password/").length, 1);
  assert.equal(postsTo(page.trace, "/update-data/").length, 0);
  assert.equal(postsTo(page.trace, "/vault/migrate/").length, 0);
  assert.equal(page.trace.at(-1).step, "session-key");
  // Stamped with the post-change state, or VaultSession refuses the handoff.
  assert.equal(page.trace.at(-1).salt, "new-vault-salt");
  assert.equal(page.trace.at(-1).context.identity, "new-identity");
  assert.equal(page.fields.id_current_password.value, "");
  assert.ok(page.notices.some((notice) => notice.kind === "success"));
  assert.equal(page.trace[0].url, "/auth/reauth/");
  assert.equal(page.trace[0].payload.get("tool"), "account");
});

test("rejected password verification prevents all vault reads and credential changes", async () => {
  const page = setup({
    reauthReply: {
      response: { ok: false, status: 401 },
      result: { success: false, error: "Incorrect password" },
    },
  });
  await page.submit();
  assert.equal(
    page.trace.some((entry) => entry.step === "read"),
    false,
  );
  assert.equal(postsTo(page.trace, "/auth/account/password/").length, 0);
  assert.equal(page.recoveryVisible(), false);
});

for (const [label, replies] of [
  ["password vault", { "/vault-data/": { success: false, error: "Unreadable" } }],
  ["note list", { "/vault/notes/?content=1": { success: false, error: "Unreadable" } }],
]) {
  test(`an unreadable ${label} response stops before the password changes`, async () => {
    const page = setup({ replies });
    await page.submit();
    assert.equal(postsTo(page.trace, "/auth/account/password/").length, 0);
    assert.equal(
      page.trace.some((entry) => entry.step === "session-key"),
      false,
    );
    assert.ok(page.notices.some((notice) => notice.kind === "error"));
  });
}

test("a 429 retries the same note batch before refreshing the session key", async () => {
  const page = setup({
    replies: {
      "/vault-data/": { success: true, encrypted_data: "pass-old", iv: "old-iv" },
      "/vault/index/": { success: true, encrypted_data: "index-old", iv: "old-iv" },
      "/vault/notes/?content=1": {
        success: true,
        notes: [{ id: "n1", content: "text", iv: "old-iv" }],
      },
    },
    migrateReply: (attempt) =>
      attempt === 1
        ? { response: { ok: false, status: 429 }, result: { success: false } }
        : { response: { ok: true, status: 200 }, result: { success: true } },
  });
  await page.submit();
  const migration = postsTo(page.trace, "/vault/migrate/");
  assert.equal(migration.length, 2);
  assert.deepEqual(
    JSON.parse(JSON.stringify(migration[0].payload)),
    JSON.parse(JSON.stringify(migration[1].payload)),
  );
  assert.equal(migration[1].payload.index.encrypted_data, "index-new");
  assert.equal(postsTo(page.trace, "/update-data/").length, 1);
  assert.ok(
    page.trace.findIndex((entry) => entry.url === "/update-data/") <
      page.trace.findIndex((entry) => entry.url === "/vault/migrate/"),
  );
  assert.equal(page.trace.at(-1).step, "session-key");
  assert.equal(page.notices.filter((notice) => notice.kind === "info").length, 1);
});

test("a failed later batch keeps the old session key and leaves the index for last", async () => {
  const notes = Array.from({ length: 26 }, (_, i) => ({
    id: `n${i}`,
    content: `text${i}`,
    iv: "old-iv",
  }));
  const page = setup({
    replies: {
      "/vault/index/": { success: true, encrypted_data: "index-old", iv: "old-iv" },
      "/vault/notes/?content=1": { success: true, notes },
    },
    migrateReply: (attempt) =>
      attempt === 1
        ? { response: { ok: true, status: 200 }, result: { success: true } }
        : { response: { ok: false, status: 500 }, result: { success: false } },
  });
  await page.submit();
  const migration = postsTo(page.trace, "/vault/migrate/");
  assert.equal(migration.length, 2);
  assert.equal(migration[0].payload.notes.length, 25);
  assert.equal(migration[0].payload.index, undefined);
  assert.equal(migration[1].payload.notes.length, 1);
  assert.equal(migration[1].payload.index.encrypted_data, "index-new");
  assert.equal(
    page.trace.some((entry) => entry.step === "session-key"),
    false,
  );
  assert.equal(page.fields.id_current_password.value, "");
  assert.equal(page.recoveryVisible(), true);
  assert.ok(
    page.notices.some((notice) => notice.message.includes("notes could not all be re-secured")),
  );
});
