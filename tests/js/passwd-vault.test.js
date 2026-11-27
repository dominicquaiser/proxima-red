/** Exercise share creation through the password vault controller and its real save queue. */

"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const scripts = ["shared/js/save-queue.js", "passwd/js/vault.js"].map((file) => ({
  file,
  source: fs.readFileSync(path.join(__dirname, "../../static", file), "utf8"),
}));

const reply = (status, result) => ({ response: { status, ok: status === 200 }, result });
const success = (fields = {}) => reply(200, { success: true, ...fields });
const storedVault = (shares) => ({ encrypted_data: JSON.stringify({ shares }), iv: "iv" });

function vaultServer(initial = {}) {
  let blob = initial;
  const revision = () => {
    if (!blob.iv) return "";
    return createHash("sha256").update(blob.iv).update(blob.encrypted_data).digest("hex");
  };
  return {
    read: () => success({ ...blob, revision: revision() }),
    write({ encrypted_data, iv, expected_revision }) {
      if (blob.encrypted_data === encrypted_data && blob.iv === iv) {
        return success({ revision: revision() });
      }
      if (expected_revision !== undefined && expected_revision !== revision()) {
        return reply(409, { success: false, code: "vault_data_changed" });
      }
      blob = { encrypted_data, iv };
      return success({ revision: revision() });
    },
  };
}

// Ciphertext the test decryptor refuses, like a blob written under another key.
const UNDECRYPTABLE = "written under another key";

// Only what vault.js reads or sets on the buttons and panels it toggles.
function element(className = "") {
  const classes = new Set(className.split(" ").filter(Boolean));
  const listeners = {};
  return {
    disabled: false,
    textContent: "",
    classList: {
      add: (name) => classes.add(name),
      remove: (name) => classes.delete(name),
      toggle: (name, force = !classes.has(name)) => {
        if (force) classes.add(name);
        else classes.delete(name);
        return force;
      },
      contains: (name) => classes.has(name),
    },
    addEventListener(name, handler) {
      listeners[name] = handler;
    },
    async click() {
      await listeners.click?.({ preventDefault() {}, stopPropagation() {} });
      await new Promise(setImmediate);
    },
  };
}

async function setup({
  server = vaultServer(),
  storage = new Map(),
  identity = "12345678:current-vault-salt",
  shareId = "new-share",
  save = (store) => store(),
  readBack = server.read,
  load = server.read,
} = {}) {
  const events = {};
  const requests = [];
  const notices = [];
  const createButton = element();
  const unreadablePanel = element("hidden");
  const resetButton = element();
  const form = {
    action: "/",
    querySelectorAll: () => [],
    addEventListener(name, handler) {
      events[name] = handler;
    },
  };
  const elements = {
    inlinePasswordForm: form,
    "create-new-btn": createButton,
    "vault-unreadable": unreadablePanel,
    "reset-vault-btn": resetButton,
    "unlock-modal": { dataset: { userId: "12345678" } },
  };
  let vaultReads = 0;
  const context = {
    console: { error() {} },
    // The two-click confirmation windows never need to expire in these tests.
    setTimeout: () => 1,
    clearTimeout() {},
    document: {
      getElementById: (id) => elements[id] || null,
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener(name, handler) {
        events[name] = handler;
      },
    },
    addEventListener() {},
    Notify: { show: (message, kind) => notices.push({ message, kind }) },
    FormUi: {
      setupShareForm: () => ({
        readPlaintext: () => "test secret",
        readTitle: () => "Test share",
        encrypt: async () => "test share key",
        reset() {},
        clearSecrets() {},
        setBusy() {},
      }),
    },
    VaultSession: { create: () => ({ identity, start: async () => "test vault key" }) },
    sessionStorage: {
      getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, value),
      removeItem: (key) => storage.delete(key),
    },
    AuthCrypto: {
      importKeyFromBase64: async (key) => key,
      encryptAccountData: async (data) => ({ encryptedData: JSON.stringify(data), iv: "write-iv" }),
      decryptAccountData: async (data) => {
        if (data === UNDECRYPTABLE) throw new Error("OperationError");
        return JSON.parse(data);
      },
    },
    Http: {
      getCsrfToken: () => "test token",
      getJson: async (url) => {
        requests.push({ method: "GET", url });
        vaultReads += 1;
        return vaultReads === 1 ? load() : readBack();
      },
      postForm: async (url, body) => {
        requests.push({ method: "POST", url, body });
        if (url === "/") return success({ share_id: shareId });
        if (url === "/delete-share/") return success();
        assert.equal(url, "/update-data/");
        return save(() => server.write(body));
      },
    },
  };
  context.window = context;
  vm.createContext(context);
  for (const { file, source } of scripts) vm.runInContext(source, context, { filename: file });
  events.DOMContentLoaded();
  await new Promise(setImmediate);

  return {
    createButton,
    unreadablePanel,
    resetButton,
    notices,
    requests,
    savedShares: () => JSON.parse(requests.at(-1).body.encrypted_data).shares,
    submit: () => events.submit({ preventDefault() {} }),
  };
}

for (const [scenario, loseResponse] of [
  [
    "a connection reset",
    () => {
      throw new Error("connection reset");
    },
  ],
  ["an unreadable HTTP 200 response", () => reply(200, { success: false })],
  ["an HTTP 500 sent after the write", () => reply(500, { success: false })],
]) {
  test(`a matching read confirms a save after ${scenario} and keeps the share live`, async () => {
    const vault = await setup({
      save(store) {
        store();
        return loseResponse();
      },
    });
    await vault.submit();

    assert.deepEqual(vault.requests.map(({ method, url }) => `${method} ${url}`), [
      "GET /vault-data/",
      "POST /",
      "POST /update-data/",
      "GET /vault-data/",
    ]);
    assert.equal(vault.createButton.disabled, false);
    assert.deepEqual(vault.notices.map(({ kind }) => kind), ["success"]);
  });
}

test("an unconfirmed save keeps the share live and pauses further writes", async () => {
  const vault = await setup({ save: () => reply(504, { success: false }) });
  await vault.submit();
  await vault.submit();

  assert.deepEqual(vault.requests.map(({ url }) => url), [
    "/vault-data/",
    "/",
    "/update-data/",
    "/vault-data/",
  ]);
  assert.equal(vault.createButton.disabled, true);
  assert.match(vault.notices.at(-1).message, /reload your vault/i);
});

test("a definite save rejection still revokes the new share", async () => {
  const vault = await setup({ save: () => reply(400, { success: false, error: "Invalid data" }) });
  await vault.submit();

  assert.deepEqual(vault.requests.map(({ url }) => url), [
    "/vault-data/",
    "/",
    "/update-data/",
    "/delete-share/",
  ]);
  assert.equal(vault.requests.at(-1).body.share_id, "new-share");
  assert.equal(vault.createButton.disabled, false);
  assert.deepEqual(vault.notices.map(({ kind }) => kind), ["error"]);
});

test("a reload retries a pending save before allowing a subsequent change", async () => {
  const server = vaultServer();
  const storage = new Map();
  let finishOriginalSave;
  const vault = await setup({
    server,
    storage,
    save(store) {
      finishOriginalSave = store;
      return reply(504, { success: false });
    },
  });
  await vault.submit();

  assert.equal(server.read().result.revision, "", "initial reads finish before the original save");
  const reloaded = await setup({ server, storage, shareId: "after-reload" });
  assert.deepEqual(reloaded.requests.map(({ url }) => url), ["/vault-data/", "/update-data/"]);
  assert.equal(
    JSON.stringify(reloaded.requests[1].body),
    JSON.stringify(vault.requests[2].body),
    "retry the original ciphertext, not a new encryption",
  );
  assert.equal(storage.size, 0);
  assert.equal(reloaded.createButton.disabled, false);

  await reloaded.submit();
  assert.equal(finishOriginalSave().response.status, 409, "the late original cannot overwrite");
  const shares = JSON.parse(server.read().result.encrypted_data).shares;
  assert.deepEqual(shares.map(({ id }) => id), ["after-reload", "new-share"]);
  assert.equal(shares[1].key, "test share key");
});

test("a tab that read before a late commit cannot overwrite it", async () => {
  const server = vaultServer();
  let finishOriginalSave;
  const first = await setup({
    server,
    save(store) {
      finishOriginalSave = store;
      return reply(504, { success: false });
    },
  });
  await first.submit();

  // A second tab does not have the journal entry, so it loads the old revision.
  const second = await setup({ server, shareId: "second-tab-share" });
  assert.equal(finishOriginalSave().response.status, 200);
  await second.submit();

  assert.equal(second.requests.at(-1).url, "/delete-share/");
  assert.equal(second.requests.at(-1).body.share_id, "second-tab-share");
  assert.equal(second.createButton.disabled, true);
  const shares = JSON.parse(server.read().result.encrypted_data).shares;
  assert.deepEqual(shares.map(({ id }) => id), ["new-share"]);
  assert.equal(shares[0].key, "test share key");
});

test("an unresolved replay keeps writes paused and can be retried on the next reload", async () => {
  const server = vaultServer();
  const storage = new Map();
  const initial = await setup({ server, storage, save: () => reply(504, { success: false }) });
  await initial.submit();

  const reloaded = await setup({ server, storage, save: () => reply(503, { success: false }) });
  assert.equal(reloaded.createButton.disabled, true);
  await reloaded.submit();
  assert.deepEqual(reloaded.requests.map(({ url }) => url), [
    "/vault-data/",
    "/update-data/",
    "/vault-data/",
  ]);
  assert.equal(storage.size, 1);

  const recovered = await setup({ server, storage });
  assert.equal(recovered.createButton.disabled, false);
  assert.deepEqual(recovered.savedShares().map(({ id }) => id), ["new-share"]);
  assert.equal(storage.size, 0);
});

test("a pending save is not replayed after the account password changes", async () => {
  const server = vaultServer();
  const storage = new Map();
  const initial = await setup({ server, storage, save: () => reply(504, { success: false }) });
  await initial.submit();

  const reloaded = await setup({ server, storage, identity: "12345678:rotated-vault-salt" });
  assert.deepEqual(reloaded.requests.map(({ url }) => url), ["/vault-data/"]);
  assert.equal(storage.size, 0);
});

test("an ambiguous server error is retried because reading the old revision proves nothing", async () => {
  const server = vaultServer();
  const storage = new Map();
  const vault = await setup({ server, storage, save: () => reply(500, { success: false }) });
  await vault.submit();
  assert.equal(vault.requests.some(({ url }) => url === "/delete-share/"), false);

  const reloaded = await setup({ server, storage });
  assert.deepEqual(reloaded.savedShares().map(({ id }) => id), ["new-share"]);
});

test("an app error whose read-back fails leaves the save unconfirmed", async () => {
  const vault = await setup({
    save: () => reply(500, { success: false }),
    readBack: () => reply(503, { success: false }),
  });
  await vault.submit();

  assert.deepEqual(vault.requests.map(({ url }) => url), [
    "/vault-data/",
    "/",
    "/update-data/",
    "/vault-data/",
  ]);
  assert.equal(vault.createButton.disabled, true);
  assert.match(vault.notices.at(-1).message, /reload your vault/i);
});

test("a vault that won't decrypt explains why and is replaced only after a confirmed reset", async () => {
  const vault = await setup({
    server: vaultServer({ encrypted_data: UNDECRYPTABLE, iv: "old-iv" }),
  });
  assert.equal(vault.unreadablePanel.classList.contains("hidden"), false);
  assert.deepEqual(vault.notices, [], "the panel explains it; a reload prompt would be wrong");

  await vault.submit();
  await vault.createButton.click();
  assert.equal(vault.requests.length, 1, "nothing is created or saved over the unreadable list");
  assert.match(vault.notices.at(-1).message, /can't be decrypted/);

  await vault.resetButton.click();
  assert.equal(vault.requests.length, 1, "the first click only asks for confirmation");
  assert.match(vault.resetButton.textContent, /click again/i);

  await vault.resetButton.click();
  assert.deepEqual(vault.requests.slice(1).map(({ url }) => url), ["/update-data/"]);
  assert.deepEqual(vault.savedShares(), []);
  assert.equal(vault.unreadablePanel.classList.contains("hidden"), true);
  assert.equal(vault.notices.at(-1).kind, "success");

  await vault.submit();
  assert.deepEqual(vault.requests.slice(2).map(({ url }) => url), ["/", "/update-data/"]);
  assert.deepEqual(vault.savedShares().map(({ id }) => id), ["new-share"]);
});

test("reset sends the unreadable revision and preserves a vault restored in the meantime", async () => {
  const server = vaultServer({ encrypted_data: UNDECRYPTABLE, iv: "old-iv" });
  const originalRevision = server.read().result.revision;
  const vault = await setup({ server });
  await vault.resetButton.click();

  const restored = storedVault([{ id: "restored-share", key: "restored key" }]);
  server.write(restored); // The account page completes its password migration.
  await vault.resetButton.click();

  assert.equal(vault.requests.at(-1).body.expected_revision, originalRevision);
  assert.equal(server.read().result.encrypted_data, restored.encrypted_data);
  assert.match(vault.notices.at(-1).message, /saved links changed/i);
  assert.equal(vault.resetButton.disabled, true);
});

test("a failed reset keeps the unreadable list and its notice", async () => {
  const vault = await setup({
    server: vaultServer({ encrypted_data: UNDECRYPTABLE, iv: "old-iv" }),
    save: () => reply(400, { success: false, error: "Invalid data" }),
  });
  await vault.resetButton.click();
  await vault.resetButton.click();

  assert.equal(vault.unreadablePanel.classList.contains("hidden"), false);
  assert.equal(vault.resetButton.disabled, false, "the reset can be tried again");
  await vault.submit();
  assert.deepEqual(vault.requests.map(({ url }) => url), ["/vault-data/", "/update-data/"]);
});

test("a saved link with an unexpected shape is hidden but written back unchanged", async () => {
  const saved = { id: "saved-share", key: "saved key", title: "Saved", tags: ["work"] };
  const unexpected = { id: 7, link: "from another version" };
  const vault = await setup({ server: vaultServer(storedVault([saved, unexpected])) });
  assert.equal(vault.unreadablePanel.classList.contains("hidden"), true);
  assert.match(vault.notices.at(-1).message, /could not be read/);

  await vault.submit();
  assert.deepEqual(vault.requests.map(({ url }) => url), ["/vault-data/", "/", "/update-data/"]);
  assert.deepEqual(
    vault.savedShares().map(({ id }) => id),
    ["new-share", "saved-share", 7],
  );
  assert.deepEqual(vault.savedShares().at(-1), unexpected);
});

test("a failed load asks for a reload instead of offering the reset", async () => {
  const vault = await setup({ load: () => reply(500, { success: false }) });

  assert.equal(vault.unreadablePanel.classList.contains("hidden"), true);
  assert.equal(vault.createButton.disabled, true);
  assert.match(vault.notices.at(-1).message, /reload the page/i);
});
