"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const source = fs.readFileSync(
  path.join(__dirname, "../../static/auth/js/vault-session.js"),
  "utf8",
);
const storage = () => {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
  };
};
const settle = async () => {
  for (let i = 0; i < 30; i++) await Promise.resolve();
};

function setup({ tool = "note", mirror = storage(), handoff = true, server = null } = {}) {
  let now = 1000000000;
  let sequence = 0;
  const timers = new Map();
  const documentEvents = {};
  const windowEvents = {};
  const sessionStorage = storage();
  const calls = [];
  const transitions = [];
  let resolveUnlock = null;
  let prompts = 0;
  const backend = server || {
    identity: "12345678:salt",
    context: "session-context",
    user: "12345678",
    expires: { pass: now / 1000 + 1800, note: now / 1000 + 604800 },
    signedIn: true,
  };
  const state = () => ({
    tool,
    user_id: backend.user,
    identity: backend.identity,
    cache_context: backend.context,
    server_time: now / 1000,
    expires_at: backend.expires[tool],
    unlocked: backend.expires[tool] > now / 1000,
  });
  const transfer = () => {
    sessionStorage.setItem("master", "derived-key");
    sessionStorage.setItem("context", JSON.stringify(state()));
  };
  if (handoff) transfer();
  const schedule = (callback, delay, interval = 0) => {
    const id = ++sequence;
    timers.set(id, { callback, time: now + delay, interval });
    return id;
  };
  const request = async (method) => {
    calls.push(method);
    if (backend.offline) throw new Error("offline");
    if (!backend.signedIn) return { response: { status: 401, ok: false }, result: {} };
    if (method === "POST") {
      if (backend.expires.note <= now / 1000) return { response: { status: 423 }, result: {} };
      backend.expires.note = now / 1000 + 604800;
    }
    return { response: { status: 200, ok: true }, result: { success: true, state: state() } };
  };
  const context = {
    URLSearchParams,
    sessionStorage,
    localStorage: mirror,
    Date: { now: () => now },
    setTimeout: (callback, delay) => schedule(callback, delay),
    clearTimeout: (id) => timers.delete(id),
    setInterval: (callback, delay) => schedule(callback, delay, delay),
    document: {
      visibilityState: "visible",
      addEventListener: (name, listener) => {
        documentEvents[name] = listener;
      },
      querySelectorAll: () => [],
    },
    addEventListener: (name, listener) => {
      windowEvents[name] = listener;
    },
    Notify: { show: () => {} },
    Http: {
      setVaultIdentity: () => {},
      getJson: () => request("GET"),
      postForm: () => request("POST"),
    },
    AuthCrypto: {
      STORAGE_KEYS: { masterKey: "master", context: "context", noteMirror: "noteVaultMasterKey" },
      consumeVaultKeyFromFragment: () => {},
      clearSecureSession: () => {
        sessionStorage.removeItem("master");
        sessionStorage.removeItem("context");
      },
    },
    SecureSessionUnlock: {
      ensureSecureSession: () => {
        prompts++;
        return new Promise((resolve) => {
          resolveUnlock = resolve;
        });
      },
      dismiss: () => {
        if (resolveUnlock) resolveUnlock(false);
        resolveUnlock = null;
      },
    },
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(source, context);
  const session = context.VaultSession.create({
    tool,
    userId: "12345678",
    onLock: () => transitions.push("locked"),
    onUnlock: () => transitions.push("unlocked"),
    onSignedOut: () => transitions.push("signed-out"),
    onIdentityChange: () => transitions.push("changed"),
  });
  return {
    session,
    backend,
    calls,
    transitions,
    mirror,
    sessionStorage,
    context,
    prompts: () => prompts,
    jump: (ms) => {
      now += ms;
    },
    async unlock() {
      backend.expires[tool] = now / 1000 + (tool === "pass" ? 1800 : 604800);
      transfer();
      resolveUnlock(true);
      resolveUnlock = null;
      await settle();
    },
    async event(name, trusted = true) {
      (documentEvents[name] || windowEvents[name])?.({ isTrusted: trusted });
      await settle();
    },
    async advance(ms) {
      const target = now + ms;
      for (let i = 0; i < 2000; i++) {
        const pending = [...timers]
          .filter(([, timer]) => timer.time <= target)
          .sort((a, b) => a[1].time - b[1].time)[0];
        if (!pending) {
          now = target;
          await settle();
          return;
        }
        const [id, timer] = pending;
        now = timer.time;
        timers.delete(id);
        if (timer.interval) timers.set(id, { ...timer, time: now + timer.interval });
        timer.callback();
        await settle();
      }
      throw new Error("Timer loop did not settle");
    },
  };
}

test("password access locks at 30 minutes despite interactions and status checks", async () => {
  const page = setup({ tool: "pass" });
  assert.equal(await page.session.start(), "derived-key");
  await page.advance(1799000);
  await page.event("keydown");
  assert.deepEqual(page.transitions, []);
  await page.advance(1000);
  assert.deepEqual(page.transitions, ["locked"]);
  assert.equal(page.prompts(), 1);
  assert.equal(page.sessionStorage.getItem("vaultKey:pass"), null);
  assert.equal(page.calls.includes("POST"), false);
  await page.unlock();
  assert.deepEqual(page.transitions, ["locked", "unlocked"]);
});

test("an idle note tab and synthetic input do not send renewal traffic", async () => {
  const page = setup();
  await page.session.start();
  await page.advance(1); // Initial foreground visit.
  page.calls.length = 0;
  await page.advance(3600000);
  await page.event("input", false);
  await page.advance(1);
  assert.ok(page.calls.includes("GET"));
  assert.equal(page.calls.includes("POST"), false);
});

test("editing renews notes with throttled activity and leaves the password deadline alone", async () => {
  const page = setup();
  const passwordExpiry = page.backend.expires.pass;
  await page.session.start();
  await page.advance(1);
  page.calls.length = 0;
  for (let i = 0; i < 20; i++) await page.event("input");
  await page.advance(60000);
  assert.equal(page.calls.filter((method) => method === "POST").length, 1);
  assert.equal(page.backend.expires.pass, passwordExpiry);
  assert.ok(page.backend.expires.note > 1000000 + 604800);
});

test("hidden note tabs do not renew", async () => {
  const page = setup();
  page.context.document.visibilityState = "hidden";
  await page.session.start();
  await page.event("input");
  await page.advance(60000);
  assert.equal(page.calls.includes("POST"), false);
});

test("note activity resumes after a lock cancels a pending activity update", async () => {
  const page = setup();
  await page.session.start();
  await page.advance(1);
  await page.event("input");
  page.backend.expires.note = 0;
  await page.session.refresh();
  assert.equal(page.prompts(), 1);
  await page.unlock();
  page.calls.length = 0;
  await page.event("input");
  await page.advance(60000);
  assert.equal(page.calls.filter((method) => method === "POST").length, 1);
});

test("a new note tab or browser restart reuses a validated note key", async () => {
  const first = setup();
  await first.session.start();
  const second = setup({ mirror: first.mirror, handoff: false, server: first.backend });
  assert.equal(await second.session.start(), "derived-key");
  assert.equal(second.prompts(), 0);
});

test("note key caching cannot unlock a password tab", async () => {
  const notes = setup();
  await notes.session.start();
  const passwords = setup({ tool: "pass", mirror: notes.mirror, handoff: false });
  const started = passwords.session.start();
  await settle();
  assert.equal(passwords.prompts(), 1);
  assert.notEqual(notes.mirror.getItem("noteVaultMasterKey"), null);
  await passwords.unlock();
  assert.equal(await started, "derived-key");
});

for (const field of ["context", "identity", "expiresAt"]) {
  test(`a note cache with invalid ${field} requires a password`, async () => {
    const mirror = storage();
    const record = {
      key: "old-key",
      context: "session-context",
      identity: "12345678:salt",
      expiresAt: 2000000,
    };
    record[field] = field === "expiresAt" ? 0 : "old";
    mirror.setItem("noteVaultMasterKey", JSON.stringify(record));
    const page = setup({ mirror, handoff: false });
    const started = page.session.start();
    await settle();
    assert.equal(page.prompts(), 1);
    assert.equal(mirror.getItem("noteVaultMasterKey"), null);
    await page.unlock();
    assert.equal(await started, "derived-key");
  });
}

test("an account or password change locks the old tab without adopting another key", async () => {
  const page = setup();
  await page.session.start();
  page.backend.identity = "87654321:new-salt";
  await page.session.refresh();
  assert.deepEqual(page.transitions, ["locked", "changed"]);
  assert.equal(page.mirror.getItem("noteVaultMasterKey"), null);
  assert.equal(page.prompts(), 0);
});

test("signing out clears keys; signing back into the same account can recover the tab", async () => {
  const page = setup();
  await page.session.start();
  page.backend.signedIn = false;
  await page.session.refresh();
  assert.deepEqual(page.transitions, ["locked", "signed-out"]);
  assert.equal(page.mirror.getItem("noteVaultMasterKey"), null);
  page.backend.signedIn = true;
  page.backend.context = "new-session";
  await page.session.refresh();
  assert.equal(page.prompts(), 1);
  await page.unlock();
  assert.equal(page.transitions.at(-1), "unlocked");
});

test("a signed-out tab reports the sign-out once, not on every periodic check", async () => {
  const page = setup();
  await page.session.start();
  page.backend.signedIn = false;
  await page.session.refresh();
  await page.advance(180000);
  await page.event("focus");
  assert.equal(page.transitions.filter((t) => t === "signed-out").length, 1);
});

test("network loss cannot leave a password vault unlocked beyond its deadline", async () => {
  const page = setup({ tool: "pass" });
  await page.session.start();
  page.backend.offline = true;
  await page.advance(1800000);
  assert.deepEqual(page.transitions, ["locked"]);
  assert.equal(page.sessionStorage.getItem("vaultKey:pass"), null);
});

test("resuming after sleep locks expired access even with suspended timers and no network", async () => {
  const page = setup({ tool: "pass" });
  await page.session.start();
  page.backend.offline = true;
  page.jump(1800001);
  await page.event("focus");
  assert.deepEqual(page.transitions, ["locked"]);
  assert.equal(page.sessionStorage.getItem("vaultKey:pass"), null);
});
