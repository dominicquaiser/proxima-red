/**
 * Tests for static/shared/js/http.js - the CSRF-aware fetch wrappers every
 * page submits through (window.Http).
 *
 * The contract under test is that `result` is always a non-null object. Every
 * caller across the four apps reaches straight for `result.success` /
 * `result.error`, so a reply that is not a JSON object - the HTML 403 a
 * `block=True` rate limiter hands back, a proxy error page, a followed
 * redirect to sign-in - must arrive as a synthesized failure rather than as a
 * rejected `Response.json()`.
 *
 * fetch is stubbed with real Response objects, so parseJsonBody runs against
 * the same parser the browser uses.
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
// getCsrfToken looks for a hidden form field, then the cookie jar.
global.document = { querySelector: () => null, cookie: "" };
// postForm branches on `body instanceof HTMLFormElement`; Node has no DOM, so
// stand one up purely so the instanceof check can run and be false.
global.HTMLFormElement = class HTMLFormElement {};

const source = fs.readFileSync(
  path.join(__dirname, "..", "..", "static", "shared", "js", "http.js"),
  "utf8",
);
vm.runInThisContext(source, { filename: "http.js" });

const DEFAULT_ERROR_MESSAGE = "An unexpected error occurred.";
const HTML_403 = "<!doctype html><html><body>Forbidden</body></html>";

/** Stub fetch with a single canned Response. */
function respondWith(body, init, { redirected = false } = {}) {
  const response = new Response(body, init);
  if (redirected) {
    Object.defineProperty(response, "redirected", { value: true });
  }
  global.fetch = async () => response;
  return response;
}

describe("Http.postForm / getJson body parsing", () => {
  test("a JSON object body is passed through untouched", async () => {
    respondWith(JSON.stringify({ success: true, note_id: "abc" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

    const { response, result } = await window.Http.postForm("/x/", { a: 1 });

    assert.equal(response.status, 200);
    assert.deepEqual(result, { success: true, note_id: "abc" });
  });

  test("an HTML error page becomes a failure object, not a throw", async () => {
    respondWith(HTML_403, {
      status: 403,
      headers: { "Content-Type": "text/html" },
    });

    const { response, result } = await window.Http.postForm("/x/", { a: 1 });

    assert.equal(response.ok, false);
    assert.equal(result.success, false);
    assert.equal(typeof result.error, "string");
    // The parser's own complaint must never reach the user.
    assert.ok(!/Unexpected token/i.test(result.error));
  });

  test("getJson hardens the same way", async () => {
    respondWith(HTML_403, { status: 403 });

    const { result } = await window.Http.getJson("/x/");

    assert.equal(result.success, false);
    assert.ok(result.error.length > 0);
  });

  test("an empty body is a failure object rather than a parse error", async () => {
    respondWith("", { status: 502 });

    const { result } = await window.Http.getJson("/x/");

    assert.equal(result.success, false);
  });

  test("valid JSON that is not an object is treated as unparseable", async () => {
    // `result.success` would throw on null exactly as a rejected parse did.
    respondWith("null", {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

    const { result } = await window.Http.getJson("/x/");

    assert.notEqual(result, null);
    assert.equal(result.success, false);
  });

  test("a JSON array is treated as unparseable too", async () => {
    respondWith("[1,2,3]", {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });

    const { result } = await window.Http.getJson("/x/");

    assert.equal(result.success, false);
  });
});

describe("Http failure messages are actionable", () => {
  test("401 asks the user to sign in again", async () => {
    respondWith(HTML_403, { status: 401 });
    const { result } = await window.Http.getJson("/x/");
    assert.match(result.error, /sign in/i);
  });

  test("403 (the block=True rate limiter's HTML) suggests waiting", async () => {
    respondWith(HTML_403, { status: 403 });
    const { result } = await window.Http.getJson("/x/");
    assert.match(result.error, /wait a moment/i);
  });

  test("429 names the rate limit", async () => {
    respondWith(HTML_403, { status: 429 });
    const { result } = await window.Http.getJson("/x/");
    assert.match(result.error, /too many requests/i);
  });

  test("5xx blames the server, not the user", async () => {
    respondWith("<html>502</html>", { status: 502 });
    const { result } = await window.Http.getJson("/x/");
    assert.match(result.error, /server/i);
  });

  test("a followed redirect reads as a session bounce, not a 200", async () => {
    // A rate-limited sign-in POST redirects to the sign-in page: status 200,
    // HTML body. Only `redirected` distinguishes it from a broken endpoint.
    respondWith("<html>sign in</html>", { status: 200 }, { redirected: true });

    const { response, result } = await window.Http.postForm("/auth/signin/", {});

    assert.equal(response.ok, true);
    assert.equal(result.success, false);
    assert.match(result.error, /session|reload/i);
  });

  test("an unclassifiable status falls back to the generic message", async () => {
    respondWith("<html>?</html>", { status: 418 });
    const { result } = await window.Http.getJson("/x/");
    assert.equal(result.error, DEFAULT_ERROR_MESSAGE);
  });
});

describe("Http.firstError reads the synthesized shape", () => {
  test("a synthesized failure yields its own message", async () => {
    respondWith(HTML_403, { status: 429 });
    const { result } = await window.Http.getJson("/x/");
    assert.equal(window.Http.firstError(result), result.error);
  });

  test("a server-sent field-errors object still wins", () => {
    const message = window.Http.firstError({ errors: { password: ["Too short."] } });
    assert.equal(message, "Too short.");
  });
});
