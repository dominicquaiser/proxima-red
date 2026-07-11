/**
 * Tests for the language-class validator in static/note/js/markdown.js
 * (window.NoteMarkdown.isHighlightLanguageClass). This is the guard behind the
 * DOMPurify carve-out that force-keeps a `language-xxx` class on <pre>/<code>
 * so highlight.js can honor an explicit fence language - so it must accept only
 * bare language tokens and reject anything that could break out of the
 * attribute or smuggle another class past the sanitizer.
 *
 * marked itself needs a DOM (DOMPurify), so render()/renderInto() are exercised
 * manually in the browser, not here. We stub marked + DOMPurify just enough to
 * let the module load, then test the pure validator.
 *
 * Run with: node --test tests/js/
 */

"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

// markdown.js calls window.marked.use() and window.DOMPurify.addHook() at load;
// stub both as no-ops so the IIFE can run under Node with no DOM.
global.window = globalThis;
window.marked = { use() {} };
window.DOMPurify = { addHook() {} };

const source = fs.readFileSync(
  path.join(__dirname, "..", "..", "static", "note", "js", "markdown.js"),
  "utf8",
);
vm.runInThisContext(source, { filename: "markdown.js" });

const { isHighlightLanguageClass, slugifyHeading } = window.NoteMarkdown;

describe("isHighlightLanguageClass", () => {
  test("accepts bare language tokens marked emits", () => {
    for (const value of [
      "language-python",
      "language-bash",
      "language-js",
      "language-json",
      "language-c++",
      "language-objective-c",
      "language-x86asm",
      "language-json5",
    ]) {
      assert.equal(isHighlightLanguageClass(value), true, value);
    }
  });

  test("rejects anything that is not a language-* token", () => {
    for (const value of [
      "language-", // empty language
      "lang-python", // wrong prefix (marked uses language-)
      "hljs", // no prefix
      "notlanguage-python", // prefix not at start
      "", // empty
    ]) {
      assert.equal(isHighlightLanguageClass(value), false, value);
    }
  });

  test("rejects values that would break out of the attribute or add a class", () => {
    for (const value of [
      "language-python hljs", // a second, unvalidated class
      "language-py thon", // whitespace
      "language-<img src=x>", // angle brackets
      'language-x"onerror="alert(1)', // quote break-out
      "language-py;color:red", // stray punctuation
    ]) {
      assert.equal(isHighlightLanguageClass(value), false, value);
    }
  });
});

// slugifyHeading turns a heading's text into the anchor id an in-note
// `[text](#slug)` link is expected to resolve to (GitHub-style). Only produces
// [a-z0-9-], so the slug is always a safe element id / selector fragment.
describe("slugifyHeading", () => {
  test("lowercases and hyphenates the common cases", () => {
    assert.equal(slugifyHeading("Prerequisites"), "prerequisites");
    assert.equal(slugifyHeading("Getting Started"), "getting-started");
    assert.equal(slugifyHeading("  Trim  Me  "), "trim-me");
  });

  test("drops punctuation and collapses separators", () => {
    assert.equal(slugifyHeading("What's new?"), "whats-new");
    assert.equal(slugifyHeading("Step 1: Install"), "step-1-install");
    assert.equal(slugifyHeading("snake_case heading"), "snake-case-heading");
    assert.equal(slugifyHeading("Already-Hyphenated"), "already-hyphenated");
  });

  test("produces only [a-z0-9-] and never leading/trailing hyphens", () => {
    for (const text of ["***", "!!!", "  ", "", "— dash —", "<b>x</b>"]) {
      const slug = slugifyHeading(text);
      assert.match(slug, /^$|^[a-z0-9]+(?:-[a-z0-9]+)*$/, JSON.stringify(text));
    }
  });

  test("returns empty string when there is nothing slug-worthy", () => {
    assert.equal(slugifyHeading("***"), "");
    assert.equal(slugifyHeading("   "), "");
    assert.equal(slugifyHeading(""), "");
    assert.equal(slugifyHeading(undefined), "");
  });
});
