/**
 * Tests for static/note/js/toolbar.js - the pure text-manipulation functions
 * behind the note editor's tool rail (window.NoteToolbar). The module is
 * deliberately DOM-free so it can run under Node directly.
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
const source = fs.readFileSync(
  path.join(__dirname, "..", "..", "static", "note", "js", "toolbar.js"),
  "utf8",
);
vm.runInThisContext(source, { filename: "toolbar.js" });

const { wrapInline, setHeading, prefixLines, fenceCodeBlock } = window.NoteToolbar;

describe("wrapInline", () => {
  test("wraps a selection in the marker", () => {
    const result = wrapInline("make me bold", 8, 12, "**");
    assert.equal(result.value, "make me **bold**");
    assert.equal(result.value.slice(result.selStart, result.selEnd), "bold");
  });

  test("unwraps when the selection is already wrapped", () => {
    const result = wrapInline("make me **bold**", 8, 16, "**");
    assert.equal(result.value, "make me bold");
    assert.equal(result.value.slice(result.selStart, result.selEnd), "bold");
  });

  test("unwraps when the selection sits inside its markers", () => {
    const result = wrapInline("make me **bold**", 10, 14, "**");
    assert.equal(result.value, "make me bold");
    assert.equal(result.value.slice(result.selStart, result.selEnd), "bold");
  });

  test("with no selection inserts a marker pair with the caret inside", () => {
    const result = wrapInline("start ", 6, 6, "_");
    assert.equal(result.value, "start __");
    assert.equal(result.selStart, 7);
    assert.equal(result.selEnd, 7);
  });
});

describe("setHeading", () => {
  test("prefixes the current line", () => {
    const result = setHeading("title\nbody", 2, 2, 2);
    assert.equal(result.value, "## title\nbody");
  });

  test("replaces an existing heading of another level", () => {
    const result = setHeading("# title", 3, 3, 3);
    assert.equal(result.value, "### title");
  });

  test("toggles off a heading of the same level", () => {
    const result = setHeading("## title", 4, 4, 2);
    assert.equal(result.value, "title");
  });

  test("applies to every selected line", () => {
    const value = "one\ntwo";
    const result = setHeading(value, 0, value.length, 1);
    assert.equal(result.value, "# one\n# two");
  });
});

describe("prefixLines", () => {
  test("adds bullet prefixes to selected lines", () => {
    const value = "a\nb\nc";
    const result = prefixLines(value, 0, value.length, "- ", false);
    assert.equal(result.value, "- a\n- b\n- c");
  });

  test("removes the prefix when every line already has it", () => {
    const value = "- a\n- b";
    const result = prefixLines(value, 0, value.length, "- ", false);
    assert.equal(result.value, "a\nb");
  });

  test("skips blank lines when prefixing", () => {
    const value = "a\n\nb";
    const result = prefixLines(value, 0, value.length, "> ", false);
    assert.equal(result.value, "> a\n\n> b");
  });

  test("numbers lines sequentially", () => {
    const value = "a\nb\nc";
    const result = prefixLines(value, 0, value.length, "", true);
    assert.equal(result.value, "1. a\n2. b\n3. c");
  });

  test("removes numbering when every line is numbered", () => {
    const value = "1. a\n2. b";
    const result = prefixLines(value, 0, value.length, "", true);
    assert.equal(result.value, "a\nb");
  });

  test("task prefix produces GFM checkboxes", () => {
    const result = prefixLines("todo", 0, 4, "- [ ] ", false);
    assert.equal(result.value, "- [ ] todo");
  });

  test("expands the selection to full lines", () => {
    const value = "first line\nsecond line";
    // Selection spans the middle of both lines.
    const result = prefixLines(value, 3, 14, "- ", false);
    assert.equal(result.value, "- first line\n- second line");
  });
});

describe("fenceCodeBlock", () => {
  test("wraps the selected lines in fences", () => {
    const result = fenceCodeBlock("code()", 0, 6);
    assert.equal(result.value, "```\ncode()\n```");
  });

  test("removes fences when the selection is already fenced", () => {
    const value = "```\ncode()\n```";
    const result = fenceCodeBlock(value, 0, value.length);
    assert.equal(result.value, "code()");
  });

  test("leaves surrounding text untouched", () => {
    const value = "before\ncode()\nafter";
    const result = fenceCodeBlock(value, 7, 13);
    assert.equal(result.value, "before\n```\ncode()\n```\nafter");
  });
});
