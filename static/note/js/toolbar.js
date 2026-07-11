/**
 * @fileoverview Pure text-manipulation functions behind the note editor's
 * tool rail, exposed as window.NoteToolbar.
 *
 * Every function takes (value, selStart, selEnd) - the textarea's content and
 * selection - and returns {value, selStart, selEnd} describing the edited
 * text and the selection afterwards. Deliberately DOM-free so Node can test
 * them directly (tests/js/toolbar.test.js); editor.js owns applying the
 * result to the real textarea.
 */
(function () {
  "use strict";

  /** Bounds of the full lines covered by the selection. */
  function lineSpan(value, selStart, selEnd) {
    const start = value.lastIndexOf("\n", selStart - 1) + 1;
    const newlineAfter = value.indexOf("\n", selEnd);
    const end = newlineAfter === -1 ? value.length : newlineAfter;
    return { start, end };
  }

  function splice(value, start, end, replacement) {
    return value.slice(0, start) + replacement + value.slice(end);
  }

  /**
   * Toggle an inline marker (e.g. "**", "_", "~~") around the selection.
   * With no selection, insert a marker pair and place the caret inside it.
   */
  function wrapInline(value, selStart, selEnd, marker) {
    const selected = value.slice(selStart, selEnd);

    // Unwrap when the selection is already wrapped ("**bold**" selected as a
    // whole, or "bold" selected inside its markers).
    if (
      selected.length >= 2 * marker.length &&
      selected.startsWith(marker) &&
      selected.endsWith(marker)
    ) {
      const inner = selected.slice(marker.length, selected.length - marker.length);
      return {
        value: splice(value, selStart, selEnd, inner),
        selStart: selStart,
        selEnd: selStart + inner.length,
      };
    }
    if (
      value.slice(selStart - marker.length, selStart) === marker &&
      value.slice(selEnd, selEnd + marker.length) === marker
    ) {
      return {
        value: splice(value, selStart - marker.length, selEnd + marker.length, selected),
        selStart: selStart - marker.length,
        selEnd: selEnd - marker.length,
      };
    }

    const wrapped = marker + selected + marker;
    return {
      value: splice(value, selStart, selEnd, wrapped),
      selStart: selStart + marker.length,
      selEnd: selStart + marker.length + selected.length,
    };
  }

  /**
   * Set (or toggle off) the heading level of every line in the selection.
   * A line already at exactly `level` loses its heading; other lines are
   * rewritten to the requested level.
   */
  function setHeading(value, selStart, selEnd, level) {
    const span = lineSpan(value, selStart, selEnd);
    const prefix = "#".repeat(level) + " ";

    const rewritten = value
      .slice(span.start, span.end)
      .split("\n")
      .map(function (line) {
        const current = line.match(/^(#{1,6})\s+/);
        const body = current ? line.slice(current[0].length) : line;
        if (current && current[1].length === level) {
          return body; // toggle off
        }
        return prefix + body;
      })
      .join("\n");

    return {
      value: splice(value, span.start, span.end, rewritten),
      selStart: span.start,
      selEnd: span.start + rewritten.length,
    };
  }

  /**
   * Toggle a line prefix over the selection: "- " (bullets), "> " (quote),
   * "- [ ] " (tasks), or numbered items when `numbered` is true. If every
   * selected line already carries the prefix it is removed, otherwise added.
   */
  function prefixLines(value, selStart, selEnd, prefix, numbered) {
    const span = lineSpan(value, selStart, selEnd);
    const lines = value.slice(span.start, span.end).split("\n");

    const matcher = numbered ? /^\d+\.\s+/ : null;
    const hasPrefix = function (line) {
      return numbered ? matcher.test(line) : line.startsWith(prefix);
    };
    const allPrefixed = lines.every(function (line) {
      return !line.trim() || hasPrefix(line);
    });

    const rewritten = lines
      .map(function (line, i) {
        if (!line.trim()) return line;
        if (allPrefixed) {
          return numbered ? line.replace(matcher, "") : line.slice(prefix.length);
        }
        return numbered ? i + 1 + ". " + line : prefix + line;
      })
      .join("\n");

    return {
      value: splice(value, span.start, span.end, rewritten),
      selStart: span.start,
      selEnd: span.start + rewritten.length,
    };
  }

  /**
   * Wrap the selected lines in a fenced code block (or remove the fences when
   * the selection is already exactly fenced).
   */
  function fenceCodeBlock(value, selStart, selEnd) {
    const span = lineSpan(value, selStart, selEnd);
    const block = value.slice(span.start, span.end);
    const lines = block.split("\n");

    if (lines.length >= 2 && /^```/.test(lines[0]) && /^```\s*$/.test(lines[lines.length - 1])) {
      const inner = lines.slice(1, -1).join("\n");
      return {
        value: splice(value, span.start, span.end, inner),
        selStart: span.start,
        selEnd: span.start + inner.length,
      };
    }

    const fenced = "```\n" + block + "\n```";
    return {
      value: splice(value, span.start, span.end, fenced),
      selStart: span.start,
      selEnd: span.start + fenced.length,
    };
  }

  window.NoteToolbar = { wrapInline, setHeading, prefixLines, fenceCodeBlock };
})();
