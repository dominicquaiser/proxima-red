/**
 * @fileoverview Pure text-manipulation functions behind the note editor's
 * tool rail, exposed as window.NoteToolbar.
 *
 * Public functions take textarea content plus selection offsets and return the
 * edited text plus post-edit selection. Kept DOM-free for Node tests.
 */
(function () {
  "use strict";

  const HEADING_RE = /^(#{1,6})\s+/;
  const NUMBERED_PREFIX_RE = /^\d+\.\s+/;
  const CODE_FENCE_OPEN_RE = /^```/;
  const CODE_FENCE_CLOSE_RE = /^```\s*$/;

  /**
   * @typedef {Object} LineSpan
   * @property {number} start
   * @property {number} end
   */

  /**
   * @typedef {Object} ToolbarEdit
   * @property {string} value
   * @property {number} selStart
   * @property {number} selEnd
   */

  /**
   * Return bounds for full lines touched by the selection.
   *
   * @param {string} value
   * @param {number} selStart
   * @param {number} selEnd
   * @returns {LineSpan}
   */
  function lineSpan(value, selStart, selEnd) {
    const start = value.lastIndexOf("\n", selStart - 1) + 1;
    const newlineAfterSelection = value.indexOf("\n", selEnd);
    const end = newlineAfterSelection === -1 ? value.length : newlineAfterSelection;

    return { start, end };
  }

  /** @returns {string} value with [start, end) replaced. */
  function replaceRange(value, start, end, replacement) {
    return value.slice(0, start) + replacement + value.slice(end);
  }

  /**
   * Toggle an inline Markdown marker around the selection.
   *
   * @param {string} value
   * @param {number} selStart
   * @param {number} selEnd
   * @param {string} marker
   * @returns {ToolbarEdit}
   */
  function wrapInline(value, selStart, selEnd, marker) {
    const selected = value.slice(selStart, selEnd);

    const selectionIncludesMarkers =
      selected.length >= 2 * marker.length &&
      selected.startsWith(marker) &&
      selected.endsWith(marker);

    if (selectionIncludesMarkers) {
      const inner = selected.slice(marker.length, selected.length - marker.length);
      return {
        value: replaceRange(value, selStart, selEnd, inner),
        selStart: selStart,
        selEnd: selStart + inner.length,
      };
    }

    const markerBeforeSelection = value.slice(selStart - marker.length, selStart);
    const markerAfterSelection = value.slice(selEnd, selEnd + marker.length);
    if (markerBeforeSelection === marker && markerAfterSelection === marker) {
      return {
        value: replaceRange(value, selStart - marker.length, selEnd + marker.length, selected),
        selStart: selStart - marker.length,
        selEnd: selEnd - marker.length,
      };
    }

    const wrapped = marker + selected + marker;
    return {
      value: replaceRange(value, selStart, selEnd, wrapped),
      selStart: selStart + marker.length,
      selEnd: selStart + marker.length + selected.length,
    };
  }

  /**
   * Set or toggle off a Markdown heading level on selected lines.
   *
   * @param {string} value
   * @param {number} selStart
   * @param {number} selEnd
   * @param {number} level
   * @returns {ToolbarEdit}
   */
  function setHeading(value, selStart, selEnd, level) {
    const span = lineSpan(value, selStart, selEnd);
    const headingPrefix = "#".repeat(level) + " ";
    const selectedLines = value.slice(span.start, span.end).split("\n");

    const rewritten = selectedLines
      .map(function (line) {
        const currentHeading = line.match(HEADING_RE);
        const body = currentHeading ? line.slice(currentHeading[0].length) : line;

        if (currentHeading && currentHeading[1].length === level) {
          return body;
        }
        return headingPrefix + body;
      })
      .join("\n");

    return {
      value: replaceRange(value, span.start, span.end, rewritten),
      selStart: span.start,
      selEnd: span.start + rewritten.length,
    };
  }

  /**
   * Toggle a line prefix or numbered-list marker on selected non-blank lines.
   *
   * @param {string} value
   * @param {number} selStart
   * @param {number} selEnd
   * @param {string} prefix
   * @param {boolean} numbered
   * @returns {ToolbarEdit}
   */
  function prefixLines(value, selStart, selEnd, prefix, numbered) {
    const span = lineSpan(value, selStart, selEnd);
    const selectedLines = value.slice(span.start, span.end).split("\n");

    function lineHasPrefix(line) {
      return numbered ? NUMBERED_PREFIX_RE.test(line) : line.startsWith(prefix);
    }

    const everyNonBlankLinePrefixed = selectedLines.every(function (line) {
      return !line.trim() || lineHasPrefix(line);
    });

    const rewritten = selectedLines
      .map(function (line, index) {
        if (!line.trim()) return line;

        if (everyNonBlankLinePrefixed) {
          return numbered ? line.replace(NUMBERED_PREFIX_RE, "") : line.slice(prefix.length);
        }

        return numbered ? index + 1 + ". " + line : prefix + line;
      })
      .join("\n");

    return {
      value: replaceRange(value, span.start, span.end, rewritten),
      selStart: span.start,
      selEnd: span.start + rewritten.length,
    };
  }

  /**
   * Toggle fenced-code-block markers around selected lines.
   *
   * @param {string} value
   * @param {number} selStart
   * @param {number} selEnd
   * @returns {ToolbarEdit}
   */
  function fenceCodeBlock(value, selStart, selEnd) {
    const span = lineSpan(value, selStart, selEnd);
    const block = value.slice(span.start, span.end);
    const lines = block.split("\n");
    const firstLine = lines[0];
    const lastLine = lines[lines.length - 1];

    if (
      lines.length >= 2 &&
      CODE_FENCE_OPEN_RE.test(firstLine) &&
      CODE_FENCE_CLOSE_RE.test(lastLine)
    ) {
      const inner = lines.slice(1, -1).join("\n");
      return {
        value: replaceRange(value, span.start, span.end, inner),
        selStart: span.start,
        selEnd: span.start + inner.length,
      };
    }

    const fenced = "```\n" + block + "\n```";
    return {
      value: replaceRange(value, span.start, span.end, fenced),
      selStart: span.start,
      selEnd: span.start + fenced.length,
    };
  }

  window.NoteToolbar = { wrapInline, setHeading, prefixLines, fenceCodeBlock };
})();
