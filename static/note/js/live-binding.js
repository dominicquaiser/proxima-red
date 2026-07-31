/**
 * @fileoverview DOM-free text diff/splice helpers for the live-note textarea
 * and Yjs document bridge.
 *
 * All offsets are UTF-16 code units, matching Y.Text and textarea selections.
 */
(function () {
  "use strict";

  /**
   * Diff two strings into one changed region.
   *
   * The suffix scan stops at the prefix boundary, resolving overlaps like
   * "aa" -> "aaa" as an insertion at the end.
   *
   * @param {string} oldStr
   * @param {string} newStr
   * @returns {{index: number, removed: string, inserted: string}|null}
   */
  function diffText(oldStr, newStr) {
    if (oldStr === newStr) return null;

    let start = 0;
    const minLen = Math.min(oldStr.length, newStr.length);
    while (start < minLen && oldStr[start] === newStr[start]) start++;

    let endOld = oldStr.length;
    let endNew = newStr.length;
    while (endOld > start && endNew > start && oldStr[endOld - 1] === newStr[endNew - 1]) {
      endOld--;
      endNew--;
    }

    return {
      index: start,
      removed: oldStr.slice(start, endOld),
      inserted: newStr.slice(start, endNew),
    };
  }

  /**
   * Convert a Y.Text observer delta into splices in pre-change coordinates.
   *
   * The result is ascending and can be applied in reverse order without
   * rebasing. Insert/delete pairs at the same index intentionally stay split.
   *
   * @param {Array<Object>} delta
   * @returns {Array<{index: number, remove: number, insert: string}>}
   */
  function spliceListFromDelta(delta) {
    const splices = [];
    let pos = 0;
    for (const op of delta) {
      if (typeof op.retain === "number") {
        pos += op.retain;
      } else if (typeof op.insert === "string") {
        splices.push({ index: pos, remove: 0, insert: op.insert });
      } else if (typeof op.delete === "number") {
        splices.push({ index: pos, remove: op.delete, insert: "" });
        pos += op.delete;
      }
    }
    return splices;
  }

  /**
   * Carry a caret/selection offset across remote splices.
   *
   * Inserts exactly at the offset keep the caret before the remote text;
   * deletions spanning the offset clamp it to the deletion start.
   *
   * @param {number} offset
   * @param {Array<{index: number, remove: number, insert: string}>} splices
   * @returns {number}
   */
  function transformOffset(offset, splices) {
    let result = offset;
    for (const splice of splices) {
      if (splice.index >= offset) break;
      const removeEnd = splice.index + splice.remove;
      if (removeEnd <= offset) {
        result += splice.insert.length - splice.remove;
      } else {
        // The deletion spans the offset: collapse to its start.
        result -= offset - splice.index;
        break;
      }
    }
    return result;
  }

  /**
   * Apply a splice list to a string in reverse index order.
   *
   * @param {string} str
   * @param {Array<{index: number, remove: number, insert: string}>} splices
   * @returns {string}
   */
  function applySplices(str, splices) {
    let result = str;
    for (let i = splices.length - 1; i >= 0; i--) {
      const splice = splices[i];
      result =
        result.slice(0, splice.index) + splice.insert + result.slice(splice.index + splice.remove);
    }
    return result;
  }

  window.NoteLiveBinding = {
    diffText,
    spliceListFromDelta,
    transformOffset,
    applySplices,
  };
})();
