/**
 * @fileoverview Shared time-formatting helpers exposed as window.TimeFmt.
 *
 * Centralises the millisecond -> days/hours/minutes/seconds breakdown used by
 * both the vault listing ("3 days left") and the retrieve-page countdown
 * ("2d 5h"), so the unit math lives in one place instead of being reimplemented
 * per page.
 */
(function () {
  "use strict";

  const MS_PER = {
    day: 1000 * 60 * 60 * 24,
    hour: 1000 * 60 * 60,
    minute: 1000 * 60,
    second: 1000,
  };

  /**
   * Break a millisecond span into whole days/hours/minutes/seconds.
   *
   * Negative spans clamp to zero; a NaN span yields all-NaN fields so callers
   * can detect an unparseable date.
   *
   * @param {number} ms
   * @returns {{days: number, hours: number, minutes: number, seconds: number}}
   */
  const breakdown = (ms) => {
    if (Number.isNaN(ms)) {
      return { days: NaN, hours: NaN, minutes: NaN, seconds: NaN };
    }
    const clamped = Math.max(0, ms);
    return {
      days: Math.floor(clamped / MS_PER.day),
      hours: Math.floor((clamped % MS_PER.day) / MS_PER.hour),
      minutes: Math.floor((clamped % MS_PER.hour) / MS_PER.minute),
      seconds: Math.floor((clamped % MS_PER.minute) / MS_PER.second),
    };
  };

  /**
   * Coarse "time remaining" string using only the largest non-zero unit
   * (days, else hours, else minutes). Used where an approximate distance is
   * enough, e.g. "3 days" / "5 hours" / "12 minutes". Returns "unknown time"
   * for a NaN span.
   *
   * @param {number} ms
   * @returns {string}
   */
  const coarse = (ms) => {
    if (Number.isNaN(ms)) {
      return "unknown time";
    }
    const { days, hours, minutes } = breakdown(ms);
    if (days > 0) return `${days} day${days === 1 ? "" : "s"}`;
    if (hours > 0) return `${hours} hour${hours === 1 ? "" : "s"}`;
    return `${minutes} minute${minutes === 1 ? "" : "s"}`;
  };

  window.TimeFmt = { breakdown, coarse };
})();
