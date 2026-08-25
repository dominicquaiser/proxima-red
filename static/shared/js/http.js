/**
 * @fileoverview Shared HTTP utilities exposed as window.Http.
 *
 * Provides CSRF-aware fetch wrappers so every page can submit forms or
 * JSON payloads without re-implementing CSRF lookup and fetch/parse boilerplate.
 */
(function () {
  "use strict";

  const DEFAULT_ERROR_MESSAGE = "An unexpected error occurred.";

  /**
   * Describe a reply that could not be parsed as JSON.
   *
   * These endpoints answer JSON, so a body that will not parse is the server
   * (or something in front of it) answering with a page instead: a
   * `block=True` rate limiter handing back the HTML 403, a proxy error page,
   * or a redirect to sign-in that fetch followed transparently. The status is
   * the only evidence available, so map it to something the user can act on.
   *
   * @param {Response} response
   * @returns {string}
   */
  const statusErrorMessage = (response) => {
    // A followed redirect is a 200 carrying someone else's HTML: an auth or
    // rate-limit bounce, not the endpoint's own answer.
    if (response.redirected) {
      return "Your session may have expired. Please reload the page and try again.";
    }
    if (response.status === 401) {
      return "Your session has expired. Please sign in again.";
    }
    if (response.status === 403) {
      return "That request was refused. Wait a moment, then reload the page and try again.";
    }
    if (response.status === 429) {
      return "Too many requests. Please wait a moment and try again.";
    }
    if (response.status >= 500) {
      return "The server could not complete that request. Please try again.";
    }
    return DEFAULT_ERROR_MESSAGE;
  };

  /**
   * Parse a reply body, guaranteeing callers a non-null object.
   *
   * `Response.json()` rejects on a non-JSON body, and every caller here
   * reaches straight for `result.success` / `result.error`. Letting the
   * rejection escape surfaced the parser's own complaint ("Unexpected token
   * '<'") as the user-facing error on every rate limit and proxy hiccup, and
   * skipped the caller's own error handling on the way past. Synthesising a
   * failure body instead keeps that handling on the normal path.
   *
   * @param {Response} response
   * @returns {Promise<Object>} The parsed body, or a synthesized failure.
   */
  const parseJsonBody = async (response) => {
    let parsed;
    try {
      parsed = await response.json();
    } catch (error) {
      return { success: false, error: statusErrorMessage(response) };
    }
    // Valid JSON that is not a plain object (`null`, a string, a number, an
    // array) leaves the same callers reading `success`/`error` off something
    // that has neither. `null` throws outright; the rest degrade to an error
    // with no message. Normalise them all to the failure shape.
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { success: false, error: statusErrorMessage(response) };
    }
    return parsed;
  };

  /**
   * Resolve the CSRF token from the DOM or cookie jar.
   *
   * Prefers a hidden `csrfmiddlewaretoken` form field anywhere in the
   * document, falling back to the `csrftoken` cookie when no field is found.
   *
   * @returns {string|null} The CSRF token, or null if not found.
   */
  const getCsrfToken = () => {
    const field = document.querySelector('input[name="csrfmiddlewaretoken"]');
    if (field && field.value) {
      return field.value;
    }
    const match = document.cookie.match(/csrftoken=([^;]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  };

  /**
   * POST to `url` with this app's standard headers and parse the JSON reply.
   *
   * Body encoding is determined by type:
   * - `HTMLFormElement` is converted to `FormData` first.
   * - `FormData` / `URLSearchParams` are sent as `application/x-www-form-urlencoded`.
   * - Any other object is sent as `application/json`.
   *
   * Both the raw `Response` and parsed body are returned so callers retain
   * full control over success/error handling. `result` is always a non-null
   * object: a reply that is not a JSON object becomes
   * `{success: false, error}` (see `parseJsonBody`), so `result.success` and
   * `result.error` are safe to read without a guard.
   *
   * @param {string} url - The endpoint to POST to.
   * @param {FormData|URLSearchParams|HTMLFormElement|Object} body - Request payload.
   * @returns {Promise<{response: Response, result: Object}>}
   */
  const postForm = async (url, body) => {
    const normalizedBody = body instanceof HTMLFormElement ? new FormData(body) : body;

    const headers = { "X-Requested-With": "XMLHttpRequest" };
    let payload;

    if (normalizedBody instanceof FormData || normalizedBody instanceof URLSearchParams) {
      const params = new URLSearchParams(normalizedBody);
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      headers["X-CSRFToken"] = params.get("csrfmiddlewaretoken") || getCsrfToken() || "";
      payload = params;
    } else {
      headers["Content-Type"] = "application/json";
      headers["X-CSRFToken"] = getCsrfToken() || "";
      payload = JSON.stringify(normalizedBody);
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body: payload,
      credentials: "same-origin",
    });
    return { response, result: await parseJsonBody(response) };
  };

  /**
   * GET `url` as an AJAX request and parse the JSON reply.
   *
   * The read-only counterpart to `postForm`: sends the
   * `X-Requested-With: XMLHttpRequest` header (so Django's `is_ajax_request`
   * sees it) with same-origin credentials, and returns both the raw `Response`
   * and the parsed body so callers control success/error handling. No CSRF
   * token is needed for a GET. `result` carries the same always-an-object
   * guarantee as `postForm`.
   *
   * @param {string} url - The endpoint to GET.
   * @returns {Promise<{response: Response, result: Object}>}
   */
  const getJson = async (url) => {
    const response = await fetch(url, {
      headers: { "X-Requested-With": "XMLHttpRequest" },
      credentials: "same-origin",
    });
    return { response, result: await parseJsonBody(response) };
  };

  /**
   * Extract the first human-readable message from a parsed AJAX response.
   *
   * Handles two shapes that the views produce:
   * - `{ error: "string message" }`: a top-level error string.
   * - `{ errors: ... }`: Django form errors: an array of strings, a plain
   *   string, or an object mapping field names to a string or string array.
   *
   * @param {{ error?: string, errors?: string|string[]|Object }} result
   * @returns {string} The first message found, or a generic fallback.
   */
  const firstError = (result) => {
    const payload = result && (result.errors || result.error);
    if (!payload) {
      return DEFAULT_ERROR_MESSAGE;
    }
    if (typeof payload === "string") {
      return payload;
    }
    if (Array.isArray(payload)) {
      return payload[0];
    }
    // payload is a field-keyed errors object; grab the first field's message
    const firstKey = Object.keys(payload)[0];
    if (!firstKey) {
      return DEFAULT_ERROR_MESSAGE;
    }
    const value = payload[firstKey];
    if (Array.isArray(value)) {
      return value[0];
    }
    if (typeof value === "string") {
      return value;
    }
    return DEFAULT_ERROR_MESSAGE;
  };

  window.Http = { getCsrfToken, postForm, getJson, firstError };
})();
