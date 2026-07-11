/**
 * @fileoverview Markdown rendering for the note tool, exposed as
 * window.NoteMarkdown. Wraps the vendored marked + DOMPurify with the
 * strictest useful configuration.
 *
 * Rendering is client-side only: the server cannot render encrypted notes,
 * and plain-text notes go through the same pipeline so there is exactly one
 * rendering path to audit.
 *
 * Two defensive layers, plus the site CSP as backstop:
 *  1. marked is configured to ESCAPE raw HTML (author HTML renders as
 *     literal text, both block and inline tokens).
 *  2. DOMPurify sanitizes the rendered HTML against a tag/attribute
 *     allowlist (no style/class/event handlers; javascript: URIs stripped).
 *
 * Load order: vendor/marked.min.js, vendor/purify.min.js, then this file.
 */
(function () {
  "use strict";

  // Tags marked can emit for the supported syntax (GFM: headings, emphasis,
  // lists + task-list checkboxes, quotes, code, links, images, tables, hr).
  const ALLOWED_TAGS = [
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "br",
    "hr",
    "ul",
    "ol",
    "li",
    "blockquote",
    "pre",
    "code",
    "em",
    "strong",
    "del",
    "a",
    "img",
    "input",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
  ];

  // No style/class pass-through and no event handlers. "checked"/"disabled"/
  // "type" exist only for GFM task-list checkboxes; "align" for table cells.
  const ALLOWED_ATTR = [
    "href",
    "title",
    "alt",
    "src",
    "type",
    "checked",
    "disabled",
    "align",
    "start",
  ];

  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // marked emits an explicit fence language as `class="language-xxx"` on the
  // <code>. That class is the ONE exception we let past the sanitizer (only on
  // <pre>/<code>, see the hook below) so the highlighter can honor the author's
  // choice instead of always auto-detecting. The value is strictly validated so
  // nothing but a bare language token can survive; no spaces/quotes/angle
  // brackets, so it can never break out of the attribute.
  function isHighlightLanguageClass(value) {
    return /^language-[\w+-]+$/.test(value);
  }

  // Raw author HTML (block and inline tokens both arrive here in marked v15)
  // is escaped to literal text - "HTML disabled" rather than "HTML sanitized".
  window.marked.use({
    gfm: true,
    breaks: false,
    renderer: {
      html(token) {
        return escapeHtml(token.text);
      },
    },
  });

  // An href with a URL scheme (http:, https:, mailto:, ...) or protocol-relative
  // `//host`. Dangerous schemes like javascript: are already stripped by DOMPurify
  // before this runs, so anything matching here is a safe outbound link.
  // Same-document `#anchor` and relative paths (which have no scheme) are handled
  // separately below.
  function isAbsoluteUrl(href) {
    return /^[a-z][a-z0-9+.-]*:/i.test(href) || href.slice(0, 2) === "//";
  }

  // Links are triaged by target so each kind behaves honestly in a standalone
  // note (there is no vault/filesystem to resolve anything against):
  //  - absolute URLs open in a new tab with no window.opener handle back to us;
  //  - `#anchor` links stay same-document (no target=_blank, which would open a
  //    blank tab) and are smooth-scrolled by enableInternalLinks;
  //  - relative paths (`./other.md`, `../x`) can't resolve to anything, so we
  //    strip the href and add a tooltip explaining cross-note links aren't
  //    supported yet.
  window.DOMPurify.addHook("afterSanitizeAttributes", function (node) {
    if (node.tagName !== "A") return;
    const href = node.getAttribute("href");
    if (!href) return;
    if (href.charAt(0) === "#") return;
    if (isAbsoluteUrl(href)) {
      node.setAttribute("target", "_blank");
      node.setAttribute("rel", "noopener noreferrer");
      return;
    }
    node.removeAttribute("href");
    node.setAttribute("title", "Cross-note links aren't supported yet");
  });

  // `class` is not in ALLOWED_ATTR, so DOMPurify strips it everywhere by
  // default (the deliberate "no class pass-through" rule). We carve out exactly
  // one exception: a validated `language-xxx` on <pre>/<code>, force-kept so the
  // highlighter (highlight.js, run post-sanitize in highlightAll) can honor an
  // explicit fence language. Any other class, or this one on any other element,
  // is still dropped.
  window.DOMPurify.addHook("uponSanitizeAttribute", function (node, data) {
    if (
      data.attrName === "class" &&
      (node.tagName === "CODE" || node.tagName === "PRE") &&
      isHighlightLanguageClass(data.attrValue)
    ) {
      data.forceKeepAttr = true;
    }
  });

  /**
   * Render markdown source to sanitized HTML.
   *
   * Note on remote images: the site CSP (`img-src 'self' data:`) blocks
   * loading of cross-origin <img> targets, which is intended behavior -
   * remote images in notes would be tracking pixels.
   *
   * @param {string} source Markdown text.
   * @returns {string} Sanitized HTML, safe to assign to innerHTML.
   */
  function render(source) {
    const html = window.marked.parse(source || "");
    return window.DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ALLOWED_TAGS,
      ALLOWED_ATTR: ALLOWED_ATTR,
    });
  }

  /**
   * Syntax-highlight every code block already present in a container.
   *
   * Runs AFTER sanitization on the live DOM: highlight.js reads each block's
   * textContent (already sanitized + escaped), escapes it again, and writes its
   * own token <span>s back. No untrusted HTML re-enters the sanitizer, so the
   * strict ALLOWED_TAGS/ALLOWED_ATTR allowlist is untouched. An explicit
   * `language-xxx` (kept by the hook above) is honored; otherwise highlight.js
   * auto-detects. No-op if the highlighter script is absent.
   *
   * @param {Element} container Element whose `pre code` blocks to highlight.
   */
  function highlightAll(container) {
    if (!window.hljs || !container) return;
    container.querySelectorAll("pre code").forEach(function (block) {
      window.hljs.highlightElement(block);
    });
  }

  /**
   * Slugify a heading's text into a GitHub-style anchor id: lowercased, with
   * punctuation dropped and whitespace collapsed to single hyphens. Matches how
   * `[Prerequisites](#prerequisites)` is expected to resolve. Returns "" when
   * the heading has no slug-worthy characters.
   *
   * @param {string} text Heading text content.
   * @returns {string} A slug like "getting-started" (only [a-z0-9-]).
   */
  function slugifyHeading(text) {
    return (text || "")
      .toLowerCase()
      .trim()
      .replace(/[^\w\s-]/g, "")
      .replace(/[\s_]+/g, "-")
      .replace(/^-+|-+$/g, "");
  }

  /**
   * Give every heading in a container a slug `id` so in-note `#anchor` links
   * have something to jump to. Runs on the live DOM after sanitization (like
   * highlightAll), so the sanitizer never has to allow `id` through. Duplicate
   * slugs get a `-1`, `-2`, ... suffix, mirroring GitHub's disambiguation.
   *
   * @param {Element} container Element whose headings to id.
   */
  function addHeadingIds(container) {
    if (!container) return;
    const seen = new Map();
    container.querySelectorAll("h1, h2, h3, h4, h5, h6").forEach(function (h) {
      const base = slugifyHeading(h.textContent);
      if (!base) return;
      const count = seen.get(base) || 0;
      seen.set(base, count + 1);
      h.id = count ? base + "-" + count : base;
    });
  }

  /**
   * Wire same-document `#anchor` clicks inside a container to a smooth scroll to
   * the matching heading id. Delegated on the container (which outlives each
   * render), and bound only once so repeated renders don't stack listeners.
   * Links whose target isn't found fall through to default behavior.
   *
   * @param {Element} container Element to delegate clicks on.
   */
  function enableInternalLinks(container) {
    if (!container || container.dataset.internalLinksBound) return;
    container.dataset.internalLinksBound = "1";
    container.addEventListener("click", function (event) {
      const link = event.target.closest('a[href^="#"]');
      if (!link || !container.contains(link)) return;
      const id = decodeURIComponent(link.getAttribute("href").slice(1));
      if (!id) return;
      let target = null;
      container.querySelectorAll("[id]").forEach(function (el) {
        if (!target && el.id === id) target = el;
      });
      if (!target) return;
      event.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  /**
   * Render markdown into an element and highlight its code blocks. This is the
   * one entry point callers should use so highlighting stays centralized.
   *
   * @param {Element} el Target element (its innerHTML is replaced).
   * @param {string} source Markdown text.
   */
  function renderInto(el, source) {
    el.innerHTML = render(source);
    highlightAll(el);
    addHeadingIds(el);
    enableInternalLinks(el);
  }

  /**
   * Derive a filename-friendly title from the note's first markdown heading
   * (or its first non-empty line), used for the .md download.
   *
   * @param {string} source Markdown text.
   * @param {string} [fallback="note"] Name when the note is empty.
   * @returns {string} A slug like "project-kickoff-notes" (no extension).
   */
  function titleSlug(source, fallback = "note") {
    const lines = (source || "").split("\n");
    let title = "";
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      title = trimmed.replace(/^#{1,6}\s+/, "");
      break;
    }
    const slug = title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 60);
    return slug || fallback;
  }

  // isHighlightLanguageClass and slugifyHeading are exposed for DOM-free tests.
  window.NoteMarkdown = {
    render,
    renderInto,
    titleSlug,
    slugifyHeading,
    isHighlightLanguageClass,
  };
})();
