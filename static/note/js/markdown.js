/**
 * @fileoverview Markdown rendering for notes, exposed as window.NoteMarkdown.
 *
 * Raw author HTML is escaped by marked, then DOMPurify sanitizes the generated
 * markup against a small allowlist. Rendering stays client-side for encrypted
 * and plain notes alike.
 */
(function () {
  "use strict";

  const LANGUAGE_CLASS_RE = /^language-[\w+-]+$/;
  const ABSOLUTE_URL_RE = /^[a-z][a-z0-9+.-]*:/i;
  const HEADING_SELECTOR = "h1, h2, h3, h4, h5, h6";
  const INTERNAL_LINKS_BOUND = "internalLinksBound";

  // Tags marked can emit for the supported GFM syntax.
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

  // No style/class/event pass-through. class has one hook-guarded exception.
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

  // The one allowed class shape: explicit fence language for highlight.js.
  function isHighlightLanguageClass(value) {
    return LANGUAGE_CLASS_RE.test(value);
  }

  // Disable raw author HTML by rendering it as text before sanitization.
  window.marked.use({
    gfm: true,
    breaks: false,
    renderer: {
      html(token) {
        return escapeHtml(token.text);
      },
    },
  });

  /** @param {string} href */
  function isAbsoluteUrl(href) {
    return ABSOLUTE_URL_RE.test(href) || href.slice(0, 2) === "//";
  }

  // Absolute links open safely; #anchors stay local; unresolved relative links
  // become inert because standalone shared notes have no note filesystem.
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

  // Keep only validated language classes on code blocks for highlight.js.
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
   * Render markdown to sanitized HTML.
   *
   * @param {string} source
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
   * Highlight code blocks after sanitization. No-op without highlight.js.
   *
   * @param {Element} container
   */
  function highlightAll(container) {
    if (!window.hljs || !container) return;
    container.querySelectorAll("pre code").forEach(function (block) {
      window.hljs.highlightElement(block);
    });
  }

  /**
   * Slugify heading text into a GitHub-style anchor id.
   *
   * @param {string} text
   * @returns {string}
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
   * Give headings slug ids after sanitization so #anchor links can resolve.
   *
   * @param {Element} container
   */
  function addHeadingIds(container) {
    if (!container) return;
    const seen = new Map();
    container.querySelectorAll(HEADING_SELECTOR).forEach(function (heading) {
      const base = slugifyHeading(heading.textContent);
      if (!base) return;
      const count = seen.get(base) || 0;
      seen.set(base, count + 1);
      heading.id = count ? base + "-" + count : base;
    });
  }

  /**
   * Wire same-document #anchor clicks to smooth scrolling.
   *
   * @param {Element} container
   */
  function enableInternalLinks(container) {
    if (!container || container.dataset[INTERNAL_LINKS_BOUND]) return;
    container.dataset[INTERNAL_LINKS_BOUND] = "1";
    container.addEventListener("click", function (event) {
      const link = event.target.closest('a[href^="#"]');
      if (!link || !container.contains(link)) return;
      const id = decodeURIComponent(link.getAttribute("href").slice(1));
      if (!id) return;
      const target = findElementById(container, id);
      if (!target) return;
      event.preventDefault();
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  function findElementById(container, id) {
    let target = null;
    container.querySelectorAll("[id]").forEach(function (element) {
      if (!target && element.id === id) target = element;
    });
    return target;
  }

  /**
   * Render markdown into an element and run post-processing.
   *
   * @param {Element} el
   * @param {string} source
   */
  function renderInto(el, source) {
    el.innerHTML = render(source);
    highlightAll(el);
    addHeadingIds(el);
    enableInternalLinks(el);
  }

  /**
   * Derive a filename-friendly title from the first heading or non-empty line.
   *
   * @param {string} source
   * @param {string} [fallback="note"]
   * @returns {string}
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
