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
  // Preserve blocked URLs for placeholder metadata and host labels.
  const BLOCKED_SRC_ATTR = "data-blocked-src";
  const BLOCKED_IMAGE_SELECTOR = "img[" + BLOCKED_SRC_ATTR + "]";

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

  /**
   * Escape the five HTML-significant characters.
   *
   * Escape author HTML before sanitization so it remains visible as text.
   *
   * @param {string} text
   * @returns {string}
   */
  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  /**
   * The one allowed class shape: an explicit fence language for highlight.js.
   *
   * Everything else is stripped, so `class` cannot be used to pull in page
   * styling from a shared note.
   *
   * @param {string} value Candidate class attribute value.
   * @returns {boolean}
   */
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

  /**
   * @param {string} href
   * @returns {boolean} True for a scheme-qualified or protocol-relative URL.
   */
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

  /**
   * Check whether an image URL falls outside the allowed data and same-origin sources.
   *
   * Allow data URLs and URLs resolving to the page origin. Blocking other
   * origins prevents image hosts from learning when a reader opens a note.
   *
   * @param {string} src Raw `src` attribute value.
   * @param {string} origin Page origin, e.g. "https://note.proxima.red".
   * @returns {boolean} True when the image must not be rendered.
   */
  function isBlockedImageSrc(src, origin) {
    if (!src) return false;
    let url;
    try {
      // Resolving against the origin normalises relative and
      // protocol-relative forms, so they compare like any other URL.
      url = new URL(src, origin);
    } catch (error) {
      return true; // Unparseable: refuse rather than hand it to the browser.
    }
    // Inline bytes: no request leaves the browser, so nothing to leak.
    if (url.protocol === "data:") return false;
    return url.origin !== origin;
  }

  // Remove blocked sources before DOM insertion; retain the URL for the placeholder.
  window.DOMPurify.addHook("afterSanitizeAttributes", function (node) {
    if (node.tagName !== "IMG") return;
    const src = node.getAttribute("src");
    if (!isBlockedImageSrc(src, window.location.origin)) return;
    node.removeAttribute("src");
    node.setAttribute(BLOCKED_SRC_ATTR, src);
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
   * Sanitizer hooks remove remote image sources. Use renderInto to also add
   * image placeholders, heading IDs, and syntax highlighting in the DOM.
   *
   * @param {string} source
   * @returns {string} Sanitized HTML, safe to assign to innerHTML.
   */
  function render(source) {
    const html = window.marked.parse(source || "");
    return window.DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ALLOWED_TAGS,
      ALLOWED_ATTR: ALLOWED_ATTR,
      // Only the sanitizer hook may supply data-blocked-src; reject author data attributes.
      ALLOW_DATA_ATTR: false,
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
   * Host of a URL, for display. Falls back to the raw value.
   *
   * @param {string} src
   * @returns {string}
   */
  function displayHost(src) {
    try {
      // Use the same base as the policy check, including for protocol-relative URLs.
      return new URL(src, window.location.origin).host || src;
    } catch (error) {
      return src;
    }
  }

  /**
   * Replace src-stripped images with a labelled placeholder.
   *
   * Runs after sanitization. Placeholder labels use textContent so image URLs
   * and alt text remain text when inserted into the live DOM.
   *
   * @param {Element} container
   */
  function blockRemoteImages(container) {
    if (!container) return;
    container.querySelectorAll(BLOCKED_IMAGE_SELECTOR).forEach(function (image) {
      const src = image.getAttribute(BLOCKED_SRC_ATTR) || "";
      const alt = image.getAttribute("alt") || "";

      const placeholder = document.createElement("span");
      placeholder.className = "md-image-blocked";
      placeholder.setAttribute(BLOCKED_SRC_ATTR, src);
      placeholder.title =
        "Images hosted elsewhere are never loaded, so opening this note " +
        "cannot tell anyone that you read it.";

      const label = document.createElement("span");
      label.className = "md-image-blocked__label";
      label.textContent = "Image not shown";
      placeholder.appendChild(label);

      // The alt text is often the only description of what is missing.
      if (alt) {
        const caption = document.createElement("span");
        caption.className = "md-image-blocked__alt";
        caption.textContent = alt;
        placeholder.appendChild(caption);
      }

      const host = document.createElement("span");
      host.className = "md-image-blocked__host";
      host.textContent = displayHost(src);
      placeholder.appendChild(host);

      image.replaceWith(placeholder);
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

  /**
   * Find a descendant by id, scanning rather than using a selector.
   *
   * The id comes from the note's own `#anchor` link, so it is untrusted text
   * and cannot be spliced into a CSS selector without escaping. Comparing
   * `element.id` sidesteps that entirely. Scoping to the container also keeps a
   * note from scrolling to page chrome that happens to share an id.
   *
   * @param {Element} container
   * @param {string} id
   * @returns {?Element} The first match, or null.
   */
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
    blockRemoteImages(el);
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

  // isHighlightLanguageClass, slugifyHeading and isBlockedImageSrc are exposed
  // for DOM-free tests.
  window.NoteMarkdown = {
    render,
    renderInto,
    titleSlug,
    slugifyHeading,
    isHighlightLanguageClass,
    isBlockedImageSrc,
  };
})();
