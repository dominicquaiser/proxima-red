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
  // Where a blocked image's URL is parked. Not discarded, so a future opt-in
  // "load images" control has something to restore.
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

  /**
   * Whether an image URL would be refused by the page's `img-src` policy.
   *
   * Mirrors the CSP (`img-src 'self' data:`) exactly, so the placeholder shows
   * up if and only if the browser would have refused the request, no silent
   * broken-image icons left over, and nothing marked "not shown" that would
   * actually have loaded.
   *
   * Blocking is a privacy decision, not just a CSP artifact: there is no image
   * upload, so every remote image is a third-party URL whose owner would learn
   * the reader's IP and the moment they opened the note. Full reasoning in
   * CLAUDE.md and the privacy policy (§3.5).
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

  // Strip the src off images the policy would refuse, and mark them for
  // blockRemoteImages() below. The URL is kept in a data attribute rather than
  // discarded: it is what a future opt-in "load images" control would restore,
  // and it lets the placeholder name the host it would have contacted.
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
   * Images the `img-src` policy would refuse come back already stripped of
   * their `src` (the sanitizer hook does that), so this output makes no
   * third-party requests either. It does not carry the visible placeholder,
   * though: that is a DOM pass. Prefer `renderInto` unless you only need the
   * string.
   *
   * @param {string} source
   * @returns {string} Sanitized HTML, safe to assign to innerHTML.
   */
  function render(source) {
    const html = window.marked.parse(source || "");
    return window.DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ALLOWED_TAGS,
      ALLOWED_ATTR: ALLOWED_ATTR,
      // Nothing in the allowlist needs a data-* attribute, and blockRemoteImages
      // treats data-blocked-src as proof the hook put it there. DOMPurify allows
      // data-* by default; refusing it keeps that assumption true rather than
      // resting on raw HTML never surviving marked's escaping.
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
      // Needs the same base as isBlockedImageSrc, or a protocol-relative URL
      // (which is blocked) has nothing to resolve against and prints raw.
      return new URL(src, window.location.origin).host || src;
    } catch (error) {
      return src;
    }
  }

  /**
   * Replace src-stripped images with a labelled placeholder.
   *
   * Runs after DOMPurify on the live DOM, like `highlightAll`: the placeholder
   * is built with `createElement`/`textContent` and never passes back through
   * the sanitizer, so no markup from the note can reach it. Without this the
   * reader would just get a broken-image icon and a console CSP violation with
   * nothing explaining either.
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
