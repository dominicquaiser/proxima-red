/**
 * @fileoverview Authenticated vault page: imports the session master key, decrypts
 * and renders the user's saved shares, and drives the create-modal, search/sort/
 * status-filter, and optimistic add/remove with encrypted server persistence.
 *
 * Layout: constants and pure helpers (no DOM, no page state) live at module
 * scope; the DOMContentLoaded closure holds the page state and is organised
 * into modal, rendering, persistence, event-handler, and wiring sections.
 */
(function () {
  "use strict";

  // Fallback endpoint for saving the encrypted vault blob; the page normally
  // carries the URLconf-defined URL in #main-content's data-update-url
  // (cf. data-salts-url in signin.html).
  const SAVE_ENDPOINT = "/update-data/";

  // --- Masked icons (sourced from static/icons/phosphor; tinted via CSS) ---
  // The link/trash icons for a row live in the #share-row-template markup; the
  // copy button swaps to ICON_CHECK and back to ICON_LINK on copy (see
  // handleCopyLinkClick), so those two are still needed here.
  const ICON_LINK =
    '<span class="icon-default"><span class="vicon vicon--link"></span></span>' +
    '<span class="icon-hover"><span class="vicon vicon--link-duotone"></span></span>';
  const ICON_CHECK = '<span class="vicon vicon--check"></span>';
  const ICON_SORT_ASC = '<span class="vicon vicon--caret-double-up"></span>';
  const ICON_SORT_DESC = '<span class="vicon vicon--caret-double-down"></span>';

  // Tile accent palette (gruvbox tokens from main.css).
  const TILE_COLORS = [
    "var(--color-olive-green)",
    "var(--color-amber-gold)",
    "var(--color-steel-blue)",
    "var(--color-plum)",
    "var(--color-seafoam-green)",
    "var(--color-burnt-orange)",
    "var(--color-moss-green)",
    "var(--color-ochre)",
    "var(--color-deep-teal)",
    "var(--color-deep-purple)",
    "var(--color-forest-green)",
    "var(--color-rust-orange)",
    "var(--color-pastel-teal)",
  ];

  // Label restored on the create-modal submit button when it is idle.
  const CREATE_LINK_LABEL = "Create Encrypted Link";

  // Tag constraints. Tags live inside the encrypted vault blob (one normalized,
  // lower-cased string each); these bound their length and per-share count.
  const MAX_TAG_LENGTH = 24;
  const MAX_TAGS_PER_SHARE = 6;

  // --- Pure helpers (no DOM access, no page state) ---

  // Canonical form of a single tag: trimmed, lower-cased, length-capped.
  const normalizeTag = (value) => (value || "").trim().toLowerCase().slice(0, MAX_TAG_LENGTH);

  // Normalize a tag list: canonicalize each, drop empties/duplicates, cap count.
  const normalizeTagList = (tags) => {
    const seen = [];
    (Array.isArray(tags) ? tags : []).forEach((raw) => {
      const tag = normalizeTag(raw);
      if (tag && !seen.includes(tag)) seen.push(tag);
    });
    return seen.slice(0, MAX_TAGS_PER_SHARE);
  };

  const getShareTags = (share) => (Array.isArray(share.tags) ? share.tags : []);

  const formatShortDate = (value) => {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return date.toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  const toTime = (value) => {
    const time = value ? new Date(value).getTime() : NaN;
    return Number.isNaN(time) ? 0 : time;
  };

  const getInitials = (title) => {
    const clean = (title || "").trim();
    if (!clean) return "··";
    const words = clean.split(/\s+/);
    if (words.length >= 2) {
      return (words[0][0] + words[1][0]).toUpperCase();
    }
    return clean.slice(0, 2).toUpperCase();
  };

  const pickTileColor = (key) => {
    let hash = 0;
    for (let i = 0; i < key.length; i += 1) {
      hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
    }
    return TILE_COLORS[hash % TILE_COLORS.length];
  };

  const isShareExpired = (share) => {
    const expiresAt = share.expires_at ? new Date(share.expires_at) : null;
    return expiresAt ? expiresAt < new Date() : false;
  };

  // Ascending comparison of two shares on `key`; the caller applies direction.
  const compareSharesBy = (key, a, b) => {
    switch (key) {
      case "title":
        return (a.title || "Untitled").localeCompare(b.title || "Untitled", undefined, {
          sensitivity: "base",
          numeric: true,
        });
      case "created":
        return toTime(a.created_at) - toTime(b.created_at);
      case "expiry":
        return toTime(a.expires_at) - toTime(b.expires_at);
      case "status":
        // Active (0) sorts before Expired (1) when ascending.
        return (isShareExpired(a) ? 1 : 0) - (isShareExpired(b) ? 1 : 0);
      default:
        return 0;
    }
  };

  document.addEventListener("DOMContentLoaded", () => {
    // --- DOM Elements ---
    const createNewBtn = document.getElementById("create-new-btn");
    const modal = document.getElementById("create-modal");
    const modalClose = document.getElementById("modal-close");
    const inlineForm = document.getElementById("inlinePasswordForm");
    const shareList = document.getElementById("share-list");
    const noSharesPlaceholder = document.getElementById("no-shares-placeholder");
    const searchInput = document.getElementById("share-search");
    const listingCount = document.getElementById("listing-count");
    const userIdBtn = document.getElementById("user-id-btn");
    const statusLinks = document.querySelectorAll(".status-link");
    const tagCloud = document.getElementById("tag-cloud");
    const tagCloudEmpty = document.getElementById("tag-cloud-empty");
    const sortHeaders = document.querySelectorAll(".row-head__cell[data-sort]");
    const countEls = {
      all: document.querySelector('[data-count="all"]'),
      active: document.querySelector('[data-count="active"]'),
      expired: document.querySelector('[data-count="expired"]'),
    };
    const userDataScript = document.getElementById("user-data");
    const rowTemplate = document.getElementById("share-row-template");
    const saveEndpoint =
      document.getElementById("main-content")?.dataset.updateUrl || SAVE_ENDPOINT;

    // --- State ---
    let userShares = [];
    let masterKey = null;
    let isPersisting = false;
    let isCopyingLink = false;
    let searchTerm = "";
    let statusFilter = "all"; // 'all' | 'active' | 'expired'
    let tagFilter = null; // null, or a single tag name to filter the listing by
    let sortKey = null; // 'title' | 'created' | 'status' | 'expiry' | null
    let sortDir = "asc"; // 'asc' | 'desc'
    let shareFormController = null; // set up in setupModalInputs()

    // --- Vault availability + create modal ---

    const disableVault = (message) => {
      if (inlineForm) {
        inlineForm.querySelectorAll("input, button").forEach((el) => {
          el.disabled = true;
        });
      }
      if (createNewBtn) {
        createNewBtn.disabled = true;
      }
      window.Notify.show(message, "error");
    };

    const openModal = () => {
      if (!modal) return;
      modal.classList.remove("hidden");
      const firstField = inlineForm?.querySelector(".title-input");
      firstField?.focus();
    };

    const closeModal = () => {
      if (!modal) return;
      modal.classList.add("hidden");
      shareFormController?.reset();
    };

    const setupModalInputs = () => {
      if (!inlineForm) {
        return;
      }

      shareFormController = window.FormUi.setupShareForm(inlineForm);
    };

    // --- Rendering ---

    const updateSortIndicators = () => {
      sortHeaders.forEach((header) => {
        const isActive = header.dataset.sort === sortKey;
        header.classList.toggle("row-head__cell--active", isActive);
        header.setAttribute(
          "aria-sort",
          isActive ? (sortDir === "asc" ? "ascending" : "descending") : "none",
        );
        const caret = header.querySelector(".sort-caret");
        if (caret) {
          caret.innerHTML = isActive ? (sortDir === "asc" ? ICON_SORT_ASC : ICON_SORT_DESC) : "";
        }
      });
    };

    // Fill a row's ".tags" cell: one colour-coded ".tag" chip (with a remove
    // button) per tag, plus a trailing "+" affordance until the per-share cap is
    // reached. Colours come from the shared deterministic tile palette.
    const renderShareTags = (container, share) => {
      const tags = getShareTags(share);
      container.innerHTML = "";

      tags.forEach((tag) => {
        const chip = document.createElement("span");
        chip.className = "tag";
        chip.style.color = pickTileColor(tag);
        chip.dataset.tag = tag;

        const label = document.createElement("span");
        label.className = "tag__label";
        label.textContent = tag;

        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "tag__remove";
        remove.title = "Remove tag";
        remove.setAttribute("aria-label", `Remove tag ${tag}`);
        remove.textContent = "×";

        chip.append(label, remove);
        container.appendChild(chip);
      });

      if (tags.length < MAX_TAGS_PER_SHARE) {
        const addBtn = document.createElement("button");
        addBtn.type = "button";
        addBtn.className = "tag-add";
        addBtn.title = "Add tag";
        addBtn.setAttribute("aria-label", "Add tag");
        addBtn.textContent = "+";
        container.appendChild(addBtn);
      }
    };

    // Clone the #share-row-template and fill in this share's data. The static
    // structure (cells, icon buttons, masked secret) lives in the template;
    // only the dynamic text/colour and the expired-state tweaks happen here.
    const buildShareRow = (share) => {
      const expiresAt = share.expires_at ? new Date(share.expires_at) : null;
      const isExpired = isShareExpired(share);
      const shareUrl = `${window.location.origin}/${share.id}/#${share.key}`;
      const title = share.title || "Untitled";

      const row = rowTemplate.content.firstElementChild.cloneNode(true);
      row.dataset.shareId = share.id;
      row.dataset.shareUrl = shareUrl;

      const tile = row.querySelector(".tile");
      tile.style.background = pickTileColor(title);
      tile.textContent = getInitials(title);

      const titleEl = row.querySelector(".row__title");
      titleEl.textContent = title;
      titleEl.title = title;
      titleEl.classList.toggle("row__title--expired", isExpired);

      const tagsContainer = row.querySelector(".tags");
      if (tagsContainer) {
        renderShareTags(tagsContainer, share);
      }

      row.querySelector(".row__created").textContent = formatShortDate(share.created_at);

      const badge = row.querySelector(".badge");
      badge.classList.add(isExpired ? "badge--expired" : "badge--active");
      badge.textContent = isExpired ? "Expired" : "Active";

      const expiry = row.querySelector(".row__expiry");
      if (isExpired) {
        expiry.textContent = "Expired";
      } else if (expiresAt) {
        expiry.textContent = `${window.TimeFmt.coarse(expiresAt - new Date())} left`;
      } else {
        expiry.textContent = "No expiry";
      }

      // The copy action only applies to live shares.
      if (isExpired) {
        row.querySelector(".copy-link-btn")?.remove();
      }

      return row;
    };

    const updateCounts = () => {
      let active = 0;
      let expired = 0;
      userShares.forEach((share) => {
        if (isShareExpired(share)) {
          expired += 1;
        } else {
          active += 1;
        }
      });
      if (countEls.all) countEls.all.textContent = userShares.length;
      if (countEls.active) countEls.active.textContent = active;
      if (countEls.expired) countEls.expired.textContent = expired;
    };

    // Unique, sorted set of every tag in use across the vault.
    const collectAllTags = () => {
      const set = new Set();
      userShares.forEach((share) => getShareTags(share).forEach((tag) => set.add(tag)));
      return Array.from(set).sort((a, b) => a.localeCompare(b));
    };

    // Rebuild the sidebar tag cloud from the in-use tag set, highlighting the
    // active filter. `tags` is the result of collectAllTags() (already reconciled
    // against tagFilter by the caller).
    const renderTagCloud = (tags) => {
      if (!tagCloud) return;

      tagCloud.innerHTML = "";
      tags.forEach((tag) => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "chip";
        chip.style.color = pickTileColor(tag);
        chip.dataset.tag = tag;
        chip.textContent = tag;
        if (tag === tagFilter) {
          chip.classList.add("chip--active");
        }
        tagCloud.appendChild(chip);
      });

      if (tagCloudEmpty) {
        tagCloudEmpty.classList.toggle("hidden", tags.length > 0);
      }
    };

    const renderShares = () => {
      if (!shareList) return;

      shareList.innerHTML = "";
      updateCounts();

      // Reconcile a stale tag filter (its tag may have been removed) before it is
      // used for filtering, so the listing and cloud agree within one render.
      const allTags = collectAllTags();
      if (tagFilter && !allTags.includes(tagFilter)) {
        tagFilter = null;
      }

      const term = searchTerm.trim().toLowerCase();
      const visibleShares = userShares.filter((share) => {
        if (statusFilter === "active" && isShareExpired(share)) return false;
        if (statusFilter === "expired" && !isShareExpired(share)) return false;
        if (tagFilter && !getShareTags(share).includes(tagFilter)) return false;
        if (term && !(share.title || "Untitled").toLowerCase().includes(term)) return false;
        return true;
      });

      if (sortKey) {
        visibleShares.sort((a, b) => {
          const result = compareSharesBy(sortKey, a, b);
          return sortDir === "asc" ? result : -result;
        });
      }

      if (!visibleShares.length) {
        if (noSharesPlaceholder) {
          noSharesPlaceholder.classList.remove("hidden");
          const placeholderText = noSharesPlaceholder.querySelector("p");
          if (placeholderText) {
            placeholderText.textContent = userShares.length
              ? "No shares match the current filter."
              : "You haven't shared anything yet.";
          }
        }
      } else {
        if (noSharesPlaceholder) noSharesPlaceholder.classList.add("hidden");
        visibleShares.forEach((share) => {
          shareList.appendChild(buildShareRow(share));
        });
      }

      if (listingCount) {
        const isFiltered = Boolean(term) || statusFilter !== "all" || Boolean(tagFilter);
        listingCount.textContent = isFiltered
          ? `Showing ${visibleShares.length} of ${userShares.length} shares`
          : `Showing ${userShares.length} share${userShares.length === 1 ? "" : "s"}`;
      }

      renderTagCloud(allTags);
    };

    // --- Persistence ---

    const loadSavedShares = async () => {
      if (!masterKey || !userDataScript) {
        renderShares();
        return;
      }

      try {
        const payload = JSON.parse(userDataScript.textContent);
        if (!payload?.encrypted_data || !payload?.iv) {
          renderShares();
          return;
        }

        const decrypted = await window.AuthCrypto.decryptAccountData(
          payload.encrypted_data,
          payload.iv,
          masterKey,
        );

        userShares = Array.isArray(decrypted?.shares) ? decrypted.shares : [];
        userShares.forEach((share) => {
          share.tags = normalizeTagList(share.tags);
        });
      } catch (error) {
        console.error("Failed to decrypt saved vault data:", error);
        userShares = [];
        window.Notify.show(
          "Could not decrypt your saved links. You may need to resave them.",
          "error",
        );
      }

      renderShares();
    };

    const persistUserShares = async () => {
      if (!masterKey) {
        return false;
      }
      if (isPersisting) {
        return true;
      }

      isPersisting = true;

      try {
        const encryptedPayload = await window.AuthCrypto.encryptAccountData(
          { shares: userShares },
          masterKey,
        );

        if (!window.Http.getCsrfToken()) {
          throw new Error("Missing CSRF token");
        }

        const { response, result } = await window.Http.postForm(saveEndpoint, {
          encrypted_data: encryptedPayload.encryptedData,
          iv: encryptedPayload.iv,
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        if (!result.success) {
          throw new Error(result.error || "Unknown error");
        }

        return true;
      } catch (error) {
        console.error("Failed to persist vault data:", error);
        if (error.message === "Missing CSRF token") {
          window.Notify.show(
            "Secure token missing. Please refresh the page and try again.",
            "error",
          );
        } else {
          window.Notify.show("We could not save your vault data. Please try again.", "error");
        }
        return false;
      } finally {
        isPersisting = false;
      }
    };

    // Apply an optimistic change to userShares and persist it, rolling back and
    // re-rendering if the encrypted vault blob fails to save. `mutate` returns the
    // new shares array; resolves to whether the change was persisted.
    const commitShareChange = async (mutate) => {
      const previousShares = userShares;
      userShares = mutate(userShares);
      renderShares();

      const persisted = await persistUserShares();
      if (!persisted) {
        userShares = previousShares;
        renderShares();
      }
      return persisted;
    };

    // --- Event handlers ---

    // Encrypt the secret, create the share server-side, then optimistically add
    // it to the vault (rolling back if the encrypted vault blob fails to persist).
    const handleInlineFormSubmit = async (event) => {
      event.preventDefault();

      if (!masterKey) {
        window.Notify.show("Secure session missing. Please sign in again.", "error");
        return;
      }
      if (!shareFormController) {
        window.Notify.show("Form is incomplete. Please try again.", "error");
        return;
      }

      if (!shareFormController.readPlaintext()) {
        window.Notify.show("Form is incomplete. Please try again.", "error");
        return;
      }

      // The raw title drives the recipient-visible (encrypted) title; the vault's
      // own listing falls back to "Untitled" when none was given.
      const rawTitle = shareFormController.readTitle().trim();
      const titleValue = rawTitle || "Untitled";

      shareFormController.setBusy(true, "Encrypting...");

      try {
        // Encrypt the secret + optional title into the hidden fields, matching the
        // public create page so recipients see the title.
        const key = await shareFormController.encrypt(rawTitle);

        const { response, result } = await window.Http.postForm(inlineForm.action, inlineForm);

        if (!response.ok || !result.success) {
          throw new Error(result.error || `HTTP ${response.status}`);
        }

        const newShare = {
          id: result.share_id,
          title: titleValue,
          key,
          expires_at: result.expires_at,
          created_at: result.created_at,
          tags: [],
        };

        // Optimistically add the share, rolling back if the vault blob won't persist.
        const persisted = await commitShareChange((shares) => [newShare, ...shares]);
        if (!persisted) {
          return;
        }

        shareFormController.reset();
        closeModal();
        window.Notify.show("Secure link created. Copy it from your vault.", "success");
      } catch (error) {
        console.error("Failed to create share from vault:", error);
        window.Notify.show("Unable to create the secure link. Please try again.", "error");
      } finally {
        // Whatever path we took, clear the secrets from the form and restore the
        // submit button to its idle state.
        shareFormController.clearSecrets();
        shareFormController.setBusy(false, CREATE_LINK_LABEL);
      }
    };

    // Copy a row's share URL, with the icon-swap "copied" feedback.
    const handleCopyLinkClick = async (row, copyBtn) => {
      if (isCopyingLink) {
        return;
      }

      if (!window.ClipboardUtil.isSupported()) {
        window.Notify.show("Clipboard is unavailable in this browser.", "error");
        return;
      }

      const shareUrl = row.dataset.shareUrl;
      if (!shareUrl) {
        window.Notify.show("Share URL is missing. Refresh the page and try again.", "error");
        return;
      }

      isCopyingLink = true;
      if (await window.ClipboardUtil.copy(shareUrl)) {
        copyBtn.classList.add("is-copied");
        copyBtn.innerHTML = ICON_CHECK;
        setTimeout(() => {
          copyBtn.classList.remove("is-copied");
          copyBtn.innerHTML = ICON_LINK;
        }, 2000);

        window.Notify.show("Link copied to clipboard.", "success");
      } else {
        window.Notify.show("Clipboard access denied. Please copy manually.", "error");
      }
      isCopyingLink = false;
    };

    // Remove a row from the vault (the underlying share stays live until expiry),
    // rolling back the optimistic removal if the vault blob fails to persist.
    const handleRemoveClick = async (row) => {
      const shareId = row.dataset.shareId;
      const persisted = await commitShareChange((shares) =>
        shares.filter((share) => share.id !== shareId),
      );
      if (!persisted) {
        return;
      }

      window.Notify.show(
        "Link removed from vault. The secure share remains active until it expires.",
        "info",
      );
    };

    // Add a normalized tag to a share, persisting the encrypted vault blob.
    // No-ops (duplicate or over the per-share cap) leave the array untouched.
    const addTagToShare = (shareId, tag) =>
      commitShareChange((shares) =>
        shares.map((share) => {
          if (share.id !== shareId) return share;
          const tags = getShareTags(share);
          if (tags.includes(tag) || tags.length >= MAX_TAGS_PER_SHARE) return share;
          return { ...share, tags: [...tags, tag] };
        }),
      );

    // Remove a tag from a share, persisting the encrypted vault blob.
    const removeTagFromShare = (shareId, tag) =>
      commitShareChange((shares) =>
        shares.map((share) =>
          share.id === shareId
            ? { ...share, tags: getShareTags(share).filter((existing) => existing !== tag) }
            : share,
        ),
      );

    // Swap a row's "+" affordance for an inline text input. Enter commits the
    // normalized tag, Escape or blur cancels; either way the listing re-renders
    // (restoring the "+"). A guard keeps the blur-after-Enter from double-firing.
    const startTagInput = (addBtn, shareId) => {
      const input = document.createElement("input");
      input.type = "text";
      input.className = "tag-input";
      input.maxLength = MAX_TAG_LENGTH;
      input.setAttribute("aria-label", "New tag");

      let settled = false;
      const commit = () => {
        if (settled) return;
        settled = true;
        const tag = normalizeTag(input.value);
        if (tag) {
          addTagToShare(shareId, tag);
        } else {
          renderShares();
        }
      };
      const cancel = () => {
        if (settled) return;
        settled = true;
        renderShares();
      };

      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commit();
        } else if (event.key === "Escape") {
          event.preventDefault();
          cancel();
        }
      });
      input.addEventListener("blur", commit);

      addBtn.replaceWith(input);
      input.focus();
    };

    // Delegated click handler routing row actions to the right handler.
    const handleShareListClick = async (event) => {
      const row = event.target.closest(".row");
      if (!row) return;

      const tagRemoveBtn = event.target.closest(".tag__remove");
      if (tagRemoveBtn) {
        event.preventDefault();
        const tag = tagRemoveBtn.closest(".tag")?.dataset.tag;
        if (tag) {
          await removeTagFromShare(row.dataset.shareId, tag);
        }
        return;
      }

      const tagAddBtn = event.target.closest(".tag-add");
      if (tagAddBtn) {
        event.preventDefault();
        startTagInput(tagAddBtn, row.dataset.shareId);
        return;
      }

      const copyBtn = event.target.closest(".copy-link-btn");
      if (copyBtn) {
        event.preventDefault();
        event.stopPropagation();
        await handleCopyLinkClick(row, copyBtn);
        return;
      }

      const removeBtn = event.target.closest(".remove-btn");
      if (removeBtn) {
        await handleRemoveClick(row);
      }
    };

    // --- Wiring ---

    const bindEvents = () => {
      if (createNewBtn) {
        createNewBtn.addEventListener("click", () => {
          if (!masterKey) {
            window.Notify.show(
              "Unlock your account by signing in again before creating new links.",
              "error",
            );
            return;
          }
          openModal();
        });
      }

      if (modalClose) {
        modalClose.addEventListener("click", closeModal);
      }

      if (modal) {
        // Click on the dimmed backdrop (outside the modal card) closes it.
        modal.addEventListener("click", (event) => {
          if (event.target === modal) {
            closeModal();
          }
        });
      }

      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && modal && !modal.classList.contains("hidden")) {
          closeModal();
        }
      });

      if (searchInput) {
        searchInput.addEventListener("input", (event) => {
          searchTerm = event.target.value || "";
          renderShares();
        });
      }

      // Column headers sort the listing; clicking the active column flips direction.
      sortHeaders.forEach((header) => {
        header.addEventListener("click", () => {
          const key = header.dataset.sort;
          if (sortKey === key) {
            sortDir = sortDir === "asc" ? "desc" : "asc";
          } else {
            sortKey = key;
            sortDir = "asc";
          }
          updateSortIndicators();
          renderShares();
        });
      });

      // Status filters narrow the listing by share status (all / active / expired).
      statusLinks.forEach((link) => {
        link.addEventListener("click", (event) => {
          event.preventDefault();
          statusFilter = link.dataset.status || "all";
          statusLinks.forEach((el) => el.classList.remove("status-link--active"));
          link.classList.add("status-link--active");
          renderShares();
        });
      });

      // Clicking a sidebar tag filters the listing to shares carrying it; the
      // active tag (or any other) toggles/replaces it. Chips are rebuilt on every
      // render, so this is delegated from the container.
      if (tagCloud) {
        tagCloud.addEventListener("click", (event) => {
          const chip = event.target.closest(".chip");
          if (!chip) return;
          const tag = chip.dataset.tag;
          tagFilter = tagFilter === tag ? null : tag;
          renderShares();
        });
      }

      if (userIdBtn) {
        userIdBtn.addEventListener("click", async () => {
          const id = userIdBtn.textContent.trim();
          if (!id) return;
          if (await window.ClipboardUtil.copy(id)) {
            window.Notify.show("User ID copied to clipboard.", "success");
          }
        });
      }

      if (inlineForm) {
        inlineForm.addEventListener("submit", handleInlineFormSubmit);
      }

      if (shareList) {
        shareList.addEventListener("click", handleShareListClick);
      }
    };

    const initialize = async () => {
      if (!window.AuthCrypto) {
        disableVault("Cryptographic module unavailable. Please reload the page.");
        return;
      }

      const storedKeyBase64 = sessionStorage.getItem(window.AuthCrypto.STORAGE_KEYS.masterKey);
      if (!storedKeyBase64) {
        disableVault("Secure session expired. Please sign in again.");
        return;
      }

      try {
        masterKey = await window.AuthCrypto.importKeyFromBase64(storedKeyBase64);
      } catch (error) {
        console.error("Failed to import stored key:", error);
        disableVault("Could not unlock your data. Please sign in again.");
        return;
      }

      setupModalInputs();
      await loadSavedShares();
    };

    bindEvents();
    initialize();
  });
})();
