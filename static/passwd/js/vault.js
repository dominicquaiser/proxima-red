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

  // Fallback endpoint for reading the encrypted vault blob; the page normally
  // carries the URLconf-defined URL in #main-content's data-vault-data-url. The
  // blob is fetched after the vault key is established (not embedded in the page
  // HTML), so a logged-in-but-locked tab never receives ciphertext.
  const VAULT_DATA_ENDPOINT = "/vault-data/";

  // Fallback endpoint for saving the encrypted vault blob; the page normally
  // carries the URLconf-defined URL in #main-content's data-update-url
  // (cf. data-salts-url in signin.html).
  const SAVE_ENDPOINT = "/update-data/";

  // Fallback endpoint for revoking a share server-side; the page normally
  // carries the URLconf-defined URL in #main-content's data-delete-url.
  const DELETE_ENDPOINT = "/delete-share/";

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

  // Shown when a change is attempted before the stored links have loaded.
  const VAULT_LOADING_MESSAGE = "Your saved links are still loading. Try again in a moment.";
  const VAULT_SAVE_UNCONFIRMED_MESSAGE =
    "Could not confirm the vault save. Reload your vault to finish saving.";
  const VAULT_CHANGED_MESSAGE = "Your saved links changed. Reload your vault and try again.";
  const PENDING_SAVE_KEY = "passwdVaultPendingSave";
  // Shown when a change is attempted while the stored list can't be decrypted.
  const VAULT_UNREADABLE_MESSAGE =
    "Your saved links can't be decrypted. Start a new list to keep using the vault.";

  // Reset control for a stored list that can't be decrypted. Like row removal,
  // it needs a second click within the window.
  const RESET_VAULT_LABEL = "Start a new list";
  const RESET_VAULT_CONFIRM_LABEL = "Click again to erase the old list";
  const RESET_VAULT_CONFIRM_MS = 3000;

  // These responses reject the request before the vault is written, so the
  // save failed and there is nothing to read back.
  const VAULT_SAVE_REJECTION_STATUSES = new Set([400, 401, 403, 404, 409, 413, 423, 429]);

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

  const isStoredTimestamp = (value) =>
    value == null || typeof value === "string" || typeof value === "number";

  // Whether a decrypted vault entry has the shape this page shows and saves.
  const isUsableShare = (entry) =>
    typeof entry?.id === "string" &&
    typeof entry.key === "string" &&
    (entry.title == null || typeof entry.title === "string") &&
    isStoredTimestamp(entry.created_at) &&
    isStoredTimestamp(entry.expires_at);

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
    const rowTemplate = document.getElementById("share-row-template");
    const unreadablePanel = document.getElementById("vault-unreadable");
    const resetVaultBtn = document.getElementById("reset-vault-btn");
    const mainContent = document.getElementById("main-content");
    const vaultDataEndpoint = mainContent?.dataset.vaultDataUrl || VAULT_DATA_ENDPOINT;
    const saveEndpoint = mainContent?.dataset.updateUrl || SAVE_ENDPOINT;
    const deleteEndpoint = mainContent?.dataset.deleteUrl || DELETE_ENDPOINT;

    // --- State ---
    // The shown share list. While the vault is loaded only `saves` (see
    // Persistence) assigns it, so what is on screen is what gets saved.
    let userShares = [];
    let masterKey = null;
    let vaultSession = null;
    let vaultRevision = "";
    let saveInFlight = null;
    let writeBlockMessage = "";
    let unconfirmedSaveIds = null;
    // The loaded revision doesn't decrypt under this key. The reset control
    // can replace that revision only.
    let vaultUnreadable = false;
    let resetArmTimer = null;
    // Decrypted entries this page can't show, for example ones written by a
    // newer version. Every save writes them back unchanged.
    let keptEntries = [];
    let isCopyingLink = false;
    let armedRemoveBtn = null;
    let armedRemoveTimer = null;
    let searchTerm = "";
    let statusFilter = "all"; // 'all' | 'active' | 'expired'
    let tagFilter = null; // null, or a single tag name to filter the listing by
    let sortKey = null; // 'title' | 'created' | 'status' | 'expiry' | null
    let sortDir = "asc"; // 'asc' | 'desc'
    let shareFormController = null; // set up in setupModalInputs()

    // --- Vault availability + create modal ---

    const disableVault = (message) => {
      writeBlockMessage = message;
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

    // Return the reset button to its first-click state.
    const disarmResetBtn = () => {
      clearTimeout(resetArmTimer);
      resetArmTimer = null;
      if (!resetVaultBtn) return;
      resetVaultBtn.textContent = RESET_VAULT_LABEL;
      resetVaultBtn.classList.remove("vault-unreadable__reset--armed");
    };

    const armResetBtn = () => {
      resetVaultBtn.textContent = RESET_VAULT_CONFIRM_LABEL;
      resetVaultBtn.classList.add("vault-unreadable__reset--armed");
      resetArmTimer = setTimeout(disarmResetBtn, RESET_VAULT_CONFIRM_MS);
    };

    // Show or hide the notice that takes the listing's place while the stored
    // list can't be decrypted.
    const setVaultUnreadable = (unreadable) => {
      vaultUnreadable = unreadable;
      unreadablePanel?.classList.toggle("hidden", !unreadable);
      disarmResetBtn();
      renderShares();
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
          // "Nothing shared yet" would contradict the unreadable-list notice.
          noSharesPlaceholder.classList.toggle("hidden", vaultUnreadable);
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

    const hasCiphertext = (blob) =>
      typeof blob?.encrypted_data === "string" && typeof blob.iv === "string";

    const sameCiphertext = (stored, payload) =>
      stored?.encrypted_data === payload.encrypted_data && stored.iv === payload.iv;

    const sessionUnavailable = ({ response: { status }, result }) =>
      status === 401 || status === 423 || result.code === "vault_identity_changed";

    const fetchStoredVault = async () => {
      const reply = await window.Http.getJson(vaultDataEndpoint);
      if (sessionUnavailable(reply)) return null;
      const { response, result } = reply;
      if (!response.ok || response.redirected || result.success !== true) {
        throw new Error(result.error || `HTTP ${response.status}`);
      }
      const { revision, encrypted_data, iv } = result;
      if (revision === "" && encrypted_data === undefined && iv === undefined) return result;
      if (typeof revision === "string" && revision && hasCiphertext(result)) return result;
      throw new Error("Invalid saved link response.");
    };

    const postVaultSave = async (payload) => {
      try {
        return await window.Http.postForm(saveEndpoint, payload);
      } catch (error) {
        console.error("Could not read the vault save response:", error);
        return null;
      }
    };

    const acceptedRevision = (reply) => {
      if (reply?.response.ok && !reply.response.redirected && reply.result.success === true) {
        return typeof reply.result.revision === "string" ? reply.result.revision : "";
      }
      return "";
    };

    // Keep the exact encrypted payload across a reload, scoped to the account
    // and key that encrypted it. Revision checks still protect storage if the
    // browser denies access to sessionStorage.
    const rememberPendingSave = (payload) => {
      const identity = vaultSession.identity;
      if (!identity) return;
      try {
        if (payload) {
          sessionStorage.setItem(PENDING_SAVE_KEY, JSON.stringify({ identity, payload }));
        } else {
          sessionStorage.removeItem(PENDING_SAVE_KEY);
        }
      } catch (error) {
        console.error("Could not keep the pending vault save across reload:", error);
      }
    };

    const readPendingSave = () => {
      const identity = vaultSession.identity;
      if (!identity) return null;
      try {
        const saved = JSON.parse(sessionStorage.getItem(PENDING_SAVE_KEY));
        if (
          saved?.identity === identity &&
          hasCiphertext(saved.payload) &&
          typeof saved.payload.expected_revision === "string"
        ) {
          return saved.payload;
        }
        if (saved) rememberPendingSave(null);
      } catch (error) {
        console.error("Could not read the pending vault save:", error);
      }
      return null;
    };

    // A fetched revision equal to the original base leaves the first request
    // free to commit. Replaying its ciphertext settles the race: the server
    // accepts either copy and acknowledges an exact retry without rewriting.
    const recoverPendingSave = async (stored, loadKey) => {
      const pending = readPendingSave();
      if (!pending) return stored;
      if (stored.revision === pending.expected_revision) {
        const reply = await postVaultSave(pending);
        if (loadKey !== masterKey || (reply && sessionUnavailable(reply))) return null;
        const revision = acceptedRevision(reply);
        if (revision) {
          stored = { ...pending, revision };
        } else {
          stored = await fetchStoredVault();
          if (!stored || loadKey !== masterKey) return null;
          const invalid =
            reply && !reply.response.redirected && [400, 413].includes(reply.response.status);
          if (stored.revision === pending.expected_revision && !invalid) {
            disableVault(VAULT_SAVE_UNCONFIRMED_MESSAGE);
            return null;
          }
        }
      }
      rememberPendingSave(null);
      if (!sameCiphertext(stored, pending)) {
        window.Notify.show("Review your saved links before retrying the interrupted save.", "info");
      }
      return stored;
    };

    // Load a confirmed revision before handing the decrypted list to the queue.
    const loadSavedShares = async () => {
      const loadKey = masterKey;
      await saveInFlight;
      if (!loadKey || loadKey !== masterKey || writeBlockMessage) return;

      let blob;
      try {
        const stored = await fetchStoredVault();
        if (!stored || loadKey !== masterKey) return;
        blob = await recoverPendingSave(stored, loadKey);
        if (!blob || loadKey !== masterKey) return;
      } catch (error) {
        if (loadKey !== masterKey) return;
        console.error("Failed to load saved vault data:", error);
        disableVault("Could not load your saved links. Please reload the page.");
        return;
      }

      vaultRevision = blob.revision;
      let storedEntries = [];
      if (hasCiphertext(blob)) {
        try {
          const decrypted = await window.AuthCrypto.decryptAccountData(
            blob.encrypted_data,
            blob.iv,
            loadKey,
          );
          if (!Array.isArray(decrypted?.shares)) throw new Error("Invalid saved link list.");
          storedEntries = decrypted.shares;
        } catch (error) {
          if (loadKey !== masterKey) return;
          console.error("Failed to decrypt saved vault data:", error);
          setVaultUnreadable(true);
          return;
        }
        if (loadKey !== masterKey) return;
      }

      // One odd entry shouldn't cost the rest of the list, and dropping it on
      // the next save would destroy data this version doesn't understand.
      const shares = [];
      keptEntries = [];
      storedEntries.forEach((entry) => {
        if (isUsableShare(entry)) shares.push({ ...entry, tags: normalizeTagList(entry.tags) });
        else keptEntries.push(entry);
      });
      if (keptEntries.length) {
        window.Notify.show(
          "Some saved links could not be read and are hidden. They stay stored unchanged.",
          "error",
        );
      }
      saves.load(shares);
    };

    // Encrypt and save one whole share list. Only `saves` calls this, one save
    // at a time; it reports failures itself and resolves to whether the server
    // stored the list. When a lost reply leaves that unknown, it pauses writes
    // until a reload instead of guessing.
    const persistUserShares = async (shares) => {
      const saveKey = masterKey;
      const expectedRevision = vaultRevision;
      if (!saveKey || writeBlockMessage) return false;

      try {
        const encryptedPayload = await window.AuthCrypto.encryptAccountData(
          { shares: [...shares, ...keptEntries] },
          saveKey,
        );
        if (saveKey !== masterKey) return false;

        if (!window.Http.getCsrfToken()) {
          throw new Error("Missing CSRF token");
        }

        const payload = {
          encrypted_data: encryptedPayload.encryptedData,
          iv: encryptedPayload.iv,
          expected_revision: expectedRevision,
        };
        rememberPendingSave(payload);
        const reply = await postVaultSave(payload);

        let revision = acceptedRevision(reply);
        if (!revision) {
          if (
            reply &&
            !reply.response.redirected &&
            VAULT_SAVE_REJECTION_STATUSES.has(reply.response.status)
          ) {
            rememberPendingSave(null);
            if (reply.result.code === "vault_data_changed") {
              disableVault(VAULT_CHANGED_MESSAGE);
              return false;
            }
            throw new Error(reply.result.error || `HTTP ${reply.response.status}`);
          }

          // Other ciphertext on a read-back can't settle a lost reply. The
          // write may still be running, or a later revision may include it.
          if (saveKey === masterKey) {
            const stored = await fetchStoredVault().catch((error) => {
              console.error("Failed to check the stored vault after a save:", error);
              return null;
            });
            if (sameCiphertext(stored, payload)) revision = stored.revision;
          }
        }

        if (revision) {
          rememberPendingSave(null);
          if (saveKey === masterKey) vaultRevision = revision;
          return true;
        }
        unconfirmedSaveIds = new Set(shares.map((share) => share.id));
        disableVault(VAULT_SAVE_UNCONFIRMED_MESSAGE);
        return false;
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
      }
    };

    // Every save replaces the whole encrypted list, so saves go through one
    // queue (static/shared/js/save-queue.js): one at a time, a change made
    // during a save is sent right after it, and a failed save restores the
    // last list the server accepted. The lock clears it via saves.reset().
    const saves = window.SaveQueue.create({
      persist: (shares) => {
        saveInFlight = persistUserShares(shares);
        return saveInFlight.finally(() => {
          saveInFlight = null;
        });
      },
      show: (shares) => {
        userShares = shares;
        renderShares();
      },
    });

    // Show a change at once and save it. `mutate` returns the new shares array
    // and must leave its input unchanged; resolves to whether the server
    // accepted a vault that includes the change (false also before the vault
    // has loaded, which callers check up front where it matters).
    const commitShareChange = (mutate) =>
      writeBlockMessage ? Promise.resolve(false) : saves.commit(mutate);

    const canChangeShares = () => {
      if (writeBlockMessage) {
        window.Notify.show(writeBlockMessage, "error");
        return false;
      }
      if (vaultUnreadable) {
        window.Notify.show(VAULT_UNREADABLE_MESSAGE, "error");
        return false;
      }
      if (!saves.ready) {
        window.Notify.show(VAULT_LOADING_MESSAGE, "info");
        return false;
      }
      return true;
    };

    // Replace a stored list that can't be decrypted with an empty one. Without
    // its key nobody can read the old list, but it may still be the only copy
    // of those links, so this runs only on a confirmed request. The links
    // themselves stay live until they expire either way.
    const resetUnreadableVault = async () => {
      const resetKey = masterKey;
      resetVaultBtn.disabled = true;
      try {
        // Through the queue like every save: the empty list becomes the
        // restore point, then is saved over the unreadable one.
        keptEntries = [];
        saves.load([]);
        const replaced = await saves.commit((shares) => shares);
        if (resetKey !== masterKey) return;
        if (!replaced) {
          saves.reset();
          return;
        }
        setVaultUnreadable(false);
        window.Notify.show("Started a new, empty list of saved links.", "success");
      } finally {
        resetVaultBtn.disabled = Boolean(writeBlockMessage);
      }
    };

    // First click arms the reset, a second click within the window runs it.
    const handleResetClick = async () => {
      if (!vaultUnreadable || !masterKey) return;
      if (writeBlockMessage) {
        window.Notify.show(writeBlockMessage, "error");
        return;
      }
      if (resetArmTimer === null) {
        armResetBtn();
        return;
      }
      disarmResetBtn();
      await resetUnreadableVault();
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
      if (!canChangeShares()) return;
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
          // Clean up the share only when its vault entry could not have committed.
          if (!unconfirmedSaveIds?.has(newShare.id) && !(await revokeShare(newShare.id))) {
            console.error("Could not revoke a share that was not saved to the vault:", newShare.id);
          }
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
        copyBtn.innerHTML = ICON_CHECK;
        setTimeout(() => {
          copyBtn.innerHTML = ICON_LINK;
        }, 2000);

        window.Notify.show("Link copied to clipboard.", "success");
      } else {
        window.Notify.show("Clipboard access denied. Please copy manually.", "error");
      }
      isCopyingLink = false;
    };

    const revokeShare = async (shareId) => {
      try {
        const { response, result } = await window.Http.postForm(deleteEndpoint, {
          share_id: shareId,
        });
        return response.ok && result.success;
      } catch (error) {
        console.error("Failed to revoke share:", error);
        return false;
      }
    };

    // Restore an armed remove button to its idle (non-confirming) appearance and
    // clear the pending disarm timer.
    const disarmRemoveBtn = () => {
      if (armedRemoveTimer) {
        clearTimeout(armedRemoveTimer);
        armedRemoveTimer = null;
      }
      if (armedRemoveBtn) {
        armedRemoveBtn.classList.remove("remove-btn--confirm");
        armedRemoveBtn.title = "Remove from vault";
        armedRemoveBtn = null;
      }
    };

    // First click arms the button (turns the trash icon red) and waits for a
    // confirming second click; inaction disarms it after a short window.
    const armRemoveBtn = (removeBtn) => {
      disarmRemoveBtn();
      armedRemoveBtn = removeBtn;
      removeBtn.classList.add("remove-btn--confirm");
      removeBtn.title = "Click again to delete";
      armedRemoveTimer = setTimeout(disarmRemoveBtn, 3000);
    };

    const handleRemoveClick = async (row, removeBtn) => {
      // Require a confirming second click before the destructive delete.
      if (armedRemoveBtn !== removeBtn) {
        armRemoveBtn(removeBtn);
        return;
      }

      disarmRemoveBtn();
      const shareId = row.dataset.shareId;

      if (!(await revokeShare(shareId))) {
        window.Notify.show("We could not revoke the secure share. Please try again.", "error");
        return;
      }

      const persisted = await commitShareChange((shares) =>
        shares.filter((share) => share.id !== shareId),
      );
      if (!persisted) {
        return;
      }

      window.Notify.show("Link removed and the secure share has been revoked.", "info");
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

      // Any click that isn't a confirming click on the armed remove button
      // cancels the pending two-click delete.
      const clickedRemoveBtn = event.target.closest(".remove-btn");
      if (armedRemoveBtn && clickedRemoveBtn !== armedRemoveBtn) {
        disarmRemoveBtn();
      }

      const copyBtn = event.target.closest(".copy-link-btn");
      if (copyBtn) {
        event.preventDefault();
        event.stopPropagation();
        await handleCopyLinkClick(row, copyBtn);
        return;
      }

      const tagRemoveBtn = event.target.closest(".tag__remove");
      const tagAddBtn = event.target.closest(".tag-add");
      if (!(tagRemoveBtn || tagAddBtn || clickedRemoveBtn) || !canChangeShares()) return;

      if (tagRemoveBtn) {
        event.preventDefault();
        const tag = tagRemoveBtn.closest(".tag")?.dataset.tag;
        if (tag) {
          await removeTagFromShare(row.dataset.shareId, tag);
        }
        return;
      }

      if (tagAddBtn) {
        event.preventDefault();
        startTagInput(tagAddBtn, row.dataset.shareId);
        return;
      }

      if (clickedRemoveBtn) {
        await handleRemoveClick(row, clickedRemoveBtn);
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
          if (!canChangeShares()) return;
          openModal();
        });
      }

      // A change on screen is only stored once its save has finished.
      window.addEventListener("beforeunload", (event) => {
        if (!saves.busy) return;
        event.preventDefault();
        event.returnValue = "";
      });

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

      if (resetVaultBtn) {
        resetVaultBtn.addEventListener("click", handleResetClick);
      }
    };

    const initialize = async () => {
      if (!window.AuthCrypto) {
        disableVault("Cryptographic module unavailable. Please reload the page.");
        return;
      }

      vaultSession = window.VaultSession.create({
        tool: "pass",
        userId: document.getElementById("unlock-modal").dataset.userId,
        onLock: () => {
          // Drops changes not yet sent, and keeps a save still running from
          // restoring anything: the decrypted list must not come back while
          // locked. Unlocking loads it afresh.
          saves.reset();
          document.getElementById("main-content").inert = true;
          masterKey = null;
          userShares = [];
          keptEntries = [];
          closeModal();
          // Unlocking decides afresh whether the stored list decrypts. This
          // also re-renders the now-empty listing.
          setVaultUnreadable(false);
        },
        onUnlock: async (key) => {
          masterKey = await window.AuthCrypto.importKeyFromBase64(key);
          document.getElementById("main-content").inert = false;
          await loadSavedShares();
        },
        onSignedOut: () => {
          window.location.href = "/auth/signin/?tool=pass";
        },
        onIdentityChange: () => {
          window.location.reload();
        },
      });
      let storedKeyBase64;
      try {
        storedKeyBase64 = await vaultSession.start();
      } catch {
        disableVault("Unable to check your session. Check your connection and reload.");
        return;
      }
      if (!storedKeyBase64) {
        disableVault("This tab is locked. Reload the page to unlock your vault.");
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
