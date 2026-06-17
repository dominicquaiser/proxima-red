/**
 * @fileoverview Shared form-field UI helpers exposed as window.FormUi:
 * password-visibility toggle, key-mode single/multi-line swap, and share
 * encryption into hidden form fields. Centralised so the auth pages, the
 * create page, and the vault modal don't each reimplement them.
 */
(function () {
  "use strict";

  /**
   * Switch `input` to type=text and install a beforeinput handler that keeps the
   * displayed value as '*' characters while storing the real value in
   * `input._maskedValue`. A fallback `input` listener catches programmatic writes
   * (password managers, autofill) that bypass beforeinput.
   * @param {HTMLInputElement} input
   */
  const setupMaskedInput = (input) => {
    input.type = "text";
    input._maskedValue = "";
    input._isRevealed = false;
    let beforeInputHandled = false;

    input.addEventListener("beforeinput", (e) => {
      if (input._isRevealed) return;
      e.preventDefault();
      beforeInputHandled = true;

      const start = input.selectionStart ?? input._maskedValue.length;
      const end = input.selectionEnd ?? input._maskedValue.length;
      let real = input._maskedValue;
      let cursor = start;

      switch (e.inputType) {
        case "insertText":
        case "insertReplacementText":
          real = real.slice(0, start) + (e.data || "") + real.slice(end);
          cursor = start + (e.data?.length ?? 0);
          break;
        case "insertFromPaste":
        case "insertFromDrop": {
          const pasted = e.dataTransfer?.getData("text/plain") ?? e.data ?? "";
          real = real.slice(0, start) + pasted + real.slice(end);
          cursor = start + pasted.length;
          break;
        }
        case "deleteContentBackward":
          if (start === end && start > 0) {
            real = real.slice(0, start - 1) + real.slice(end);
            cursor = start - 1;
          } else {
            real = real.slice(0, start) + real.slice(end);
            cursor = start;
          }
          break;
        case "deleteContentForward":
          if (start === end) {
            real = real.slice(0, start) + real.slice(end + 1);
          } else {
            real = real.slice(0, start) + real.slice(end);
          }
          cursor = start;
          break;
        case "deleteByCut":
          real = real.slice(0, start) + real.slice(end);
          cursor = start;
          break;
        default:
          return;
      }

      input._maskedValue = real;
      input.value = "*".repeat(real.length);
      try {
        input.setSelectionRange(cursor, cursor);
      } catch {}
    });

    input.addEventListener("input", () => {
      if (beforeInputHandled) {
        beforeInputHandled = false;
        return;
      }
      if (input._isRevealed) {
        input._maskedValue = input.value;
        return;
      }
      // Programmatic write (autofill, password manager) — value is the real text.
      input._maskedValue = input.value;
      const pos = input.selectionStart;
      input.value = "*".repeat(input._maskedValue.length);
      try {
        input.setSelectionRange(pos, pos);
      } catch {}
    });
  };

  /**
   * Read the real value from a masked input (returns input._maskedValue when
   * masking is active, falls back to input.value for plain type=password fields).
   * @param {HTMLInputElement} input
   * @returns {string}
   */
  const getMaskedInputValue = (input) =>
    input._maskedValue !== undefined ? input._maskedValue : input.value;

  /**
   * Wire a ".password-toggle" container so clicking it shows or hides the value
   * in `passwordInput`. Uses * masking (type=text) rather than browser bullets
   * (type=password) so the mask character is consistent. The toggle container
   * holds a checkbox that mirrors the visible/hidden state.
   * @param {HTMLElement|null} toggle
   * @param {HTMLInputElement|null} passwordInput
   */
  const setupPasswordToggle = (toggle, passwordInput) => {
    if (!toggle || !passwordInput) return;

    setupMaskedInput(passwordInput);
    const checkbox = toggle.querySelector('input[type="checkbox"]');

    toggle.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();

      const visible = checkbox ? !checkbox.checked : !passwordInput._isRevealed;
      if (checkbox) checkbox.checked = visible;
      passwordInput._isRevealed = visible;
      passwordInput.value = visible
        ? passwordInput._maskedValue
        : "*".repeat(passwordInput._maskedValue.length);
    });
  };

  /**
   * Find every ".password-toggle" under `root` and wire it to the password input
   * in its ".field" container. Used on the auth pages where toggles are
   * discovered by structure rather than passed explicitly.
   * @param {ParentNode} [scope=document]
   */
  const initPasswordToggles = (scope = document) => {
    scope.querySelectorAll(".password-toggle").forEach((toggleEl) => {
      const container = toggleEl.closest(".field");
      const input = container?.querySelector(".field__input--password");
      setupPasswordToggle(toggleEl, input);
    });
  };

  /**
   * Wire the "key mode" toggle that swaps a single-line password input for a
   * multi-line textarea (for pasting PGP/SSH keys). A <textarea> can't be
   * type=password, so the password toggle is hidden while key mode is active.
   *
   * Returns a small controller because callers read the current mode/value on
   * submit and may need to reset it (e.g. when closing a modal).
   * @param {{toggle: HTMLElement|null, passwordInput: HTMLInputElement|null,
   *          multilineInput: HTMLTextAreaElement|null,
   *          passwordToggle?: HTMLElement|null}} [config]
   * @returns {{active: boolean, value: string, reset: () => void}}
   */
  const setupKeyModeToggle = (config = {}) => {
    const { toggle, passwordInput, multilineInput, passwordToggle } = config;
    let keyMode = false;

    if (toggle && passwordInput && multilineInput) {
      toggle.addEventListener("click", () => {
        keyMode = !keyMode;
        toggle.classList.toggle("is-active", keyMode);
        toggle.textContent = keyMode ? "Sharing a password?" : "Sharing a key?";

        if (keyMode) {
          multilineInput.value = getMaskedInputValue(passwordInput);
          passwordInput.classList.add("hidden");
          passwordToggle?.classList.add("hidden");
          multilineInput.classList.remove("hidden");
          multilineInput.focus();
        } else {
          const val = multilineInput.value;
          if (passwordInput._maskedValue !== undefined) {
            passwordInput._maskedValue = val;
            passwordInput._isRevealed = false;
            passwordInput.value = "*".repeat(val.length);
          } else {
            passwordInput.value = val;
          }
          multilineInput.classList.add("hidden");
          passwordInput.classList.remove("hidden");
          passwordToggle?.classList.remove("hidden");
          passwordInput.focus();
        }
      });
    }

    return {
      get active() {
        return keyMode;
      },
      get value() {
        return keyMode && multilineInput
          ? multilineInput.value
          : getMaskedInputValue(passwordInput) || "";
      },
      // Return to single-line mode without copying values or stealing focus.
      reset() {
        if (!keyMode) return;
        keyMode = false;
        if (toggle) {
          toggle.classList.remove("is-active");
          toggle.textContent = "Sharing a key?";
        }
        if (multilineInput) {
          multilineInput.value = "";
          multilineInput.classList.add("hidden");
        }
        passwordInput?.classList.remove("hidden");
        passwordToggle?.classList.remove("hidden");
      },
    };
  };

  /**
   * Encrypt a secret and an optional title under one key (via
   * PasswordCrypto.encryptShare) and write the resulting ciphertext/IVs into a
   * share form's hidden fields. Shared by the public create page and the vault
   * modal so the field-filling logic lives in one place.
   *
   * The encryption key is intentionally NOT written into the form. It is
   * returned to the caller so it can travel in the URL fragment instead.
   * @param {string} plaintext The secret to encrypt.
   * @param {string} title Optional plaintext title ("" when none).
   * @param {{encryptedData: HTMLInputElement, iv: HTMLInputElement,
   *          encryptedTitle?: HTMLInputElement|null,
   *          titleIv?: HTMLInputElement|null}} fields Target hidden fields.
   * @returns {Promise<string>} The Base64-encoded key.
   */
  const encryptShareIntoFields = async (plaintext, title, fields) => {
    const {
      key,
      password: secret,
      title: encryptedTitle,
    } = await window.PasswordCrypto.encryptShare(plaintext, title);

    fields.encryptedData.value = secret.encryptedData;
    fields.iv.value = secret.iv;
    if (fields.encryptedTitle) {
      fields.encryptedTitle.value = encryptedTitle ? encryptedTitle.encryptedData : "";
    }
    if (fields.titleIv) {
      fields.titleIv.value = encryptedTitle ? encryptedTitle.iv : "";
    }

    return key;
  };

  /**
   * Toggle a submit button between its busy and idle states in one place.
   *
   * Two markup conventions are supported, picked automatically:
   * - Spinner buttons (a ".btn-text" + ".btn-loading" child pair, used on the
   *   auth pages) swap which child is visible.
   * - Plain text buttons swap their label when one is provided.
   *
   * In both cases the button's `disabled` state follows `busy`.
   *
   * @param {HTMLButtonElement|null} button
   * @param {{busy?: boolean, label?: string}} [options]
   */
  const setButtonBusy = (button, { busy = false, label } = {}) => {
    if (!button) return;

    button.disabled = busy;

    const textEl = button.querySelector(".btn-text");
    const loadingEl = button.querySelector(".btn-loading");
    if (textEl && loadingEl) {
      textEl.style.display = busy ? "none" : "inline";
      loadingEl.style.display = busy ? "inline-flex" : "none";
    } else if (label !== undefined) {
      button.textContent = label;
    }
  };

  /**
   * Drive an async form submission with consistent button busy-state and a
   * guaranteed teardown, so the auth pages don't each reimplement the same
   * try/catch/finally around their submit logic.
   *
   * `handler` does the page-specific work (derive secrets, POST, handle the
   * response). On an unexpected throw, `onError` is invoked. The `finally` block
   * always runs `cleanup` (e.g. wiping derived secrets from hidden fields) and
   * then restores the button — unless `keepBusy()` returns true, for a success
   * path that is mid-redirect or has already hidden the form.
   *
   * @param {HTMLButtonElement|null} button
   * @param {() => Promise<void>} handler
   * @param {{busyLabel?: string, onError?: (error: Error) => void,
   *          cleanup?: () => void, keepBusy?: () => boolean}} [options]
   * @returns {Promise<void>}
   */
  const submitWithBusy = async (button, handler, options = {}) => {
    const { busyLabel, onError, cleanup, keepBusy } = options;
    setButtonBusy(button, { busy: true, label: busyLabel });
    try {
      await handler();
    } catch (error) {
      if (onError) onError(error);
    } finally {
      if (cleanup) cleanup();
      if (!keepBusy || !keepBusy()) {
        setButtonBusy(button, { busy: false });
      }
    }
  };

  /**
   * Wire a share form and expose the common create/encrypt/reset operations.
   *
   * The public create page and the vault modal render the same form partial.
   * This controller keeps their DOM lookup, password/key-mode setup, hidden
   * ciphertext field filling, and secret cleanup in one place.
   *
   * @param {HTMLFormElement|null} form
   * @returns {Object|null}
   */
  const setupShareForm = (form) => {
    if (!form) return null;

    const elements = {
      titleInput: form.querySelector(".js-title-input"),
      passwordInput: form.querySelector(".js-password-input"),
      encryptedDataInput: form.querySelector(".js-encrypted-data-input"),
      multilineInput: form.querySelector(".js-multiline-input"),
      keyModeToggle: form.querySelector(".js-key-mode-toggle"),
      passwordToggle: form.querySelector(".js-password-toggle"),
      ivInput: form.querySelector(".js-iv-input"),
      encryptedTitleInput: form.querySelector(".js-encrypted-title-input"),
      titleIvInput: form.querySelector(".js-title-iv-input"),
      submitButton: form.querySelector(".js-share-submit"),
    };

    if (
      !elements.passwordInput ||
      !elements.encryptedDataInput ||
      !elements.ivInput ||
      !elements.encryptedTitleInput ||
      !elements.titleIvInput ||
      !elements.submitButton
    ) {
      console.error("A required share form element could not be found.");
      return null;
    }

    setupPasswordToggle(elements.passwordToggle, elements.passwordInput);

    const keyModeController = setupKeyModeToggle({
      toggle: elements.keyModeToggle,
      passwordInput: elements.passwordInput,
      multilineInput: elements.multilineInput,
      passwordToggle: elements.passwordToggle,
    });

    return {
      elements,
      readPlaintext() {
        return keyModeController.value;
      },
      readTitle() {
        return elements.titleInput?.value || "";
      },
      encrypt(title = this.readTitle()) {
        return encryptShareIntoFields(this.readPlaintext(), title, {
          encryptedData: elements.encryptedDataInput,
          iv: elements.ivInput,
          encryptedTitle: elements.encryptedTitleInput,
          titleIv: elements.titleIvInput,
        });
      },
      clearSecrets() {
        elements.passwordInput.value = "";
        if (elements.passwordInput._maskedValue !== undefined) {
          elements.passwordInput._maskedValue = "";
          elements.passwordInput._isRevealed = false;
        }
        if (elements.multilineInput) elements.multilineInput.value = "";
        elements.encryptedDataInput.value = "";
        elements.ivInput.value = "";
        elements.encryptedTitleInput.value = "";
        elements.titleIvInput.value = "";
      },
      reset() {
        // clearSecrets() handles the masked-input state and every hidden field;
        // form.reset() restores native defaults and keyModeController.reset()
        // returns to single-line mode first.
        form.reset();
        keyModeController.reset();
        this.clearSecrets();
      },
      setBusy(busy, label) {
        setButtonBusy(elements.submitButton, { busy, label });
      },
    };
  };

  /**
   * Offer an (id, password) pair to the browser's password manager via the
   * Credential Management API. Because the masked inputs use type=text, browsers
   * never see a native password field to auto-prompt on, so signin/signup call
   * this explicitly on success instead. Only Chromium implements
   * PasswordCredential; elsewhere this is a silent no-op (masking still works,
   * just without native save-password). Never throws — credential storage is
   * best-effort and must not break the success path.
   * @param {string} id The account identifier (the 8-digit user_id).
   * @param {string} password The account password.
   * @returns {Promise<void>}
   */
  const saveCredential = async (id, password) => {
    if (!id || !password) return;
    if (typeof window.PasswordCredential !== "function" || !navigator.credentials) return;
    try {
      await navigator.credentials.store(new window.PasswordCredential({ id, password }));
    } catch (error) {
      // Best-effort only: a blocked/rejected store must not affect the flow.
      console.debug("Credential store skipped:", error);
    }
  };

  window.FormUi = {
    initPasswordToggles,
    submitWithBusy,
    setupShareForm,
    getMaskedInputValue,
    saveCredential,
  };
})();
