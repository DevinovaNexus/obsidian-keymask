/**
 * KeyMask UI Masked Pill & Block Widget
 *
 * Implements CodeMirror 6 WidgetType for dynamic interactive masking:
 * - Masked Pill: [ 🔑 <Optional Label> •••••••••••• | 📋 Copy ]
 * - Click-to-Reveal with active SVG countdown progress ring (5s timeout)
 * - Auto-snapback on timeout or editor blur
 * - Ephemeral clipboard transfer with OS volatile exclusion flags
 * - Corrupted Ciphertext Block UI on authentication or integrity failure
 */

import { WidgetType } from "@codemirror/view";
import { Menu, Notice, setIcon, TFile } from "obsidian";
import type KeyMaskPlugin from "../main";
import { SecretPayload } from "../crypto/serializer";
import { UnlockModal } from "../modals/unlockModal";
import { confirmAction } from "../modals/confirmModal";
import { KeyMaskClipboard } from "../utils/clipboard";

export interface PillOptions {
  plugin: KeyMaskPlugin;
  payload: SecretPayload | null;
  rawText: string;
  isCodeBlock?: boolean;
  sourcePath?: string;
}

export class KeyMaskPillWidget extends WidgetType {
  private plugin: KeyMaskPlugin;
  private payload: SecretPayload | null;
  private rawText: string;
  private isCodeBlock: boolean;

  constructor(options: PillOptions) {
    super();
    this.plugin = options.plugin;
    this.payload = options.payload;
    this.rawText = options.rawText;
    this.isCodeBlock = options.isCodeBlock || false;
  }

  eq(other: KeyMaskPillWidget): boolean {
    return (
      other.rawText === this.rawText &&
      other.isCodeBlock === this.isCodeBlock &&
      other.payload?.label === this.payload?.label
    );
  }

  toDOM(): HTMLElement {
    return createPillElement({
      plugin: this.plugin,
      payload: this.payload,
      rawText: this.rawText,
      isCodeBlock: this.isCodeBlock,
    });
  }

  ignoreEvent(event: Event): boolean {
    // Allow interactive clicks & touches on buttons, inputs, and masked text inside widget
    const target = event.target as HTMLElement;
    if (
      target.tagName === "BUTTON" ||
      target.closest("button") ||
      target.classList.contains("keymask-pill-value") ||
      target.classList.contains("keymask-pill-mask") ||
      target.classList.contains("keymask-pill-copy") ||
      target.classList.contains("keymask-pill-reveal") ||
      target.closest(".keymask-pill")
    ) {
      return true;
    }
    return false;
  }
}

/**
 * Creates the interactive DOM element for both CM6 Live Preview widgets
 * and Reading View post-processors.
 */
export function createPillElement(options: PillOptions): HTMLElement {
  const { plugin, payload, rawText, isCodeBlock } = options;

  // Whole-file encrypted note card display
  if (payload && payload.isFilePayload) {
    return createWholeFileCardElement(options);
  }

  const container = document.createElement(isCodeBlock ? "div" : "span");
  container.className = isCodeBlock
    ? "keymask-block-wrapper"
    : "keymask-pill-wrapper";

  // Check for corrupted or invalid payload
  if (!payload) {
    renderCorruptedBlock(container, "Invalid secret syntax or damaged payload", rawText);
    return container;
  }

  const pill = document.createElement("span");
  pill.className = `keymask-pill ${isCodeBlock ? "is-codeblock" : "is-inline"}`;

  // 1. Icon & Status Indicator
  const iconSpan = document.createElement("span");
  iconSpan.className = "keymask-pill-icon";
  updateIcon(iconSpan, plugin.session.isUnlocked());

  // 2. Optional Label
  const labelSpan = document.createElement("span");
  labelSpan.className = "keymask-pill-label";
  labelSpan.textContent = payload.label || (isCodeBlock ? "Encrypted Secret Block" : "Secret");

  // 3. Mask / Value Area
  const valueSpan = document.createElement("span");
  valueSpan.className = "keymask-pill-value masked";
  valueSpan.textContent = isCodeBlock
    ? "••••••••••••••••••••••••••••••••"
    : "••••••••••••";
  valueSpan.title = "Click to reveal secret";

  // 4. Countdown Progress Ring Container (hidden while masked)
  const timerContainer = document.createElement("span");
  timerContainer.className = "keymask-timer-ring-container";
  timerContainer.style.display = "none";

  // 5. Reveal / Toggle Action Button
  const revealBtn = document.createElement("button");
  revealBtn.type = "button";
  revealBtn.className = "keymask-btn keymask-btn-reveal";
  revealBtn.title = "Click to reveal";
  revealBtn.innerHTML = `<span class="km-btn-icon">👁️</span>`;

  // 6. Copy Action Button
  const copyBtn = document.createElement("button");
  copyBtn.type = "button";
  copyBtn.className = "keymask-btn keymask-btn-copy";
  copyBtn.title = "Copy decrypted secret to clipboard (auto-wipes)";
  copyBtn.innerHTML = `<span class="km-btn-icon">📋</span> <span class="km-btn-text">Copy</span>`;

  pill.appendChild(iconSpan);
  pill.appendChild(labelSpan);
  pill.appendChild(valueSpan);
  pill.appendChild(timerContainer);
  pill.appendChild(revealBtn);
  pill.appendChild(copyBtn);
  container.appendChild(pill);

  // State Variables for Interactive Session
  let isRevealed = false;
  let countdownTimer: ReturnType<typeof setInterval> | null = null;
  let secondsRemaining = plugin.settings.revealTimeoutSeconds;

  function updateIcon(el: HTMLElement, unlocked: boolean) {
    el.textContent = unlocked ? "🔑" : "🔒";
    el.title = unlocked ? "Vault Unlocked" : "Vault Locked - Click to unlock";
  }

  // Hide / Re-mask function
  function maskSecret() {
    isRevealed = false;
    if (countdownTimer !== null) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
    valueSpan.textContent = isCodeBlock
      ? "••••••••••••••••••••••••••••••••"
      : "••••••••••••";
    valueSpan.className = "keymask-pill-value masked";
    timerContainer.style.display = "none";
    timerContainer.empty();
    revealBtn.innerHTML = `<span class="km-btn-icon">👁️</span>`;
    revealBtn.title = "Click to reveal";
  }

  // Temporary Unmasking with Countdown Ring
  async function revealSecret() {
    // If vault is locked, unlock first
    if (!plugin.session.isUnlocked()) {
      new UnlockModal(plugin.app, plugin, {
        mode: "unlock",
        onSuccess: () => revealSecret(),
      }).open();
      return;
    }

    try {
      const plaintext = await plugin.session.decryptSecret(payload!);
      isRevealed = true;
      secondsRemaining = plugin.settings.revealTimeoutSeconds;

      valueSpan.textContent = plaintext;
      valueSpan.className = `keymask-pill-value revealed ${isCodeBlock ? "multiline" : ""}`;
      revealBtn.innerHTML = `<span class="km-btn-icon">🙈</span>`;
      revealBtn.title = "Hide secret";

      // Render SVG Countdown Ring
      renderCountdownRing(timerContainer, secondsRemaining, plugin.settings.revealTimeoutSeconds);
      timerContainer.style.display = "inline-flex";

      if (countdownTimer !== null) {
        clearInterval(countdownTimer);
      }

      countdownTimer = setInterval(() => {
        secondsRemaining -= 1;
        if (secondsRemaining <= 0) {
          maskSecret();
        } else {
          renderCountdownRing(timerContainer, secondsRemaining, plugin.settings.revealTimeoutSeconds);
        }
      }, 1000);
    } catch (err: any) {
      renderCorruptedBlock(container, err.message || "Decryption failed", rawText);
    }
  }

  // Toggle reveal on click of value or eye button
  valueSpan.addEventListener("click", (e) => {
    e.stopPropagation();
    if (isRevealed) {
      maskSecret();
    } else {
      revealSecret();
    }
  });

  revealBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (isRevealed) {
      maskSecret();
    } else {
      revealSecret();
    }
  });

  // Handle Copy Button Click
  copyBtn.addEventListener("click", async (e) => {
    e.stopPropagation();

    // If vault is locked, unlock first
    if (!plugin.session.isUnlocked()) {
      new UnlockModal(plugin.app, plugin, {
        mode: "unlock",
        onSuccess: () => copySecret(),
      }).open();
      return;
    }

    await copySecret();
  });

  async function copySecret() {
    try {
      const plaintext = await plugin.session.decryptSecret(payload!);
      await KeyMaskClipboard.writeSecret(plaintext, {
        timeoutSeconds: plugin.settings.clipboardWipeTimeoutSeconds,
      });

      // Visual feedback on copy button
      copyBtn.classList.add("copied");
      copyBtn.innerHTML = `<span class="km-btn-icon">✓</span> <span class="km-btn-text">Copied!</span>`;

      setTimeout(() => {
        copyBtn.classList.remove("copied");
        copyBtn.innerHTML = `<span class="km-btn-icon">📋</span> <span class="km-btn-text">Copy</span>`;
      }, 2000);
      new Notice(`📋 Decrypted secret copied to clipboard (auto-wipes in ${plugin.settings.clipboardWipeTimeoutSeconds}s).`);
    } catch (err: any) {
      renderCorruptedBlock(container, err.message || "Decryption failed on copy", rawText);
    }
  }

  // Right-click context menu on pill to copy decrypted or encrypted secret token
  pill.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    e.stopPropagation();
    const menu = new Menu();

    menu.addItem((item) => {
      item
        .setTitle("Copy Decrypted Password")
        .setIcon("clipboard-check")
        .onClick(async () => {
          if (!plugin.session.isUnlocked()) {
            new UnlockModal(plugin.app, plugin, {
              mode: "unlock",
              onSuccess: () => copySecret(),
            }).open();
            return;
          }
          await copySecret();
        });
    });

    menu.addItem((item) => {
      item
        .setTitle("Copy Encrypted Token (Ciphertext)")
        .setIcon("copy")
        .onClick(async () => {
          await KeyMaskClipboard.writeText(rawText);
          new Notice("📦 Encrypted secret token copied to clipboard.");
        });
    });

    menu.addItem((item) => {
      item
        .setTitle(isRevealed ? "Hide Secret" : "Reveal Secret")
        .setIcon(isRevealed ? "eye-off" : "eye")
        .onClick(() => {
          if (isRevealed) {
            maskSecret();
          } else {
            revealSecret();
          }
        });
    });

    menu.showAtMouseEvent(e);
  });

  // Icon click to lock/unlock
  iconSpan.addEventListener("click", (e) => {
    e.stopPropagation();
    if (!plugin.session.isUnlocked()) {
      new UnlockModal(plugin.app, plugin, {
        mode: "unlock",
        onSuccess: () => updateIcon(iconSpan, true),
      }).open();
    } else {
      plugin.session.lock();
    }
  });

  // Listen to session lock/unlock events to update icon and re-mask if locked
  const unsubscribe = plugin.session.onStateChange((unlocked) => {
    updateIcon(iconSpan, unlocked);
    if (!unlocked && isRevealed) {
      maskSecret();
    }
  });

  // Re-mask on blur
  const onBlurHandler = () => {
    if (isRevealed) {
      maskSecret();
    }
  };
  window.addEventListener("blur", onBlurHandler);

  return container;
}

/**
 * Renders an active SVG circular countdown progress ring
 */
function renderCountdownRing(
  container: HTMLElement,
  current: number,
  total: number
): void {
  container.empty();

  const radius = 9;
  const circumference = 2 * Math.PI * radius;
  const progressRatio = Math.max(0, current / total);
  const strokeDashoffset = circumference * (1 - progressRatio);

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "keymask-progress-ring");
  svg.setAttribute("width", "22");
  svg.setAttribute("height", "22");
  svg.setAttribute("viewBox", "0 0 24 24");

  // Background track circle
  const track = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  track.setAttribute("class", "keymask-progress-track");
  track.setAttribute("cx", "12");
  track.setAttribute("cy", "12");
  track.setAttribute("r", radius.toString());
  track.setAttribute("fill", "none");
  track.setAttribute("stroke-width", "2.5");

  // Animated progress circle
  const progress = document.createElementNS("http://www.w3.org/2000/svg", "circle");
  progress.setAttribute("class", "keymask-progress-indicator");
  progress.setAttribute("cx", "12");
  progress.setAttribute("cy", "12");
  progress.setAttribute("r", radius.toString());
  progress.setAttribute("fill", "none");
  progress.setAttribute("stroke-width", "2.5");
  progress.setAttribute("stroke-dasharray", circumference.toString());
  progress.setAttribute("stroke-dashoffset", strokeDashoffset.toString());
  progress.setAttribute("transform", "rotate(-90 12 12)");

  // Seconds text inside ring
  const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
  text.setAttribute("x", "12");
  text.setAttribute("y", "15.5");
  text.setAttribute("text-anchor", "middle");
  text.setAttribute("class", "keymask-progress-text");
  text.textContent = current.toString();

  svg.appendChild(track);
  svg.appendChild(progress);
  svg.appendChild(text);
  container.appendChild(svg);
}

/**
 * Renders a Corrupted Ciphertext Block UI
 * Crucially does NOT delete or wipe raw string on disk.
 */
export function renderCorruptedBlock(
  container: HTMLElement,
  errorMsg: string,
  rawText: string
): void {
  container.empty();

  const corruptEl = document.createElement("div");
  corruptEl.className = "keymask-corrupted-block";

  const header = corruptEl.createDiv({ cls: "keymask-corrupted-header" });
  header.createEl("span", { cls: "keymask-corrupted-icon", text: "⚠️" });
  header.createEl("span", {
    cls: "keymask-corrupted-title",
    text: "Corrupted Ciphertext Block",
  });

  corruptEl.createEl("div", {
    cls: "keymask-corrupted-desc",
    text: `${errorMsg}. Content may have suffered a merge conflict or key mismatch. Raw ciphertext preserved.`,
  });

  const detailsToggle = corruptEl.createEl("details", {
    cls: "keymask-corrupted-details",
  });
  detailsToggle.createEl("summary", { text: "Inspect Raw Ciphertext" });
  const rawCode = detailsToggle.createEl("pre");
  rawCode.createEl("code", { text: rawText });

  container.appendChild(corruptEl);
}

/**
 * Renders an interactive full-width security card for Whole-File Encrypted notes.
 * Provides in-place revelation, ephemeral copying of decrypted note,
 * direct copying of raw ciphertext, and one-click de-escalation back to plaintext.
 */
export function createWholeFileCardElement(options: PillOptions): HTMLElement {
  const { plugin, payload, rawText } = options;

  const card = document.createElement("div");
  card.className = "keymask-file-card-full";

  // Prevent Live Preview mousedown events from triggering CodeMirror raw code-block editing
  card.addEventListener("mousedown", (e) => {
    e.stopPropagation();
  });

  // Check for corrupted or invalid payload
  if (!payload) {
    renderCorruptedBlock(card, "Invalid whole-file encrypted syntax", rawText);
    return card;
  }

  // 1. Resolve active note file and descriptive title
  let currentFile: TFile | null = null;
  if (options.sourcePath) {
    const file = plugin.app.vault.getAbstractFileByPath(options.sourcePath);
    if (file instanceof TFile) {
      currentFile = file;
    }
  }
  if (!currentFile) {
    const activeFile = plugin.app.workspace.getActiveFile();
    if (activeFile) currentFile = activeFile;
  }

  const fileBasename = currentFile?.basename || options.sourcePath?.split("/").pop()?.replace(/\.md$/, "");
  const noteTitle = payload.label || fileBasename || "Encrypted Note";

  // 2. Top header with Shield Icon, Note Title, and Status Badges
  const header = card.createDiv({ cls: "keymask-file-card-header" });
  const headerLeft = header.createDiv({ cls: "keymask-file-header-left" });
  const shieldIcon = headerLeft.createDiv({ cls: "keymask-shield-icon" });
  setIcon(shieldIcon, "shield-check");

  const titleGroup = headerLeft.createDiv({ cls: "keymask-file-title-group" });
  const titleRow = titleGroup.createDiv({ cls: "keymask-file-title-row" });
  titleRow.createEl("span", {
    cls: "keymask-file-card-title",
    text: noteTitle,
  });

  let subtitleText = "AES-256-GCM Authenticated • Zero Plaintext at Rest";
  if (payload.label && fileBasename && payload.label !== fileBasename) {
    subtitleText = `File: ${fileBasename}.md • ${subtitleText}`;
  }
  titleGroup.createEl("div", {
    cls: "keymask-file-card-subtitle",
    text: subtitleText,
  });

  const headerRight = header.createDiv({ cls: "keymask-file-header-right" });
  headerRight.createEl("span", {
    cls: "keymask-file-type-badge",
    text: "🔒 Encrypted Note",
  });
  const statusBadge = headerRight.createEl("span", {
    cls: "keymask-status-badge",
    text: plugin.session.isUnlocked() ? "🔓 Unlocked" : "🔒 Locked",
  });

  // 3. Action Buttons Toolbar
  const toolbar = card.createDiv({ cls: "keymask-file-card-toolbar" });
  const toolbarLeft = toolbar.createDiv({ cls: "keymask-toolbar-left" });
  const toolbarRight = toolbar.createDiv({ cls: "keymask-toolbar-right" });

  const revealBtn = toolbarLeft.createEl("button", {
    cls: "keymask-btn-action mod-cta",
    text: "🔓 Decrypt & Read Note",
    attr: { title: "Decrypt and display note in secure in-memory reader" },
  });

  const copyDecryptedBtn = toolbarLeft.createEl("button", {
    cls: "keymask-btn-action",
    text: "📋 Copy Decrypted Note",
    attr: { title: "Copy decrypted note to clipboard (ephemeral 30s auto-wipe)" },
  });

  const copyEncryptedBtn = toolbarLeft.createEl("button", {
    cls: "keymask-btn-action",
    text: "📦 Copy Encrypted",
    attr: { title: "Copy raw ciphertext block to clipboard" },
  });

  const revertBtn = toolbarRight.createEl("button", {
    cls: "keymask-btn-revert",
    text: "🔓 Decrypt to Plaintext",
    attr: { title: "Permanently decrypt note back to raw Markdown" },
  });

  // 4. In-Memory Decrypted Note Preview Container
  const previewContainer = card.createDiv({ cls: "keymask-file-preview-container" });
  previewContainer.style.display = "none";

  const previewHeader = previewContainer.createDiv({ cls: "keymask-file-preview-header" });
  const previewHeaderLeft = previewHeader.createDiv({ cls: "keymask-preview-header-left" });
  const previewIcon = previewHeaderLeft.createSpan({ cls: "keymask-preview-icon" });
  setIcon(previewIcon, "file-text");
  previewHeaderLeft.createEl("span", {
    cls: "keymask-preview-title",
    text: `Decrypted Note: ${noteTitle}`,
  });

  const previewActions = previewHeader.createDiv({ cls: "keymask-preview-actions" });
  const timerRingSpan = previewActions.createSpan({ cls: "keymask-timer-ring-container" });
  const hideBtn = previewActions.createEl("button", {
    cls: "keymask-btn-small keymask-btn-hide-preview",
    text: "🙈 Hide Note",
  });

  const previewContent = previewContainer.createEl("pre", {
    cls: "keymask-file-preview-content",
  });

  const previewFooter = previewContainer.createDiv({ cls: "keymask-file-preview-footer" });
  const lockIcon = previewFooter.createSpan({ cls: "keymask-footer-icon" });
  setIcon(lockIcon, "lock");
  previewFooter.createEl("span", {
    text: "In-memory zero-trace preview • Never written to disk • Auto-locks on blur or timeout",
  });

  // 5. Collapsible Raw Ciphertext Inspector (for verification & audits)
  const rawToggle = card.createEl("details", { cls: "keymask-file-inspect-raw" });
  rawToggle.createEl("summary", { text: "Inspect Raw Ciphertext Container" });
  const rawCode = rawToggle.createEl("pre");
  rawCode.createEl("code", { text: rawText });

  let isRevealed = false;
  let countdownTimer: ReturnType<typeof setInterval> | null = null;
  const timeoutSeconds = 60; // 60s preview window for whole file
  let secondsRemaining = timeoutSeconds;

  const maskPreview = () => {
    isRevealed = false;
    if (countdownTimer !== null) {
      clearInterval(countdownTimer);
      countdownTimer = null;
    }
    previewContainer.style.display = "none";
    previewContent.empty();
    timerRingSpan.empty();
    timerRingSpan.style.display = "none";
    revealBtn.textContent = "🔓 Decrypt & Read Note";
    revealBtn.classList.remove("mod-active");
    revealBtn.classList.add("mod-cta");
  };

  const revealNote = async () => {
    if (!plugin.session.isUnlocked()) {
      new UnlockModal(plugin.app, plugin, {
        mode: "unlock",
        onSuccess: () => revealNote(),
      }).open();
      return;
    }

    try {
      const plaintext = await plugin.session.decryptSecret(payload!);
      isRevealed = true;
      secondsRemaining = timeoutSeconds;

      previewContent.textContent = plaintext;
      previewContainer.style.display = "block";
      revealBtn.textContent = "🙈 Hide Note";
      revealBtn.classList.remove("mod-cta");
      revealBtn.classList.add("mod-active");

      renderCountdownRing(timerRingSpan, secondsRemaining, timeoutSeconds);
      timerRingSpan.style.display = "inline-flex";

      if (countdownTimer !== null) clearInterval(countdownTimer);
      countdownTimer = setInterval(() => {
        secondsRemaining -= 1;
        if (secondsRemaining <= 0) {
          maskPreview();
        } else {
          renderCountdownRing(timerRingSpan, secondsRemaining, timeoutSeconds);
        }
      }, 1000);
    } catch (err: any) {
      new Notice(`Decryption failed: ${err.message}`);
    }
  };

  revealBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (isRevealed) {
      maskPreview();
    } else {
      revealNote();
    }
  });

  hideBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    maskPreview();
  });

  copyDecryptedBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    if (!plugin.session.isUnlocked()) {
      new UnlockModal(plugin.app, plugin, {
        mode: "unlock",
        onSuccess: () => copyDecryptedBtn.click(),
      }).open();
      return;
    }

    try {
      const plaintext = await plugin.session.decryptSecret(payload!);
      await KeyMaskClipboard.writeSecret(plaintext, {
        timeoutSeconds: plugin.settings.clipboardWipeTimeoutSeconds,
      });

      copyDecryptedBtn.textContent = "✓ Copied Plaintext!";
      setTimeout(() => {
        copyDecryptedBtn.textContent = "📋 Copy Decrypted Note";
      }, 2000);
      new Notice(`📋 Decrypted note copied (auto-wipes in ${plugin.settings.clipboardWipeTimeoutSeconds}s).`);
    } catch (err: any) {
      new Notice(`Failed to copy decrypted note: ${err.message}`);
    }
  });

  copyEncryptedBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    try {
      await KeyMaskClipboard.writeText(rawText);
      copyEncryptedBtn.textContent = "✓ Copied Ciphertext!";
      setTimeout(() => {
        copyEncryptedBtn.textContent = "📦 Copy Encrypted";
      }, 2000);
      new Notice("📦 Encrypted note ciphertext copied to clipboard.");
    } catch (err: any) {
      new Notice(`Failed to copy ciphertext: ${err.message}`);
    }
  });

  revertBtn.addEventListener("click", async (e) => {
    e.stopPropagation();
    const targetFile = currentFile || plugin.app.workspace.getActiveFile();
    if (!targetFile) {
      new Notice("No active note found to revert.");
      return;
    }

    if (!plugin.session.isUnlocked()) {
      new UnlockModal(plugin.app, plugin, {
        mode: "unlock",
        onSuccess: () => revertBtn.click(),
      }).open();
      return;
    }

    const confirmed = await confirmAction(plugin.app, {
      title: "Decrypt Note to Plaintext",
      message: `Permanently decrypt "${noteTitle}" and restore unencrypted plaintext Markdown?`,
      confirmText: "Decrypt Note",
      danger: true,
    });
    if (!confirmed) {
      return;
    }

    try {
      const plaintext = await plugin.session.decryptSecret(payload!);
      await plugin.app.vault.modify(targetFile, plaintext);
      new Notice(`🔓 Note "${targetFile.basename}" decrypted and restored to plaintext.`);
    } catch (err: any) {
      new Notice(`Failed to decrypt note: ${err.message}`);
    }
  });

  // State changes
  plugin.session.onStateChange((unlocked) => {
    statusBadge.textContent = unlocked ? "🔓 Unlocked" : "🔒 Locked";
    if (!unlocked && isRevealed) {
      maskPreview();
    }
  });

  return card;
}
