/**
 * VaultGuard Paste Interceptor Modal
 *
 * Requirements:
 * - Triggers when sensitive token patterns (OpenAI, AWS, Anthropic, GitHub, Private Keys)
 *   are intercepted during an editor paste event.
 * - Options:
 *   1. [ Encrypt & Mask to Note ] (Default)
 *   2. [ Paste Unprotected (Raw) ]
 *   3. [ Cancel ]
 */

import { App, Editor, Modal, Setting, Notice } from "obsidian";
import type VaultGuardPlugin from "../main";
import { DetectedToken, maskForPreview } from "../utils/heuristics";
import { UnlockModal } from "./unlockModal";

export interface InterceptPasteOptions {
  editor: Editor;
  pastedText: string;
  detectedToken: DetectedToken;
}

export class InterceptPasteModal extends Modal {
  private plugin: VaultGuardPlugin;
  private editor: Editor;
  private pastedText: string;
  private detectedToken: DetectedToken;
  private customLabel: string;
  private errorEl: HTMLElement | null = null;

  constructor(app: App, plugin: VaultGuardPlugin, options: InterceptPasteOptions) {
    super(app);
    this.plugin = plugin;
    this.editor = options.editor;
    this.pastedText = options.pastedText;
    this.detectedToken = options.detectedToken;
    this.customLabel = options.detectedToken.suggestedLabel;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-modal", "vaultguard-intercept-modal");

    contentEl.createEl("h2", { text: "⚠️ Sensitive Token Pattern Detected" });

    const banner = contentEl.createDiv({ cls: "vaultguard-intercept-banner" });
    banner.createEl("span", {
      cls: "vaultguard-badge-pattern",
      text: this.detectedToken.patternName,
    });

    const preview = maskForPreview(this.detectedToken.matchedText);
    banner.createEl("code", {
      cls: "vaultguard-preview-code",
      text: preview,
    });

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "You are attempting to paste a confidential credential into your note. Pasting plaintext exposes it to note history, cloud sync engines, and other plugins. VaultGuard can encrypt it immediately with zero plaintext exposure.",
    });

    this.errorEl = contentEl.createDiv({ cls: "vaultguard-error-message" });
    this.errorEl.style.display = "none";

    // Optional Label customization
    new Setting(contentEl)
      .setName("Label for Encrypted Token")
      .setDesc("The display name shown on the masked UI pill.")
      .addText((text) => {
        text.setValue(this.customLabel);
        text.onChange((val) => {
          this.customLabel = val;
        });
      });

    // Action Buttons
    const buttonContainer = contentEl.createDiv({ cls: "vaultguard-modal-buttons" });

    // Cancel Button
    const cancelBtn = buttonContainer.createEl("button", { text: "Cancel" });
    cancelBtn.addEventListener("click", () => this.close());

    // Paste Raw Button
    const pasteRawBtn = buttonContainer.createEl("button", {
      cls: "mod-warning",
      text: "Paste Unprotected (Raw)",
    });
    pasteRawBtn.addEventListener("click", () => {
      this.editor.replaceSelection(this.pastedText);
      new Notice("⚠️ Pasted unprotected secret in plaintext.");
      this.close();
    });

    // Encrypt & Mask Button (Primary)
    const encryptBtn = buttonContainer.createEl("button", {
      cls: "mod-cta",
      text: "🔒 Encrypt & Mask to Note",
    });
    encryptBtn.addEventListener("click", () => this.handleEncrypt());
  }

  private showError(msg: string): void {
    if (this.errorEl) {
      this.errorEl.textContent = msg;
      this.errorEl.style.display = "block";
    }
  }

  private async handleEncrypt(): Promise<void> {
    // If vault is not initialized, open init modal first
    if (!this.plugin.settings.isInitialized) {
      new UnlockModal(this.app, this.plugin, {
        mode: "init",
        onSuccess: () => this.handleEncrypt(),
      }).open();
      return;
    }

    // If vault is locked, unlock first
    if (!this.plugin.session.isUnlocked()) {
      new UnlockModal(this.app, this.plugin, {
        mode: "unlock",
        onSuccess: () => this.handleEncrypt(),
      }).open();
      return;
    }

    try {
      // If the pasted text is entirely the secret or contains it:
      // If the pasted text is just the secret or predominantly the secret:
      const isMultiline = this.detectedToken.matchedText.includes("\n");
      const asCodeBlock = isMultiline;

      // Encrypt the detected token
      const token = await this.plugin.session.encryptSecret(
        this.detectedToken.matchedText,
        this.customLabel.trim() || undefined,
        asCodeBlock
      );

      // If the pasted text had additional surrounding text (e.g. "apiKey: sk-..."),
      // replace just the matched portion in the pasted text!
      let finalTextToInsert: string;
      if (this.pastedText === this.detectedToken.matchedText) {
        finalTextToInsert = asCodeBlock ? `\n${token}\n` : token;
      } else {
        const before = this.pastedText.slice(0, this.detectedToken.startIndex);
        const after = this.pastedText.slice(this.detectedToken.endIndex);
        finalTextToInsert = `${before}${token}${after}`;
      }

      this.editor.replaceSelection(finalTextToInsert);
      new Notice("🔒 Credential encrypted and masked in note.");
      this.close();
    } catch (err: any) {
      this.showError(err.message || "Encryption failed.");
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
