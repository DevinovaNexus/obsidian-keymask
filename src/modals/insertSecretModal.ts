/**
 * KeyMask Secret Ingestion Modal
 *
 * Requirements:
 * - Dedicated native Obsidian modal dialog
 * - Fields: Label (optional), Secret Value (masked password input / textarea)
 * - Format choice: Inline Comment (%%km:v1:...%%) vs Fenced Code Block (```keymask)
 * - Direct Cipher Insertion: Secret is encrypted directly inside modal memory.
 * - Plaintext NEVER touches editor buffer or undo/redo stack.
 */

import { App, Editor, Modal, Setting, Notice } from "obsidian";
import type KeyMaskPlugin from "../main";
import { UnlockModal } from "./unlockModal";

export interface InsertSecretOptions {
  editor: Editor;
  initialSecret?: string;
  initialLabel?: string;
}

export class InsertSecretModal extends Modal {
  private plugin: KeyMaskPlugin;
  private editor: Editor;
  private label = "";
  private secret = "";
  private format: "auto" | "inline" | "codeblock" = "auto";
  private isSecretVisible = false;
  private secretInputEl: HTMLTextAreaElement | null = null;
  private errorEl: HTMLElement | null = null;

  constructor(app: App, plugin: KeyMaskPlugin, options: InsertSecretOptions) {
    super(app);
    this.plugin = plugin;
    this.editor = options.editor;
    this.secret = options.initialSecret || "";
    this.label = options.initialLabel || "";
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("keymask-modal");

    contentEl.createEl("h2", { text: "Insert Encrypted Secret" });

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "The secret is encrypted with AES-256-GCM in memory and inserted as ciphertext. Plaintext never enters your editor buffer, undo history, or disk autosave.",
    });

    this.errorEl = contentEl.createDiv({ cls: "keymask-error-message keymask-hidden" });

    // 1. Label Input
    new Setting(contentEl)
      .setName("Secret Label (Optional)")
      .setDesc("A non-sensitive descriptor shown on the UI pill (e.g. 'Stripe Live Key', 'Production DB').")
      .addText((text) => {
        text.setPlaceholder("e.g. OpenAI Production Key");
        text.setValue(this.label);
        text.onChange((val) => {
          this.label = val;
        });
      });

    // 2. Secret Input Area
    new Setting(contentEl)
      .setName("Secret Value")
      .setDesc("The confidential credential, API key, or certificate.");

    const secretWrapper = contentEl.createDiv({ cls: "keymask-secret-input-wrapper" });

    this.secretInputEl = secretWrapper.createEl("textarea", {
      cls: "keymask-secret-textarea masked",
      attr: {
        placeholder: "Paste or type secret here...",
        rows: "4",
        spellcheck: "false",
      },
    });
    this.secretInputEl.value = this.secret;
    this.secretInputEl.addEventListener("input", () => {
      this.secret = this.secretInputEl?.value || "";
      this.clearError();
    });

    // Toggle Masking / Reveal Button
    const controlsDiv = secretWrapper.createDiv({ cls: "keymask-secret-controls" });
    const toggleRevealBtn = controlsDiv.createEl("button", {
      cls: "clickable-icon keymask-icon-btn",
      attr: { title: "Toggle Visibility" },
      text: "👁️ Show Plaintext",
    });

    toggleRevealBtn.addEventListener("click", () => {
      this.isSecretVisible = !this.isSecretVisible;
      if (this.isSecretVisible) {
        this.secretInputEl?.removeClass("masked");
        toggleRevealBtn.textContent = "🙈 Hide Plaintext";
      } else {
        this.secretInputEl?.addClass("masked");
        toggleRevealBtn.textContent = "👁️ Show Plaintext";
      }
    });

    // 3. Format Selection
    new Setting(contentEl)
      .setName("Storage Format")
      .setDesc("Inline comment for single-line API tokens, or fenced code block for multiline SSH/PEM certificates.")
      .addDropdown((dropdown) => {
        dropdown.addOption("auto", "Auto-Detect (Inline for single line, Code Block for multiline)");
        dropdown.addOption("inline", "Inline Comment (%%km:v1:...%%)");
        dropdown.addOption("codeblock", "Fenced Code Block (```keymask)");
        dropdown.setValue(this.format);
        dropdown.onChange((val: string) => {
          this.format = val as "auto" | "inline" | "codeblock";
        });
      });

    // 4. Modal Buttons
    const buttonContainer = contentEl.createDiv({ cls: "keymask-modal-buttons" });

    const cancelBtn = buttonContainer.createEl("button", { text: "Cancel" });
    cancelBtn.addEventListener("click", () => this.close());

    const insertBtn = buttonContainer.createEl("button", {
      cls: "mod-cta",
      text: "🔒 Encrypt & Insert",
    });
    insertBtn.addEventListener("click", () => this.handleEncryptAndInsert());

    // Focus input
    window.setTimeout(() => {
      this.secretInputEl?.focus();
    }, 50);
  }

  private showError(msg: string): void {
    if (this.errorEl) {
      this.errorEl.textContent = msg;
      this.errorEl.removeClass("keymask-hidden");
    }
  }

  private clearError(): void {
    if (this.errorEl) {
      this.errorEl.textContent = "";
      this.errorEl.addClass("keymask-hidden");
    }
  }

  private async handleEncryptAndInsert(): Promise<void> {
    this.clearError();

    if (!this.secret || this.secret.trim().length === 0) {
      this.showError("Please enter a secret value.");
      return;
    }

    // Check if vault is initialized
    if (!this.plugin.settings.isInitialized) {
      new UnlockModal(this.app, this.plugin, {
        mode: "init",
        onSuccess: () => this.handleEncryptAndInsert(),
      }).open();
      return;
    }

    // Check if vault is unlocked
    if (!this.plugin.session.isUnlocked()) {
      new UnlockModal(this.app, this.plugin, {
        mode: "unlock",
        onSuccess: () => this.handleEncryptAndInsert(),
      }).open();
      return;
    }

    try {
      const isMultiline = this.secret.includes("\n");
      const asCodeBlock =
        this.format === "codeblock" || (this.format === "auto" && isMultiline);

      // Directly encrypt in memory
      const token = await this.plugin.session.encryptSecret(
        this.secret,
        this.label.trim() || undefined,
        asCodeBlock
      );

      // Write token to document
      // If codeblock, ensure surrounded by newlines
      const textToInsert = asCodeBlock ? `\n${token}\n` : token;
      this.editor.replaceSelection(textToInsert);

      new Notice("🔒 Encrypted secret inserted safely.");
      this.close();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.showError(msg || "Failed to encrypt secret.");
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
