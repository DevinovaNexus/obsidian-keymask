/**
 * VaultGuard Secret Ingestion Modal
 *
 * Requirements:
 * - Dedicated native Obsidian modal dialog
 * - Fields: Label (optional), Secret Value (masked password input / textarea)
 * - Format choice: Inline Comment (%%vg:v1:...%%) vs Fenced Code Block (```vaultguard)
 * - Direct Cipher Insertion: Secret is encrypted directly inside modal memory.
 * - Plaintext NEVER touches editor buffer or undo/redo stack.
 */

import { App, Editor, Modal, Setting, Notice } from "obsidian";
import type VaultGuardPlugin from "../main";
import { UnlockModal } from "./unlockModal";

export interface InsertSecretOptions {
  editor: Editor;
  initialSecret?: string;
  initialLabel?: string;
}

export class InsertSecretModal extends Modal {
  private plugin: VaultGuardPlugin;
  private editor: Editor;
  private label = "";
  private secret = "";
  private format: "auto" | "inline" | "codeblock" = "auto";
  private isSecretVisible = false;
  private secretInputEl: HTMLTextAreaElement | null = null;
  private errorEl: HTMLElement | null = null;

  constructor(app: App, plugin: VaultGuardPlugin, options: InsertSecretOptions) {
    super(app);
    this.plugin = plugin;
    this.editor = options.editor;
    this.secret = options.initialSecret || "";
    this.label = options.initialLabel || "";
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-modal");

    contentEl.createEl("h2", { text: "Insert Encrypted Secret" });

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "The secret is encrypted with AES-256-GCM in memory and inserted as ciphertext. Plaintext never enters your editor buffer, undo history, or disk autosave.",
    });

    this.errorEl = contentEl.createDiv({ cls: "vaultguard-error-message" });
    this.errorEl.style.display = "none";

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
    const secretSetting = new Setting(contentEl)
      .setName("Secret Value")
      .setDesc("The confidential credential, API key, or certificate.");

    const secretWrapper = contentEl.createDiv({ cls: "vaultguard-secret-input-wrapper" });

    this.secretInputEl = secretWrapper.createEl("textarea", {
      cls: "vaultguard-secret-textarea masked",
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
    const controlsDiv = secretWrapper.createDiv({ cls: "vaultguard-secret-controls" });
    const toggleRevealBtn = controlsDiv.createEl("button", {
      cls: "clickable-icon vaultguard-icon-btn",
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
        dropdown.addOption("inline", "Inline Comment (%%vg:v1:...%%)");
        dropdown.addOption("codeblock", "Fenced Code Block (```vaultguard)");
        dropdown.setValue(this.format);
        dropdown.onChange((val: any) => {
          this.format = val;
        });
      });

    // 4. Modal Buttons
    const buttonContainer = contentEl.createDiv({ cls: "vaultguard-modal-buttons" });

    const cancelBtn = buttonContainer.createEl("button", { text: "Cancel" });
    cancelBtn.addEventListener("click", () => this.close());

    const insertBtn = buttonContainer.createEl("button", {
      cls: "mod-cta",
      text: "🔒 Encrypt & Insert",
    });
    insertBtn.addEventListener("click", () => this.handleEncryptAndInsert());

    // Focus input
    setTimeout(() => {
      this.secretInputEl?.focus();
    }, 50);
  }

  private showError(msg: string): void {
    if (this.errorEl) {
      this.errorEl.textContent = msg;
      this.errorEl.style.display = "block";
    }
  }

  private clearError(): void {
    if (this.errorEl) {
      this.errorEl.textContent = "";
      this.errorEl.style.display = "none";
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
    } catch (err: any) {
      this.showError(err.message || "Failed to encrypt secret.");
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
