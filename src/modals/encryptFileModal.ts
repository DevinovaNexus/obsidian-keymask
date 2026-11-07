/**
 * VaultGuard Whole-File Encryption Modal
 *
 * Prompts user to confirm full-file encryption with an optional custom label.
 */

import { App, Modal, Setting, Notice, TFile } from "obsidian";
import type VaultGuardPlugin from "../main";

export interface EncryptFileModalOptions {
  file: TFile;
  content: string;
  onSuccess?: () => void;
}

export class EncryptFileModal extends Modal {
  private plugin: VaultGuardPlugin;
  private file: TFile;
  private content: string;
  private label: string;
  private onSuccess?: () => void;

  constructor(app: App, plugin: VaultGuardPlugin, options: EncryptFileModalOptions) {
    super(app);
    this.plugin = plugin;
    this.file = options.file;
    this.content = options.content;
    this.label = options.file.basename;
    this.onSuccess = options.onSuccess;
  }

  onOpen(): void {
    this.modalEl.addClass("mod-vaultguard-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-modal");

    contentEl.createEl("h2", {
      text: "🔒 Encrypt Entire Note",
    });

    const lines = this.content.split("\n").length;
    const chars = this.content.length;

    // Info card describing the operation
    const infoCard = contentEl.createDiv({ cls: "vaultguard-intercept-banner" });
    infoCard.createEl("div", {
      cls: "vaultguard-badge-pattern",
      text: "Authenticated AES-256-GCM",
    });
    infoCard.createEl("p", {
      cls: "setting-item-description",
      text: `Target: "${this.file.basename}" • ${lines} lines • ${chars.toLocaleString()} characters`,
    });
    infoCard.createEl("p", {
      cls: "setting-item-description",
      text: "The entire contents of this note will be encrypted into an authenticated ciphertext container. Zero plaintext will remain at rest or in sync history.",
    });

    // Label setting
    new Setting(contentEl)
      .setName("Note Security Label")
      .setDesc("A public descriptive title displayed while the file is locked.")
      .addText((text) => {
        text.setValue(this.label);
        text.setPlaceholder("e.g. Confidential Journal, Server Runbook");
        text.onChange((val) => {
          this.label = val.trim();
        });
      });

    // Action buttons
    const btnContainer = contentEl.createDiv({ cls: "vaultguard-modal-buttons" });

    const cancelBtn = btnContainer.createEl("button", {
      text: "Cancel",
      cls: "vaultguard-btn-secondary",
    });
    cancelBtn.addEventListener("click", () => this.close());

    const encryptBtn = btnContainer.createEl("button", {
      text: "🔒 Encrypt Entire File",
      cls: "mod-cta",
    });
    encryptBtn.addEventListener("click", async () => {
      await this.executeEncryption();
    });
  }

  private async executeEncryption(): Promise<void> {
    try {
      if (!this.plugin.session.isUnlocked()) {
        new Notice("Vault is locked. Please unlock first.");
        return;
      }

      const label = this.label || this.file.basename;
      const encryptedBlock = await this.plugin.session.encryptSecret(
        this.content,
        label,
        true, // asCodeBlock
        true  // isFile
      );

      await this.app.vault.modify(this.file, encryptedBlock);
      new Notice(`🔒 Note "${this.file.basename}" encrypted with AES-256-GCM.`);
      this.close();

      if (this.onSuccess) {
        this.onSuccess();
      }
    } catch (err: any) {
      new Notice(`Failed to encrypt note: ${err.message}`);
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
