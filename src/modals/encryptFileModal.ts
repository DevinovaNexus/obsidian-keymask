/**
 * VaultGuard Whole-File Encryption Modal
 *
 * Prompts user to confirm full-file encryption with an optional custom label.
 * Enterprise-grade typography, alignment, and full-width inputs.
 */

import { App, Modal, Notice, TFile, setIcon } from "obsidian";
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
    this.modalEl.addClass("mod-vaultguard-modal", "vaultguard-encrypt-file-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-modal");

    // Modal Header with SVG Icon
    const headerEl = contentEl.createDiv({ cls: "vaultguard-modal-header" });
    const headerIcon = headerEl.createDiv({ cls: "vaultguard-modal-header-icon" });
    setIcon(headerIcon, "shield-check");
    headerEl.createEl("h2", { text: "Encrypt Entire Note" });

    const lines = this.content.split("\n").length;
    const chars = this.content.length;

    // Structured Target File Details Card
    const targetCard = contentEl.createDiv({ cls: "vaultguard-file-target-card" });

    // Row 1: Target note name + Security algorithm badge
    const targetTop = targetCard.createDiv({ cls: "vaultguard-target-top" });
    const targetTitleGroup = targetTop.createDiv({ cls: "vaultguard-target-title-group" });
    const targetFileIcon = targetTitleGroup.createSpan({ cls: "vaultguard-target-icon" });
    setIcon(targetFileIcon, "file-text");
    targetTitleGroup.createEl("span", {
      cls: "vaultguard-target-filename",
      text: `${this.file.basename}.md`,
    });

    targetTop.createEl("span", {
      cls: "vaultguard-target-algo-pill",
      text: "AES-256-GCM",
    });

    // Row 2: File Stats (Lines, Characters, Folder Path)
    const statsRow = targetCard.createDiv({ cls: "vaultguard-target-stats-row" });
    statsRow.createEl("span", {
      cls: "vaultguard-stat-item",
      text: `📊 ${lines} ${lines === 1 ? "line" : "lines"}`,
    });
    statsRow.createEl("span", { cls: "vaultguard-stat-bullet", text: "•" });
    statsRow.createEl("span", {
      cls: "vaultguard-stat-item",
      text: `🔤 ${chars.toLocaleString()} characters`,
    });
    if (this.file.parent && this.file.parent.path !== "/") {
      statsRow.createEl("span", { cls: "vaultguard-stat-bullet", text: "•" });
      statsRow.createEl("span", {
        cls: "vaultguard-stat-item",
        text: `📁 ${this.file.parent.path}`,
      });
    }

    // Row 3: Security guarantee notice
    const noteNotice = targetCard.createDiv({ cls: "vaultguard-target-notice" });
    noteNotice.createEl("p", {
      text: "The complete contents of this note will be converted into an authenticated ciphertext container. Zero plaintext will remain on disk or in sync history.",
    });

    // Full-Width Security Label Input Field
    const labelGroup = contentEl.createDiv({ cls: "vaultguard-form-field-group" });
    const labelHeader = labelGroup.createDiv({ cls: "vaultguard-field-header" });
    labelHeader.createEl("label", {
      cls: "vaultguard-field-label",
      text: "Note Security Label",
    });
    labelHeader.createEl("span", {
      cls: "vaultguard-field-hint",
      text: "Public title shown while note is locked",
    });

    const labelInput = labelGroup.createEl("input", {
      type: "text",
      cls: "vaultguard-full-input",
      attr: {
        placeholder: "e.g. Confidential Journal, Recovery Keys, Server Runbook",
      },
    });
    labelInput.value = this.label;
    labelInput.addEventListener("input", () => {
      this.label = labelInput.value.trim();
    });

    // Action buttons
    const btnContainer = contentEl.createDiv({ cls: "vaultguard-modal-buttons" });

    const cancelBtn = btnContainer.createEl("button", {
      text: "Cancel",
      cls: "vaultguard-btn-secondary",
    });
    cancelBtn.addEventListener("click", () => this.close());

    const encryptBtn = btnContainer.createEl("button", {
      text: "🔒 Encrypt Entire Note",
      cls: "mod-cta vaultguard-btn-primary-action",
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
