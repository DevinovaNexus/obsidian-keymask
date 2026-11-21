/**
 * KeyMask Unlock & Passphrase Management Modal
 */

import { App, Modal, Setting, Notice } from "obsidian";
import type KeyMaskPlugin from "../main";

export interface UnlockModalOptions {
  mode: "init" | "unlock" | "change";
  onSuccess?: () => void;
  onCancel?: () => void;
}

export class UnlockModal extends Modal {
  private plugin: KeyMaskPlugin;
  private options: UnlockModalOptions;
  private passphrase = "";
  private confirmPassphrase = "";
  private currentPassphrase = "";
  private errorEl: HTMLElement | null = null;
  private submitButton: HTMLButtonElement | null = null;
  private isBusy = false;

  constructor(app: App, plugin: KeyMaskPlugin, options: UnlockModalOptions) {
    super(app);
    this.plugin = plugin;
    this.options = options;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("keymask-modal");

    const modeTitles = {
      init: "Initialize KeyMask Master Passphrase",
      unlock: "Unlock KeyMask",
      change: "Change KeyMask Master Passphrase",
    };

    contentEl.createEl("h2", { text: modeTitles[this.options.mode] });

    const descEl = contentEl.createEl("p", { cls: "setting-item-description" });
    if (this.options.mode === "init") {
      descEl.textContent =
        "Choose a strong master passphrase. Your key will be derived locally using PBKDF2 (600,000 iterations) and AES-256-GCM. The passphrase is never stored on disk.";
    } else if (this.options.mode === "unlock") {
      descEl.textContent =
        "Enter your master passphrase to unlock encrypted secrets for this session.";
    } else {
      descEl.textContent =
        "Enter your current master passphrase, followed by your new master passphrase.";
    }

    this.errorEl = contentEl.createDiv({ cls: "keymask-error-message keymask-hidden" });

    if (this.options.mode === "change") {
      new Setting(contentEl)
        .setName("Current Passphrase")
        .addText((text) => {
          text.inputEl.type = "password";
          text.inputEl.placeholder = "Enter current passphrase";
          text.onChange((val) => {
            this.currentPassphrase = val;
            this.clearError();
          });
        });
    }

    new Setting(contentEl)
      .setName(this.options.mode === "change" ? "New Passphrase" : "Master Passphrase")
      .addText((text) => {
        text.inputEl.type = "password";
        text.inputEl.placeholder = "Enter passphrase";
        text.inputEl.focus();
        text.onChange((val) => {
          this.passphrase = val;
          this.clearError();
        });
        text.inputEl.addEventListener("keydown", (e) => {
          if (e.key === "Enter" && !this.isBusy) {
            void this.handleSubmit();
          }
        });
      });

    if (this.options.mode === "init" || this.options.mode === "change") {
      new Setting(contentEl)
        .setName("Confirm Passphrase")
        .addText((text) => {
          text.inputEl.type = "password";
          text.inputEl.placeholder = "Re-enter passphrase";
          text.onChange((val) => {
            this.confirmPassphrase = val;
            this.clearError();
          });
          text.inputEl.addEventListener("keydown", (e) => {
            if (e.key === "Enter" && !this.isBusy) {
              void this.handleSubmit();
            }
          });
        });
    }

    const buttonContainer = contentEl.createDiv({ cls: "keymask-modal-buttons" });

    const cancelBtn = buttonContainer.createEl("button", { text: "Cancel" });
    cancelBtn.addEventListener("click", () => {
      this.close();
      this.options.onCancel?.();
    });

    const actionText =
      this.options.mode === "init"
        ? "Initialize Vault"
        : this.options.mode === "change"
        ? "Update Passphrase"
        : "Unlock";

    this.submitButton = buttonContainer.createEl("button", {
      cls: "mod-cta",
      text: actionText,
    });
    this.submitButton.addEventListener("click", () => {
      if (!this.isBusy) {
        void this.handleSubmit();
      }
    });
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

  private async handleSubmit(): Promise<void> {
    this.clearError();

    if (this.options.mode === "init") {
      if (!this.passphrase || this.passphrase.length < 6) {
        this.showError("Passphrase must be at least 6 characters.");
        return;
      }
      if (this.passphrase !== this.confirmPassphrase) {
        this.showError("Passphrases do not match.");
        return;
      }
    } else if (this.options.mode === "unlock") {
      if (!this.passphrase) {
        this.showError("Please enter your passphrase.");
        return;
      }
    } else if (this.options.mode === "change") {
      if (!this.currentPassphrase) {
        this.showError("Please enter your current passphrase.");
        return;
      }
      if (!this.passphrase || this.passphrase.length < 6) {
        this.showError("New passphrase must be at least 6 characters.");
        return;
      }
      if (this.passphrase !== this.confirmPassphrase) {
        this.showError("New passphrases do not match.");
        return;
      }
    }

    this.setBusy(true);

    try {
      if (this.options.mode === "init") {
        await this.plugin.session.initializeVault(this.passphrase);
        this.plugin.settings.isInitialized = true;
        await this.plugin.saveSettings();
        new Notice("🔒 KeyMask initialized and unlocked.");
      } else if (this.options.mode === "unlock") {
        await this.plugin.session.unlock(this.passphrase);
        new Notice("🔓 KeyMask unlocked.");
      } else if (this.options.mode === "change") {
        await this.plugin.session.changePassphrase(
          this.currentPassphrase,
          this.passphrase
        );
        await this.plugin.saveSettings();
        new Notice("🔒 Master passphrase updated successfully.");
      }

      this.close();
      this.options.onSuccess?.();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.showError(msg || "Authentication failed. Check your passphrase.");
    } finally {
      this.setBusy(false);
    }
  }

  private setBusy(busy: boolean): void {
    this.isBusy = busy;
    if (this.submitButton) {
      this.submitButton.disabled = busy;
      if (busy) {
        this.submitButton.textContent = "Verifying...";
      } else {
        this.submitButton.textContent =
          this.options.mode === "init"
            ? "Initialize Vault"
            : this.options.mode === "change"
            ? "Update Passphrase"
            : "Unlock";
      }
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
