/**
 * VaultGuard Mobile-Friendly Confirmation Modal
 *
 * Replaces window.confirm() with an Obsidian-native, themed modal dialog.
 * Works seamlessly across Obsidian Mobile (iOS / Android) and Desktop (macOS / Windows / Linux)
 * without being blocked by mobile webview alert restrictions.
 */

import { App, Modal, setIcon } from "obsidian";

export interface ConfirmModalOptions {
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel?: () => void;
}

export class ConfirmModal extends Modal {
  private options: ConfirmModalOptions;

  constructor(app: App, options: ConfirmModalOptions) {
    super(app);
    this.options = options;
  }

  onOpen(): void {
    this.modalEl.addClass("mod-vaultguard-modal", "vaultguard-confirm-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-modal");

    // Header
    const headerEl = contentEl.createDiv({ cls: "vaultguard-modal-header" });
    const headerIcon = headerEl.createDiv({ cls: "vaultguard-modal-header-icon" });
    setIcon(headerIcon, this.options.danger ? "alert-triangle" : "shield-check");
    headerEl.createEl("h2", { text: this.options.title });

    // Message
    const messageEl = contentEl.createDiv({ cls: "vaultguard-confirm-message" });
    messageEl.createEl("p", { text: this.options.message });

    // Buttons
    const btnContainer = contentEl.createDiv({ cls: "vaultguard-modal-buttons" });

    const cancelBtn = btnContainer.createEl("button", {
      text: this.options.cancelText || "Cancel",
      cls: "vaultguard-btn-secondary",
    });
    cancelBtn.addEventListener("click", () => {
      this.close();
      if (this.options.onCancel) {
        this.options.onCancel();
      }
    });

    const confirmBtn = btnContainer.createEl("button", {
      text: this.options.confirmText || "Confirm",
      cls: this.options.danger
        ? "mod-warning vaultguard-btn-danger"
        : "mod-cta vaultguard-btn-primary-action",
    });
    confirmBtn.addEventListener("click", () => {
      this.close();
      this.options.onConfirm();
    });
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

/**
 * Async helper to prompt user for confirmation across desktop and mobile
 */
export function confirmAction(
  app: App,
  options: {
    title: string;
    message: string;
    confirmText?: string;
    cancelText?: string;
    danger?: boolean;
  }
): Promise<boolean> {
  return new Promise((resolve) => {
    new ConfirmModal(app, {
      ...options,
      onConfirm: () => resolve(true),
      onCancel: () => resolve(false),
    }).open();
  });
}
