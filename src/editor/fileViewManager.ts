/**
 * VaultGuard Encrypted File View Manager
 *
 * Manages the top-level presentation of Whole-File Encrypted notes in Obsidian.
 *
 * Automatically detects when an active note is a whole-file encrypted container:
 * 1. Safely hides the raw CodeMirror editor & code blocks to eliminate confusing raw ciphertext.
 * 2. Injects an interactive, full-width security card displaying the Note Title, security badges,
 *    and clear decryption controls (in-memory zero-trace reader, ephemeral clipboard, permanent revert).
 * 3. Reactively updates on tab switching, file modification, and vault lock/unlock events.
 */

import { MarkdownView, TFile } from "obsidian";
import type VaultGuardPlugin from "../main";
import {
  isWholeFileEncrypted,
  extractWholeFilePayload,
  SecretPayload,
} from "../crypto/serializer";
import { createWholeFileCardElement } from "./pillWidget";

export class EncryptedFileViewManager {
  private plugin: VaultGuardPlugin;
  private activeViews = new Map<MarkdownView, { bannerEl: HTMLElement; path: string }>();

  constructor(plugin: VaultGuardPlugin) {
    this.plugin = plugin;
  }

  init(): void {
    // 1. Listen for active leaf switch
    this.plugin.registerEvent(
      this.plugin.app.workspace.on("active-leaf-change", (leaf) => {
        if (leaf && leaf.view instanceof MarkdownView) {
          this.checkAndUpdateView(leaf.view);
        }
      })
    );

    // 2. Listen for file open
    this.plugin.registerEvent(
      this.plugin.app.workspace.on("file-open", (file) => {
        const view = this.plugin.app.workspace.getActiveViewOfType(MarkdownView);
        if (view) {
          this.checkAndUpdateView(view);
        }
      })
    );

    // 3. Listen for layout changes (e.g. splitting tabs, resizing)
    this.plugin.registerEvent(
      this.plugin.app.workspace.on("layout-change", () => {
        this.checkAllOpenViews();
      })
    );

    // 4. Listen for vault file modifications (e.g. encrypted or decrypted)
    this.plugin.registerEvent(
      this.plugin.app.vault.on("modify", (file) => {
        if (file instanceof TFile && file.extension === "md") {
          this.updateViewsForFile(file);
        }
      })
    );

    // 5. Listen for session lock / unlock to update all visible cards
    this.plugin.session.onStateChange(() => {
      this.checkAllOpenViews();
    });

    // Initial check for all open leaves on startup
    this.checkAllOpenViews();
  }

  public checkAllOpenViews(): void {
    this.plugin.app.workspace.iterateAllLeaves((leaf) => {
      if (leaf.view instanceof MarkdownView) {
        this.checkAndUpdateView(leaf.view);
      }
    });
  }

  public async updateViewsForFile(file: TFile): Promise<void> {
    this.plugin.app.workspace.iterateAllLeaves((leaf) => {
      if (leaf.view instanceof MarkdownView && leaf.view.file?.path === file.path) {
        this.checkAndUpdateView(leaf.view);
      }
    });
  }

  public async checkAndUpdateView(view: MarkdownView): Promise<void> {
    const file = view.file;
    if (!file || file.extension !== "md") {
      this.removeBanner(view);
      return;
    }

    try {
      const content = await this.plugin.app.vault.read(file);
      if (!isWholeFileEncrypted(content)) {
        this.removeBanner(view);
        return;
      }

      const payload = extractWholeFilePayload(content);
      if (!payload) {
        this.removeBanner(view);
        return;
      }

      this.renderBanner(view, file, payload, content);
    } catch {
      this.removeBanner(view);
    }
  }

  private renderBanner(
    view: MarkdownView,
    file: TFile,
    payload: SecretPayload,
    content: string
  ): void {
    const existing = this.activeViews.get(view);
    if (existing && existing.path === file.path) {
      // Already rendered for this file; check if element is still in DOM
      if (view.contentEl.contains(existing.bannerEl)) {
        return;
      }
    }

    // Clean up any stale banner
    this.removeBanner(view);

    // Apply active class to hide raw CodeMirror editor & reading view
    view.containerEl.addClass("vaultguard-file-encrypted-active");

    // Create wrapper container
    const bannerEl = document.createElement("div");
    bannerEl.className = "vaultguard-whole-file-banner";

    // Create the interactive security card
    const cardEl = createWholeFileCardElement({
      plugin: this.plugin,
      payload,
      rawText: content,
      isCodeBlock: true,
      sourcePath: file.path,
    });

    bannerEl.appendChild(cardEl);

    // Prepend to view content
    view.contentEl.prepend(bannerEl);
    this.activeViews.set(view, { bannerEl, path: file.path });
  }

  public removeBanner(view: MarkdownView): void {
    view.containerEl.removeClass("vaultguard-file-encrypted-active");

    const record = this.activeViews.get(view);
    if (record) {
      record.bannerEl.remove();
      this.activeViews.delete(view);
    }

    // Safety fallback: remove any orphaned banners from DOM
    const orphan = view.contentEl.querySelector(".vaultguard-whole-file-banner");
    if (orphan) {
      orphan.remove();
    }
  }

  public destroy(): void {
    for (const [view, record] of this.activeViews.entries()) {
      view.containerEl.removeClass("vaultguard-file-encrypted-active");
      record.bannerEl.remove();
    }
    this.activeViews.clear();
  }
}
