/**
 * KeyMask Batch Decrypt & Offboarding Modal (Vault De-escalation)
 *
 * Allows a user to decrypt all secrets across all notes back into raw plaintext.
 * Designed for users who wish to uninstall or disable KeyMask without leaving
 * their secrets permanently locked in ciphertext.
 */

import { App, Modal, Setting, Notice, TFile, TFolder } from "obsidian";
import type KeyMaskPlugin from "../main";
import {
  parseInline,
  parseCodeBlock,
  INLINE_SECRET_REGEX,
  CODE_BLOCK_SECRET_REGEX,
} from "../crypto/serializer";
import { UnlockModal } from "./unlockModal";

export class BatchDecryptModal extends Modal {
  private plugin: KeyMaskPlugin;
  private selectedFolder: string = "/";
  private isProcessing: boolean = false;
  private statusEl: HTMLElement | null = null;
  private confirmationInput: string = "";

  constructor(app: App, plugin: KeyMaskPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen(): void {
    this.modalEl.addClass("mod-keymask-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("keymask-modal", "keymask-decrypt-all-modal");

    contentEl.createEl("h2", { text: "🔓 Batch Decrypt & Revert to Plaintext" });

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "This operation will decrypt all KeyMask tokens (%%km:v1:...%%) in your notes back into raw plaintext. Use this if you are planning to disable or remove the KeyMask plugin and want your notes restored to standard unencrypted Markdown.",
    });

    const dangerCard = contentEl.createDiv({ cls: "keymask-corrupted-block" });
    dangerCard.createEl("div", {
      cls: "keymask-corrupted-header",
      text: "⚠️ Plaintext Warning",
    });
    dangerCard.createEl("div", {
      cls: "keymask-corrupted-desc",
      text: "Decrypting all secrets will expose your API keys, credentials, and passwords to note history, cloud sync engines (iCloud, Obsidian Sync, Git), and any third-party plugins. Ensure your environment is secure before proceeding.",
    });

    // Folder Scope
    const folders = this.getVaultFolders();
    new Setting(contentEl)
      .setName("Scope")
      .setDesc("Choose whether to decrypt the entire vault or a specific folder.")
      .addDropdown((dropdown) => {
        dropdown.addOption("/", "Entire Vault (Root)");
        for (const folder of folders) {
          dropdown.addOption(folder.path, folder.path);
        }
        dropdown.setValue(this.selectedFolder);
        dropdown.onChange((val) => {
          this.selectedFolder = val;
        });
      });

    // Confirmation Check
    new Setting(contentEl)
      .setName('Type "DECRYPT" to confirm')
      .setDesc("To prevent accidental unmasking of your entire vault, please type DECRYPT.")
      .addText((text) => {
        text.setPlaceholder("DECRYPT");
        text.onChange((val) => {
          this.confirmationInput = val.trim();
        });
      });

    this.statusEl = contentEl.createDiv({ cls: "keymask-export-status" });
    this.statusEl.style.display = "none";

    const buttonContainer = contentEl.createDiv({ cls: "keymask-modal-buttons" });

    const cancelBtn = buttonContainer.createEl("button", { text: "Cancel" });
    cancelBtn.addEventListener("click", () => this.close());

    const decryptBtn = buttonContainer.createEl("button", {
      cls: "mod-warning",
      text: "🔓 Decrypt All Notes to Plaintext",
    });
    decryptBtn.addEventListener("click", () => this.executeBatchDecryption());
  }

  private getVaultFolders(): TFolder[] {
    const allFiles = this.app.vault.getAllLoadedFiles();
    return allFiles
      .filter((item): item is TFolder => item instanceof TFolder && item.path !== "/")
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  private getTargetMarkdownFiles(): TFile[] {
    const allFiles = this.app.vault.getMarkdownFiles();
    if (this.selectedFolder === "/") {
      return allFiles;
    }
    const prefix = this.selectedFolder.endsWith("/")
      ? this.selectedFolder
      : this.selectedFolder + "/";

    return allFiles.filter(
      (file) => file.path.startsWith(prefix) || file.path === this.selectedFolder
    );
  }

  private async executeBatchDecryption(): Promise<void> {
    if (this.confirmationInput !== "DECRYPT") {
      new Notice('Please type "DECRYPT" in uppercase to confirm.');
      return;
    }

    if (!this.plugin.settings.isInitialized) {
      new Notice("KeyMask is not configured.");
      return;
    }

    if (!this.plugin.session.isUnlocked()) {
      new UnlockModal(this.app, this.plugin, {
        mode: "unlock",
        onSuccess: () => this.executeBatchDecryption(),
      }).open();
      return;
    }

    this.isProcessing = true;
    if (this.statusEl) {
      this.statusEl.style.display = "block";
      this.statusEl.textContent = "Decrypting all tokens in notes...";
    }

    try {
      const files = this.getTargetMarkdownFiles();
      let decryptedTokensCount = 0;
      let modifiedFilesCount = 0;

      for (const file of files) {
        let content = await this.app.vault.read(file);

        interface MatchToReplace {
          from: number;
          to: number;
          rawText: string;
          decryptedText: string;
        }
        const replacements: MatchToReplace[] = [];

        // 1. Find Inline Secrets: %%km:v1:...%%
        INLINE_SECRET_REGEX.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = INLINE_SECRET_REGEX.exec(content)) !== null) {
          const rawToken = match[0];
          const payload = parseInline(rawToken);
          if (payload) {
            try {
              const decrypted = await this.plugin.session.decryptSecret(payload);
              replacements.push({
                from: match.index,
                to: match.index + rawToken.length,
                rawText: rawToken,
                decryptedText: decrypted,
              });
            } catch (e) {
              console.warn(`KeyMask: Failed decrypting token in ${file.path}:`, e);
            }
          }
        }

        // 2. Find Fenced Code Blocks: ```keymask ... ```
        CODE_BLOCK_SECRET_REGEX.lastIndex = 0;
        while ((match = CODE_BLOCK_SECRET_REGEX.exec(content)) !== null) {
          const rawToken = match[0];
          const payload = parseCodeBlock(rawToken);
          if (payload) {
            try {
              const decrypted = await this.plugin.session.decryptSecret(payload);
              replacements.push({
                from: match.index,
                to: match.index + rawToken.length,
                rawText: rawToken,
                decryptedText: decrypted,
              });
            } catch (e) {
              console.warn(`KeyMask: Failed decrypting codeblock in ${file.path}:`, e);
            }
          }
        }

        if (replacements.length === 0) continue;

        // Sort descending by position so replacements do not alter preceding indices
        replacements.sort((a, b) => b.from - a.from);

        for (const item of replacements) {
          content =
            content.slice(0, item.from) +
            item.decryptedText +
            content.slice(item.to);
          decryptedTokensCount++;
        }

        await this.app.vault.modify(file, content);
        modifiedFilesCount++;
      }

      new Notice(
        `🔓 Complete: Decrypted ${decryptedTokensCount} secret${
          decryptedTokensCount > 1 ? "s" : ""
        } across ${modifiedFilesCount} note${modifiedFilesCount > 1 ? "s" : ""} back to plaintext.`
      );
      this.close();
    } catch (err: any) {
      new Notice(`Error during batch decryption: ${err.message}`);
    } finally {
      this.isProcessing = false;
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
