/**
 * VaultGuard KeePass / MacPass Export Modal
 *
 * Scans vault notes for encrypted secrets, decrypts them in memory using
 * the master key, and exports them to industry-standard formats:
 * 1. KeePass 2.x XML (.xml) - Native support in MacPass, KeePassXC, and KeePass
 * 2. Universal Password CSV (.csv) - Supported by Bitwarden, 1Password, etc.
 */

import { App, Modal, Setting, Notice, TFile, TFolder, Platform } from "obsidian";
import type VaultGuardPlugin from "../main";
import {
  parseInline,
  parseCodeBlock,
  INLINE_SECRET_REGEX,
  CODE_BLOCK_SECRET_REGEX,
  SecretPayload,
} from "../crypto/serializer";
import {
  DecryptedExportEntry,
  generateKeePassXML,
  generateCSV,
} from "../utils/exporter";
import { UnlockModal } from "./unlockModal";

export { DecryptedExportEntry, generateKeePassXML, generateCSV };

export class ExportSecretsModal extends Modal {
  private plugin: VaultGuardPlugin;
  private format: "xml" | "csv" = "xml";
  private selectedFolder: string = "/";
  private isExporting: boolean = false;
  private errorEl: HTMLElement | null = null;
  private statusEl: HTMLElement | null = null;

  constructor(app: App, plugin: VaultGuardPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen(): void {
    this.modalEl.addClass("mod-vaultguard-modal");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-modal", "vaultguard-export-modal");

    contentEl.createEl("h2", { text: "📤 Export Secrets to KeePass / MacPass" });

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "Decrypt and export your secrets into standard KeePass XML or CSV format. The exported file can be opened directly with MacPass, KeePassXC, KeePass, or imported into 1Password / Bitwarden.",
    });

    const warningBox = contentEl.createDiv({ cls: "vaultguard-intercept-banner" });
    warningBox.createEl("span", { cls: "vaultguard-badge-pattern", text: "Security Notice" });
    warningBox.createEl("span", {
      cls: "setting-item-description",
      text: "The generated export file will contain your credentials. Store it in a secure location or import it into MacPass/KeePass immediately, then delete the exported file.",
    });

    this.errorEl = contentEl.createDiv({ cls: "vaultguard-error-message" });
    this.errorEl.style.display = "none";

    // 1. Export Format Selection
    new Setting(contentEl)
      .setName("Export Format")
      .setDesc("Choose your password manager export specification.")
      .addDropdown((dropdown) => {
        dropdown.addOption("xml", "KeePass 2.x XML (.xml) - MacPass, KeePassXC, KeePass");
        dropdown.addOption("csv", "Universal CSV (.csv) - 1Password, Bitwarden, KeePass");
        dropdown.setValue(this.format);
        dropdown.onChange((val: any) => {
          this.format = val;
        });
      });

    // 2. Folder Scope Selection
    const folders = this.getVaultFolders();
    new Setting(contentEl)
      .setName("Export Scope")
      .setDesc("Choose whether to export secrets from your entire vault or a specific folder.")
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

    this.statusEl = contentEl.createDiv({ cls: "vaultguard-export-status" });
    this.statusEl.style.display = "none";

    // Action Buttons
    const buttonContainer = contentEl.createDiv({ cls: "vaultguard-modal-buttons" });

    const cancelBtn = buttonContainer.createEl("button", { text: "Cancel" });
    cancelBtn.addEventListener("click", () => this.close());

    const exportBtn = buttonContainer.createEl("button", {
      cls: "mod-cta",
      text: "📤 Decrypt & Export File",
    });
    exportBtn.addEventListener("click", () => this.handleExport());
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

  private async handleExport(): Promise<void> {
    if (!this.plugin.settings.isInitialized) {
      new Notice("VaultGuard is not configured with a master passphrase.");
      return;
    }

    if (!this.plugin.session.isUnlocked()) {
      new UnlockModal(this.app, this.plugin, {
        mode: "unlock",
        onSuccess: () => this.handleExport(),
      }).open();
      return;
    }

    this.isExporting = true;
    if (this.statusEl) {
      this.statusEl.style.display = "block";
      this.statusEl.textContent = "Scanning notes and decrypting credentials in memory...";
    }

    try {
      const files = this.getTargetMarkdownFiles();
      const entries: DecryptedExportEntry[] = [];
      const vaultName = this.app.vault.getName();

      for (const file of files) {
        const content = await this.app.vault.read(file);
        const folderGroup = file.parent?.path && file.parent.path !== "/"
          ? `VaultGuard/${file.parent.path}`
          : "VaultGuard";

        // 1. Scan Inline Secrets
        INLINE_SECRET_REGEX.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = INLINE_SECRET_REGEX.exec(content)) !== null) {
          const rawToken = match[0];
          const payload = parseInline(rawToken);
          if (payload) {
            try {
              const decrypted = await this.plugin.session.decryptSecret(payload);
              entries.push({
                title: payload.label || `Secret (${file.basename})`,
                password: decrypted,
                group: folderGroup,
                url: `obsidian://open?vault=${encodeURIComponent(vaultName)}&file=${encodeURIComponent(file.path)}`,
                notes: `Source Note: ${file.path}\nStorage Format: Inline Comment`,
              });
            } catch (e) {
              console.warn(`VaultGuard: Decryption failed for token in ${file.path}:`, e);
            }
          }
        }

        // 2. Scan Fenced Code Blocks
        CODE_BLOCK_SECRET_REGEX.lastIndex = 0;
        while ((match = CODE_BLOCK_SECRET_REGEX.exec(content)) !== null) {
          const rawToken = match[0];
          const payload = parseCodeBlock(rawToken);
          if (payload) {
            try {
              const decrypted = await this.plugin.session.decryptSecret(payload);
              entries.push({
                title: payload.label || `Secret Block (${file.basename})`,
                password: decrypted,
                group: folderGroup,
                url: `obsidian://open?vault=${encodeURIComponent(vaultName)}&file=${encodeURIComponent(file.path)}`,
                notes: `Source Note: ${file.path}\nStorage Format: Fenced Code Block`,
              });
            } catch (e) {
              console.warn(`VaultGuard: Decryption failed for codeblock in ${file.path}:`, e);
            }
          }
        }
      }

      if (entries.length === 0) {
        new Notice("No VaultGuard encrypted secrets found in the selected scope.");
        this.close();
        return;
      }

      // Generate File Content
      let fileContent: string;
      let filename: string;
      let mimeType: string;

      const dateStr = new Date().toISOString().slice(0, 10);

      if (this.format === "xml") {
        fileContent = generateKeePassXML(entries, vaultName);
        filename = `VaultGuard-Export-${dateStr}.xml`;
        mimeType = "application/xml";
      } else {
        fileContent = generateCSV(entries);
        filename = `VaultGuard-Export-${dateStr}.csv`;
        mimeType = "text/csv";
      }

      // Trigger Save: On mobile, write directly to vault root; on desktop, trigger download
      if (Platform.isMobile) {
        const existingFile = this.app.vault.getAbstractFileByPath(filename);
        if (existingFile instanceof TFile) {
          await this.app.vault.modify(existingFile, fileContent);
        } else {
          await this.app.vault.create(filename, fileContent);
        }
        new Notice(
          `✅ Saved export file "${filename}" to vault root. Open or share it to MacPass/KeePass!`
        );
      } else {
        downloadFile(fileContent, filename, mimeType);
        new Notice(
          `✅ Successfully exported ${entries.length} secret${
            entries.length > 1 ? "s" : ""
          } to ${filename}!`
        );
      }
      this.close();
    } catch (err: any) {
      if (this.errorEl) {
        this.errorEl.textContent = `Export failed: ${err.message}`;
        this.errorEl.style.display = "block";
      }
    } finally {
      this.isExporting = false;
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

/**
 * Triggers safe browser/electron file download
 */
function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: `${mimeType};charset=utf-8;` });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", filename);
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, 100);
}
