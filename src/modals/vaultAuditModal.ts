/**
 * VaultGuard Secret Audit & Batch Remediation Modal
 *
 * Scans the entire vault or selected folders for unencrypted plaintext credentials,
 * API keys, passwords, and tokens.
 * Provides interactive review and one-click batch encryption & masking.
 */

import { App, Modal, Setting, Notice, TFile, TFolder } from "obsidian";
import type VaultGuardPlugin from "../main";
import {
  DiscoveredSecret,
  maskForPreview,
  scanTextForSecrets,
} from "../utils/heuristics";
import { UnlockModal } from "./unlockModal";

export interface FileAuditResult {
  file: TFile;
  secrets: DiscoveredSecret[];
}

export class VaultAuditModal extends Modal {
  private plugin: VaultGuardPlugin;
  private selectedFolder: string = "/"; // "/" represents entire vault
  private includeSubfolders: boolean = true;
  private isScanning: boolean = false;
  private isRemediating: boolean = false;
  private auditResults: FileAuditResult[] = [];
  private selectedSecretIds: Set<string> = new Set();
  private customLabels: Map<string, string> = new Map();
  private remediatedSecretIds: Set<string> = new Set();

  private containerElContent: HTMLElement | null = null;
  private progressContainer: HTMLElement | null = null;
  private resultsContainer: HTMLElement | null = null;

  constructor(app: App, plugin: VaultGuardPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen(): void {
    this.modalEl.addClass("mod-vaultguard-audit");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-modal", "vaultguard-audit-modal");

    contentEl.createEl("h2", { text: "🔍 VaultGuard: Secret Audit & Leak Scanner" });

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "Scan your existing notes for exposed plaintext API keys, passwords, connection URIs, and private keys. Once discovered, VaultGuard can encrypt and mask them in-place with zero data loss.",
    });

    this.containerElContent = contentEl.createDiv({ cls: "vaultguard-audit-body" });
    this.renderScanControls();
  }

  private renderScanControls(): void {
    if (!this.containerElContent) return;
    this.containerElContent.empty();

    const controlsCard = this.containerElContent.createDiv({
      cls: "vaultguard-audit-controls-card",
    });

    // 1. Folder Selection Dropdown
    const folders = this.getVaultFolders();
    new Setting(controlsCard)
      .setName("Scan Target")
      .setDesc("Choose whether to audit your entire vault or a specific folder.")
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

    // 2. Subfolders Toggle
    new Setting(controlsCard)
      .setName("Include Subfolders")
      .setDesc("Recursively inspect all nested subdirectories inside the selected folder.")
      .addToggle((toggle) => {
        toggle.setValue(this.includeSubfolders);
        toggle.onChange((val) => {
          this.includeSubfolders = val;
        });
      });

    // 3. Start Scan Button
    const buttonRow = controlsCard.createDiv({ cls: "vaultguard-audit-start-row" });
    const startScanBtn = buttonRow.createEl("button", {
      cls: "mod-cta vaultguard-start-scan-btn",
      text: "🔍 Start Secret Audit",
    });

    startScanBtn.addEventListener("click", () => {
      this.runAuditScan();
    });

    // Placeholder for Progress and Results
    this.progressContainer = this.containerElContent.createDiv({
      cls: "vaultguard-audit-progress-container",
    });
    this.progressContainer.style.display = "none";

    this.resultsContainer = this.containerElContent.createDiv({
      cls: "vaultguard-audit-results-container",
    });
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

    const folderPrefix = this.selectedFolder.endsWith("/")
      ? this.selectedFolder
      : this.selectedFolder + "/";

    return allFiles.filter((file) => {
      if (this.includeSubfolders) {
        return file.path.startsWith(folderPrefix) || file.path === this.selectedFolder;
      } else {
        return file.parent?.path === this.selectedFolder;
      }
    });
  }

  private async runAuditScan(): Promise<void> {
    const filesToScan = this.getTargetMarkdownFiles();

    if (filesToScan.length === 0) {
      new Notice("No Markdown files found in the selected target.");
      return;
    }

    this.isScanning = true;
    this.auditResults = [];
    this.selectedSecretIds.clear();
    this.remediatedSecretIds.clear();

    if (this.progressContainer) {
      this.progressContainer.style.display = "block";
      this.progressContainer.empty();
    }
    if (this.resultsContainer) {
      this.resultsContainer.empty();
    }

    const totalFiles = filesToScan.length;
    let scannedCount = 0;
    let exposedCount = 0;

    const progressBar = this.progressContainer?.createEl("progress", {
      cls: "vaultguard-progress-bar",
      attr: { max: totalFiles.toString(), value: "0" },
    });
    const progressLabel = this.progressContainer?.createDiv({
      cls: "vaultguard-progress-label",
      text: `Scanning notes (0/${totalFiles})...`,
    });

    for (let i = 0; i < totalFiles; i++) {
      const file = filesToScan[i];
      try {
        const content = await this.app.vault.read(file);
        const findings = scanTextForSecrets(content);

        if (findings.length > 0) {
          this.auditResults.push({ file, secrets: findings });
          exposedCount += findings.length;

          // Select all by default
          for (const s of findings) {
            this.selectedSecretIds.add(s.id);
            this.customLabels.set(s.id, s.suggestedLabel);
          }
        }
      } catch (e) {
        console.warn(`VaultGuard: Error reading file ${file.path}:`, e);
      }

      scannedCount++;
      if (progressBar) progressBar.value = scannedCount;
      if (progressLabel) {
        progressLabel.textContent = `Scanning note ${scannedCount}/${totalFiles}... (${exposedCount} exposed secrets found)`;
      }

      // Yield event loop every 10 files to keep UI responsive
      if (i % 10 === 0) {
        await new Promise((r) => setTimeout(r, 0));
      }
    }

    this.isScanning = false;
    if (this.progressContainer) {
      this.progressContainer.style.display = "none";
    }

    this.renderAuditResults();
  }

  private renderAuditResults(): void {
    if (!this.resultsContainer) return;
    this.resultsContainer.empty();

    const totalSecrets = this.auditResults.reduce(
      (sum, r) => sum + r.secrets.length,
      0
    );

    // If no secrets found
    if (totalSecrets === 0) {
      const cleanBanner = this.resultsContainer.createDiv({
        cls: "vaultguard-clean-banner",
      });
      cleanBanner.createEl("div", { cls: "clean-icon", text: "🎉" });
      cleanBanner.createEl("h3", { text: "No Exposed Secrets Found!" });
      cleanBanner.createEl("p", {
        cls: "setting-item-description",
        text: "All scanned notes are clean. No plaintext API keys, passwords, or credentials were detected.",
      });
      return;
    }

    // Header Summary & Actions
    const summaryHeader = this.resultsContainer.createDiv({
      cls: "vaultguard-audit-summary-header",
    });

    const summaryText = summaryHeader.createDiv({
      cls: "vaultguard-audit-summary-text",
    });
    summaryText.createEl("h3", {
      text: `⚠️ Found ${totalSecrets} Exposed Secret${totalSecrets > 1 ? "s" : ""} across ${this.auditResults.length} Note${this.auditResults.length > 1 ? "s" : ""}`,
    });
    summaryText.createEl("p", {
      cls: "setting-item-description",
      text: "Select the secrets you wish to encrypt. VaultGuard will replace the plaintext with authenticated AES-256-GCM ciphertext tokens.",
    });

    const actionRow = summaryHeader.createDiv({
      cls: "vaultguard-audit-action-row",
    });

    // Select/Deselect All
    const selectAllBtn = actionRow.createEl("button", {
      text: "Select All",
      cls: "vaultguard-btn-secondary",
    });
    selectAllBtn.addEventListener("click", () => {
      for (const res of this.auditResults) {
        for (const s of res.secrets) {
          if (!this.remediatedSecretIds.has(s.id)) {
            this.selectedSecretIds.add(s.id);
          }
        }
      }
      this.updateSelectionCounts();
    });

    const deselectAllBtn = actionRow.createEl("button", {
      text: "Deselect All",
      cls: "vaultguard-btn-secondary",
    });
    deselectAllBtn.addEventListener("click", () => {
      this.selectedSecretIds.clear();
      this.updateSelectionCounts();
    });

    // Primary Remediation Button
    const remediateBtn = actionRow.createEl("button", {
      cls: "mod-cta vaultguard-batch-remediate-btn",
      text: `🔒 Encrypt & Mask Selected (${this.selectedSecretIds.size})`,
    });
    remediateBtn.addEventListener("click", () => {
      this.executeBatchRemediation();
    });

    // Group Findings by Note
    const filesList = this.resultsContainer.createDiv({
      cls: "vaultguard-audit-files-list",
    });

    for (const fileResult of this.auditResults) {
      const { file, secrets } = fileResult;

      const fileCard = filesList.createDiv({ cls: "vaultguard-file-card" });

      // File Title Bar
      const fileHeader = fileCard.createDiv({ cls: "vaultguard-file-header" });

      const fileTitle = fileHeader.createEl("span", {
        cls: "vaultguard-file-title clickable-icon",
        text: `📄 ${file.path}`,
        attr: { title: "Click to open file in workspace" },
      });
      fileTitle.addEventListener("click", () => {
        this.app.workspace.openLinkText(file.path, "", false);
      });

      fileHeader.createEl("span", {
        cls: "vaultguard-file-badge",
        text: `${secrets.length} secret${secrets.length > 1 ? "s" : ""}`,
      });

      // Secrets List in this file
      const table = fileCard.createEl("table", {
        cls: "vaultguard-secrets-table",
      });
      const thead = table.createEl("thead");
      const headerRow = thead.createEl("tr");
      headerRow.createEl("th", { text: "" }); // Checkbox
      headerRow.createEl("th", { text: "Line" });
      headerRow.createEl("th", { text: "Type" });
      headerRow.createEl("th", { text: "Masked Value Preview" });
      headerRow.createEl("th", { text: "Label" });
      headerRow.createEl("th", { text: "Action" });

      const tbody = table.createEl("tbody");

      for (const secret of secrets) {
        const row = tbody.createEl("tr", { cls: `row-${secret.id}` });

        // 1. Checkbox
        const cbCell = row.createEl("td");
        const checkbox = cbCell.createEl("input", {
          type: "checkbox",
          cls: "vaultguard-secret-checkbox",
        });
        checkbox.checked = this.selectedSecretIds.has(secret.id);
        checkbox.disabled = this.remediatedSecretIds.has(secret.id);

        checkbox.addEventListener("change", () => {
          if (checkbox.checked) {
            this.selectedSecretIds.add(secret.id);
          } else {
            this.selectedSecretIds.delete(secret.id);
          }
          this.updateRemediateButton(remediateBtn);
        });

        // 2. Line Number
        row.createEl("td", {
          cls: "vaultguard-cell-line",
          text: `L${secret.lineNumber}`,
        });

        // 3. Secret Pattern Badge
        const typeCell = row.createEl("td");
        typeCell.createEl("span", {
          cls: "vaultguard-pattern-tag",
          text: secret.patternName,
        });

        // 4. Masked Preview
        const previewCell = row.createEl("td");
        previewCell.createEl("code", {
          cls: "vaultguard-preview-snippet",
          text: maskForPreview(secret.matchedText),
        });

        // 5. Label Input
        const labelCell = row.createEl("td");
        const labelInput = labelCell.createEl("input", {
          type: "text",
          cls: "vaultguard-inline-label-input",
          attr: { placeholder: "Label" },
        });
        labelInput.value = this.customLabels.get(secret.id) || secret.suggestedLabel;
        labelInput.addEventListener("input", () => {
          this.customLabels.set(secret.id, labelInput.value.trim());
        });

        // 6. Action / Remediated Status
        const actionCell = row.createEl("td");
        if (this.remediatedSecretIds.has(secret.id)) {
          actionCell.createEl("span", {
            cls: "vaultguard-remediated-badge",
            text: "✅ Encrypted",
          });
        } else {
          const singleEncryptBtn = actionCell.createEl("button", {
            cls: "vaultguard-btn-single-encrypt",
            text: "🔒 Encrypt",
          });
          singleEncryptBtn.addEventListener("click", () => {
            this.remediateSingleSecret(file, secret);
          });
        }
      }
    }
  }

  private updateSelectionCounts(): void {
    const checkboxes = this.contentEl.querySelectorAll<HTMLInputElement>(
      ".vaultguard-secret-checkbox"
    );
    checkboxes.forEach((cb) => {
      const row = cb.closest("tr");
      if (row) {
        const idMatch = row.className.match(/row-(secret-[0-9]+-[0-9]+)/);
        if (idMatch && idMatch[1]) {
          cb.checked = this.selectedSecretIds.has(idMatch[1]);
        }
      }
    });

    const remediateBtn = this.contentEl.querySelector<HTMLButtonElement>(
      ".vaultguard-batch-remediate-btn"
    );
    if (remediateBtn) {
      this.updateRemediateButton(remediateBtn);
    }
  }

  private updateRemediateButton(btn: HTMLButtonElement): void {
    const activeCount = Array.from(this.selectedSecretIds).filter(
      (id) => !this.remediatedSecretIds.has(id)
    ).length;
    btn.textContent = `🔒 Encrypt & Mask Selected (${activeCount})`;
    btn.disabled = activeCount === 0;
  }

  /**
   * Encrypt a single secret in a note
   */
  private async remediateSingleSecret(
    file: TFile,
    secret: DiscoveredSecret
  ): Promise<void> {
    if (!this.checkVaultUnlocked(() => this.remediateSingleSecret(file, secret))) {
      return;
    }

    try {
      const content = await this.app.vault.read(file);
      const label = this.customLabels.get(secret.id) || secret.suggestedLabel;

      const token = await this.plugin.session.encryptSecret(
        secret.matchedText,
        label,
        secret.isMultiline
      );

      // Verify substring still exists at or near original location
      let updatedContent: string;
      if (content.slice(secret.startIndex, secret.endIndex) === secret.matchedText) {
        updatedContent =
          content.slice(0, secret.startIndex) +
          token +
          content.slice(secret.endIndex);
      } else {
        // Fallback: search and replace first instance
        updatedContent = content.replace(secret.matchedText, token);
      }

      await this.app.vault.modify(file, updatedContent);

      this.remediatedSecretIds.add(secret.id);
      this.selectedSecretIds.delete(secret.id);
      new Notice(`🔒 Encrypted secret in "${file.basename}".`);
      this.renderAuditResults();
    } catch (err: any) {
      new Notice(`Failed to encrypt secret: ${err.message}`);
    }
  }

  /**
   * Batch encrypt and mask all selected secrets across all files
   */
  private async executeBatchRemediation(): Promise<void> {
    const activeSelectedIds = Array.from(this.selectedSecretIds).filter(
      (id) => !this.remediatedSecretIds.has(id)
    );

    if (activeSelectedIds.length === 0) {
      new Notice("No secrets selected for encryption.");
      return;
    }

    if (!this.checkVaultUnlocked(() => this.executeBatchRemediation())) {
      return;
    }

    this.isRemediating = true;
    let encryptedCount = 0;
    let modifiedFilesCount = 0;

    try {
      for (const fileResult of this.auditResults) {
        const { file, secrets } = fileResult;

        // Filter secrets that are selected in this file
        const toRemediate = secrets.filter(
          (s) =>
            this.selectedSecretIds.has(s.id) && !this.remediatedSecretIds.has(s.id)
        );

        if (toRemediate.length === 0) continue;

        let content = await this.app.vault.read(file);

        // Sort descending by startIndex (reverse order) so character replacements
        // do not invalidate preceding index offsets!
        toRemediate.sort((a, b) => b.startIndex - a.startIndex);

        for (const secret of toRemediate) {
          const label =
            this.customLabels.get(secret.id) || secret.suggestedLabel;

          const token = await this.plugin.session.encryptSecret(
            secret.matchedText,
            label,
            secret.isMultiline
          );

          if (
            content.slice(secret.startIndex, secret.endIndex) ===
            secret.matchedText
          ) {
            content =
              content.slice(0, secret.startIndex) +
              token +
              content.slice(secret.endIndex);
          } else {
            // Fallback replace
            content = content.replace(secret.matchedText, token);
          }

          this.remediatedSecretIds.add(secret.id);
          this.selectedSecretIds.delete(secret.id);
          encryptedCount++;
        }

        await this.app.vault.modify(file, content);
        modifiedFilesCount++;
      }

      new Notice(
        `🎉 Successfully encrypted and masked ${encryptedCount} secret${
          encryptedCount > 1 ? "s" : ""
        } across ${modifiedFilesCount} note${modifiedFilesCount > 1 ? "s" : ""}!`
      );

      this.renderAuditResults();
    } catch (err: any) {
      new Notice(`Error during batch encryption: ${err.message}`);
    } finally {
      this.isRemediating = false;
    }
  }

  private checkVaultUnlocked(onSuccess: () => void): boolean {
    if (!this.plugin.settings.isInitialized) {
      new UnlockModal(this.app, this.plugin, {
        mode: "init",
        onSuccess,
      }).open();
      return false;
    }

    if (!this.plugin.session.isUnlocked()) {
      new UnlockModal(this.app, this.plugin, {
        mode: "unlock",
        onSuccess,
      }).open();
      return false;
    }

    return true;
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
