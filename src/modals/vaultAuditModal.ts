/**
 * KeyMask Secret Audit & Batch Remediation Modal
 *
 * Scans the entire vault or selected folders for unencrypted plaintext credentials,
 * API keys, passwords, and tokens.
 * Provides interactive review and one-click batch encryption & masking.
 */

import { App, Modal, Setting, Notice, TFile, TFolder, MarkdownView } from "obsidian";
import type KeyMaskPlugin from "../main";
import {
  DiscoveredSecret,
  maskForPreview,
  scanTextForSecrets,
  extractSecretSnippet,
} from "../utils/heuristics";
import { UnlockModal } from "./unlockModal";

export interface FileAuditResult {
  file: TFile;
  secrets: DiscoveredSecret[];
}

export class VaultAuditModal extends Modal {
  private plugin: KeyMaskPlugin;
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

  constructor(app: App, plugin: KeyMaskPlugin) {
    super(app);
    this.plugin = plugin;
  }

  onOpen(): void {
    this.modalEl.addClass("mod-keymask-audit");
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("keymask-modal", "keymask-audit-modal");

    contentEl.createEl("h2", { text: "🔍 KeyMask: Secret Audit & Leak Scanner" });

    contentEl.createEl("p", {
      cls: "setting-item-description",
      text: "Scan your existing notes for exposed plaintext API keys, passwords, connection URIs, and private keys. Once discovered, KeyMask can encrypt and mask them in-place with zero data loss.",
    });

    this.containerElContent = contentEl.createDiv({ cls: "keymask-audit-body" });
    this.renderScanControls();
  }

  private renderScanControls(): void {
    if (!this.containerElContent) return;
    this.containerElContent.empty();

    const controlsCard = this.containerElContent.createDiv({
      cls: "keymask-audit-controls-card",
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
    const buttonRow = controlsCard.createDiv({ cls: "keymask-audit-start-row" });
    const startScanBtn = buttonRow.createEl("button", {
      cls: "mod-cta keymask-start-scan-btn",
      text: "🔍 Start Secret Audit",
    });

    startScanBtn.addEventListener("click", () => {
      this.runAuditScan();
    });

    // Placeholder for Progress and Results
    this.progressContainer = this.containerElContent.createDiv({
      cls: "keymask-audit-progress-container keymask-hidden",
    });

    this.resultsContainer = this.containerElContent.createDiv({
      cls: "keymask-audit-results-container",
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
      this.progressContainer.removeClass("keymask-hidden");
      this.progressContainer.empty();
    }
    if (this.resultsContainer) {
      this.resultsContainer.empty();
    }

    const totalFiles = filesToScan.length;
    let scannedCount = 0;
    let exposedCount = 0;

    const progressBar = this.progressContainer?.createEl("progress", {
      cls: "keymask-progress-bar",
      attr: { max: totalFiles.toString(), value: "0" },
    });
    const progressLabel = this.progressContainer?.createDiv({
      cls: "keymask-progress-label",
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
        console.warn(`KeyMask: Error reading file ${file.path}:`, e);
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
      this.progressContainer.addClass("keymask-hidden");
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
        cls: "keymask-clean-banner",
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
      cls: "keymask-audit-summary-header",
    });

    const summaryText = summaryHeader.createDiv({
      cls: "keymask-audit-summary-text",
    });
    summaryText.createEl("h3", {
      text: `⚠️ Found ${totalSecrets} Exposed Secret${totalSecrets > 1 ? "s" : ""} across ${this.auditResults.length} Note${this.auditResults.length > 1 ? "s" : ""}`,
    });
    summaryText.createEl("p", {
      cls: "setting-item-description",
      text: "Select the secrets you wish to encrypt. KeyMask will replace the plaintext with authenticated AES-256-GCM ciphertext tokens.",
    });

    const actionRow = summaryHeader.createDiv({
      cls: "keymask-audit-action-row",
    });

    // Select/Deselect All
    const selectAllBtn = actionRow.createEl("button", {
      text: "Select All",
      cls: "keymask-btn-secondary",
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
      cls: "keymask-btn-secondary",
    });
    deselectAllBtn.addEventListener("click", () => {
      this.selectedSecretIds.clear();
      this.updateSelectionCounts();
    });

    // Expand All / Collapse All
    const expandAllBtn = actionRow.createEl("button", {
      text: "▾ Expand All",
      cls: "keymask-btn-secondary",
    });
    expandAllBtn.addEventListener("click", () => {
      this.contentEl.querySelectorAll<HTMLElement>(".keymask-file-card").forEach((card) => {
        card.removeClass("is-collapsed");
        const chevron = card.querySelector<HTMLElement>(".keymask-chevron-icon");
        if (chevron) chevron.textContent = "▼";
      });
    });

    const collapseAllBtn = actionRow.createEl("button", {
      text: "▸ Collapse All",
      cls: "keymask-btn-secondary",
    });
    collapseAllBtn.addEventListener("click", () => {
      this.contentEl.querySelectorAll<HTMLElement>(".keymask-file-card").forEach((card) => {
        card.addClass("is-collapsed");
        const chevron = card.querySelector<HTMLElement>(".keymask-chevron-icon");
        if (chevron) chevron.textContent = "▶";
      });
    });

    // Primary Remediation Button
    const remediateBtn = actionRow.createEl("button", {
      cls: "mod-cta keymask-batch-remediate-btn",
      text: `🔒 Encrypt & Mask Selected (${this.selectedSecretIds.size})`,
    });
    remediateBtn.addEventListener("click", () => {
      this.executeBatchRemediation();
    });

    // Group Findings by Note
    const filesList = this.resultsContainer.createDiv({
      cls: "keymask-audit-files-list",
    });

    for (const fileResult of this.auditResults) {
      const { file, secrets } = fileResult;

      const fileCard = filesList.createDiv({ cls: "keymask-file-card" });

      // File Title Bar with clean Basename, Path, Badge, and Action buttons
      const fileHeader = fileCard.createDiv({ cls: "keymask-file-header" });

      const fileInfo = fileHeader.createDiv({ cls: "keymask-file-info" });
      const fileTitle = fileInfo.createEl("span", {
        cls: "keymask-file-title",
        text: `📄 ${file.basename}`,
      });
      if (file.parent && file.parent.path !== "/") {
        fileInfo.createEl("span", {
          cls: "keymask-file-path",
          text: `📁 ${file.path}`,
        });
      }

      const headerRight = fileHeader.createDiv({ cls: "keymask-header-actions" });
      headerRight.createEl("span", {
        cls: "keymask-file-badge",
        text: `${secrets.length} secret${secrets.length > 1 ? "s" : ""}`,
      });

      const openNoteBtn = headerRight.createEl("button", {
        cls: "keymask-btn-open-file",
        text: "↗ Open Note",
        attr: { title: "Open this note in editor" },
      });
      openNoteBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.openNoteAtLine(file, 1);
      });

      const chevronIcon = headerRight.createEl("span", {
        cls: "keymask-chevron-icon",
        text: "▼",
      });

      // Findings List inside fileCard
      const findingsList = fileCard.createDiv({ cls: "keymask-file-findings" });

      // Header click toggles collapse / expand
      fileHeader.addEventListener("click", (e) => {
        const target = e.target as HTMLElement;
        if (target === openNoteBtn || target.closest(".keymask-btn-open-file")) {
          return;
        }
        const isCollapsed = fileCard.hasClass("is-collapsed");
        if (isCollapsed) {
          fileCard.removeClass("is-collapsed");
          chevronIcon.textContent = "▼";
        } else {
          fileCard.addClass("is-collapsed");
          chevronIcon.textContent = "▶";
        }
      });

      for (const secret of secrets) {
        const itemCard = findingsList.createDiv({
          cls: `keymask-secret-item row-${secret.id}`,
        });

        // Top Row: Checkbox, Line badge, Type tag, Jump button, Encrypt button
        const topRow = itemCard.createDiv({ cls: "keymask-item-top-row" });

        const leftGroup = topRow.createDiv({ cls: "keymask-item-left" });

        const checkbox = leftGroup.createEl("input", {
          type: "checkbox",
          cls: "keymask-secret-checkbox",
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

        const lineBadge = leftGroup.createEl("span", {
          cls: "keymask-cell-line clickable-icon",
          text: `📍 Line ${secret.lineNumber}`,
          attr: { title: "Click to jump to line in note" },
        });
        lineBadge.addEventListener("click", () => {
          this.openNoteAtLine(file, secret.lineNumber, secret.matchedText);
        });

        leftGroup.createEl("span", {
          cls: "keymask-pattern-tag",
          text: secret.patternName,
        });

        const rightGroup = topRow.createDiv({ cls: "keymask-item-right" });

        const jumpBtn = rightGroup.createEl("button", {
          cls: "keymask-btn-jump",
          text: "↗ Jump to Line",
          attr: { title: "Open note and scroll directly to this secret" },
        });
        jumpBtn.addEventListener("click", (e) => {
          e.stopPropagation();
          this.openNoteAtLine(file, secret.lineNumber, secret.matchedText);
        });

        if (this.remediatedSecretIds.has(secret.id)) {
          rightGroup.createEl("span", {
            cls: "keymask-remediated-badge",
            text: "✅ Encrypted",
          });
        } else {
          const singleEncryptBtn = rightGroup.createEl("button", {
            cls: "keymask-btn-single-encrypt",
            text: "🔒 Encrypt",
          });
          singleEncryptBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            this.remediateSingleSecret(file, secret);
          });
        }

        // Context Snippet Box (Middle Row): shows exact localized radius around the secret
        const snippetBox = itemCard.createDiv({
          cls: "keymask-snippet-box clickable-icon",
          attr: { title: "Click to jump to this secret in editor" },
        });
        snippetBox.addEventListener("click", () => {
          this.openNoteAtLine(file, secret.lineNumber, secret.matchedText);
        });

        const codeSnippet = snippetBox.createEl("code");
        const snippet = extractSecretSnippet(secret.lineContent, secret.matchedText, 40);

        if (snippet.before) {
          codeSnippet.createSpan({ text: snippet.before, cls: "keymask-snippet-context" });
        }
        codeSnippet.createEl("mark", {
          cls: "keymask-secret-highlight",
          text: snippet.matchedMasked,
        });
        if (snippet.after) {
          codeSnippet.createSpan({ text: snippet.after, cls: "keymask-snippet-context" });
        }

        // Bottom Row: Custom label input
        const bottomRow = itemCard.createDiv({ cls: "keymask-item-bottom-row" });
        bottomRow.createEl("span", {
          cls: "keymask-label-caption",
          text: "Pill Label:",
        });
        const labelInput = bottomRow.createEl("input", {
          type: "text",
          cls: "keymask-inline-label-input",
          attr: { placeholder: "Label for masked pill" },
        });
        labelInput.value =
          this.customLabels.get(secret.id) || secret.suggestedLabel;
        labelInput.addEventListener("input", () => {
          this.customLabels.set(secret.id, labelInput.value.trim());
        });
      }
    }
  }

  /**
   * Opens the file in Obsidian editor and jumps directly to the specified line and secret
   */
  private async openNoteAtLine(
    file: TFile,
    lineNumber: number,
    secretText?: string
  ): Promise<void> {
    try {
      // Close the modal so the user immediately sees the note in the editor
      this.close();

      const leaf = this.app.workspace.getLeaf(false);
      await leaf.openFile(file);
      this.app.workspace.setActiveLeaf(leaf, { focus: true });

      setTimeout(() => {
        const view = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (view && view.editor) {
          const lineIndex = Math.max(0, lineNumber - 1);
          const lineText = view.editor.getLine(lineIndex) || "";

          let ch = -1;
          if (secretText) {
            ch = lineText.indexOf(secretText);
          }

          if (ch >= 0 && secretText) {
            view.editor.setSelection(
              { line: lineIndex, ch },
              { line: lineIndex, ch: ch + secretText.length }
            );
            view.editor.scrollIntoView(
              {
                from: { line: lineIndex, ch },
                to: { line: lineIndex, ch: ch + secretText.length },
              },
              true
            );
          } else {
            view.editor.setCursor({ line: lineIndex, ch: 0 });
            view.editor.scrollIntoView(
              {
                from: { line: lineIndex, ch: 0 },
                to: { line: lineIndex, ch: 0 },
              },
              true
            );
          }
        }
      }, 75);

      new Notice(
        `📍 Jumped to Line ${lineNumber} in "${file.basename}". Reopen Audit via Settings or Command Palette.`
      );
    } catch (e: any) {
      new Notice(`Could not open file: ${e.message}`);
    }
  }

  private updateSelectionCounts(): void {
    const checkboxes = this.contentEl.querySelectorAll<HTMLInputElement>(
      ".keymask-secret-checkbox"
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
      ".keymask-batch-remediate-btn"
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
