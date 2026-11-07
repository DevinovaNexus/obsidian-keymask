/**
 * VaultGuard Obsidian Plugin
 *
 * Plugin ID: obsidian-vaultguard
 * Core Entry Point
 */

import { Editor, MarkdownView, Notice, Plugin, TFile } from "obsidian";
import {
  DEFAULT_SETTINGS,
  VaultGuardSettings,
  VaultGuardSettingTab,
} from "./settings";
import { VaultGuardSession } from "./crypto/session";
import { createVaultGuardViewPlugin } from "./editor/viewPlugin";
import { registerPostProcessors } from "./editor/postProcessor";
import { registerPasteHandler } from "./editor/pasteHandler";
import { UnlockModal } from "./modals/unlockModal";
import { InsertSecretModal } from "./modals/insertSecretModal";
import { EncryptFileModal } from "./modals/encryptFileModal";
import { VaultAuditModal } from "./modals/vaultAuditModal";
import { ExportSecretsModal } from "./modals/exportSecretsModal";
import { BatchDecryptModal } from "./modals/batchDecryptModal";
import { confirmAction } from "./modals/confirmModal";
import { VaultGuardClipboard } from "./utils/clipboard";
import {
  isWholeFileEncrypted,
  extractWholeFilePayload,
} from "./crypto/serializer";
import { EncryptedFileViewManager } from "./editor/fileViewManager";

export default class VaultGuardPlugin extends Plugin {
  settings: VaultGuardSettings = DEFAULT_SETTINGS;
  session!: VaultGuardSession;
  fileViewManager!: EncryptedFileViewManager;
  statusBarItemEl: HTMLElement | null = null;

  async onload() {
    await this.loadSettings();

    // Initialize VaultGuard in-memory session manager
    this.session = new VaultGuardSession({
      getSalt: () => this.settings.salt,
      setSalt: async (saltB64) => {
        this.settings.salt = saltB64;
        await this.saveSettings();
      },
      getCanaryToken: () => this.settings.canaryToken,
      setCanaryToken: async (token) => {
        this.settings.canaryToken = token;
        await this.saveSettings();
      },
      getKdfIterations: () => this.settings.kdfIterations,
      getAutoLockTimeoutMinutes: () => this.settings.autoLockTimeoutMinutes,
      getLockOnBlur: () => this.settings.lockOnBlur,
    });

    // 1. Status Bar Item
    this.statusBarItemEl = this.addStatusBarItem();
    this.updateStatusBar();
    this.session.onStateChange(() => {
      this.updateStatusBar();
    });

    // 2. Ribbon Icon
    this.addRibbonIcon("shield-alert", "VaultGuard", () => {
      if (!this.settings.isInitialized) {
        new UnlockModal(this.app, this, { mode: "init" }).open();
      } else if (!this.session.isUnlocked()) {
        new UnlockModal(this.app, this, { mode: "unlock" }).open();
      } else {
        const activeView = this.app.workspace.getActiveViewOfType(MarkdownView);
        if (activeView && activeView.editor) {
          new InsertSecretModal(this.app, this, {
            editor: activeView.editor,
          }).open();
        } else {
          new Notice("🔓 VaultGuard is unlocked. Open a note to insert secrets.");
        }
      }
    });

    // 3. Command Palette Commands
    this.addCommand({
      id: "insert-encrypted-secret",
      name: "Insert Encrypted Secret",
      hotkeys: [{ modifiers: ["Mod", "Shift"], key: "S" }],
      editorCallback: (editor: Editor) => {
        const selection = editor.getSelection();
        new InsertSecretModal(this.app, this, {
          editor,
          initialSecret: selection ? selection : undefined,
        }).open();
      },
    });

    this.addCommand({
      id: "audit-vault-secrets",
      name: "Audit Vault for Plaintext Secrets",
      callback: () => {
        new VaultAuditModal(this.app, this).open();
      },
    });

    this.addCommand({
      id: "encrypt-selected-text",
      name: "Encrypt Selected Text",
      editorCallback: (editor: Editor) => {
        const selection = editor.getSelection();
        if (!selection) {
          new Notice("Please select text to encrypt.");
          return;
        }
        new InsertSecretModal(this.app, this, {
          editor,
          initialSecret: selection,
        }).open();
      },
    });

    this.addCommand({
      id: "unlock-vault",
      name: "Unlock Vault",
      callback: () => {
        if (!this.settings.isInitialized) {
          new UnlockModal(this.app, this, { mode: "init" }).open();
        } else if (this.session.isUnlocked()) {
          new Notice("VaultGuard is already unlocked.");
        } else {
          new UnlockModal(this.app, this, { mode: "unlock" }).open();
        }
      },
    });

    this.addCommand({
      id: "lock-vault",
      name: "Lock Vault",
      callback: () => {
        if (!this.session.isUnlocked()) {
          new Notice("VaultGuard is already locked.");
        } else {
          this.session.lock();
          new Notice("🔒 VaultGuard locked.");
        }
      },
    });

    this.addCommand({
      id: "change-master-passphrase",
      name: "Change Master Passphrase",
      callback: () => {
        if (!this.settings.isInitialized) {
          new UnlockModal(this.app, this, { mode: "init" }).open();
        } else {
          new UnlockModal(this.app, this, { mode: "change" }).open();
        }
      },
    });

    this.addCommand({
      id: "export-secrets-keepass",
      name: "Export Secrets to KeePass / MacPass (XML/CSV)",
      callback: () => {
        new ExportSecretsModal(this.app, this).open();
      },
    });

    this.addCommand({
      id: "batch-decrypt-all-secrets",
      name: "Batch Decrypt All Notes to Plaintext (Offboarding)",
      callback: () => {
        new BatchDecryptModal(this.app, this).open();
      },
    });

    this.addCommand({
      id: "clear-ephemeral-clipboard",
      name: "Clear Ephemeral Clipboard Now",
      callback: async () => {
        await VaultGuardClipboard.clearClipboard();
        VaultGuardClipboard.cancelAutoWipe();
        new Notice("🔒 Ephemeral clipboard wiped.");
      },
    });

    this.addCommand({
      id: "encrypt-entire-note",
      name: "Encrypt Entire Current Note",
      callback: async () => {
        const activeFile = this.app.workspace.getActiveFile();
        if (!activeFile || activeFile.extension !== "md") {
          new Notice("Please open a Markdown note first.");
          return;
        }
        await this.encryptEntireFile(activeFile);
      },
    });

    this.addCommand({
      id: "decrypt-entire-note",
      name: "Decrypt Entire Current Note to Plaintext",
      callback: async () => {
        const activeFile = this.app.workspace.getActiveFile();
        if (!activeFile || activeFile.extension !== "md") {
          new Notice("Please open a Markdown note first.");
          return;
        }
        await this.decryptEntireFile(activeFile);
      },
    });

    this.addCommand({
      id: "copy-note-encrypted",
      name: "Copy Note (Encrypted Ciphertext)",
      callback: async () => {
        const activeFile = this.app.workspace.getActiveFile();
        if (!activeFile || activeFile.extension !== "md") {
          new Notice("Please open a Markdown note first.");
          return;
        }
        await this.copyEncryptedFile(activeFile);
      },
    });

    this.addCommand({
      id: "copy-note-decrypted",
      name: "Copy Note (Decrypted Plaintext)",
      callback: async () => {
        const activeFile = this.app.workspace.getActiveFile();
        if (!activeFile || activeFile.extension !== "md") {
          new Notice("Please open a Markdown note first.");
          return;
        }
        await this.copyDecryptedFile(activeFile);
      },
    });

    // 4. Editor Context Menu
    this.registerEvent(
      this.app.workspace.on("editor-menu", (menu, editor) => {
        const selection = editor.getSelection();
        if (selection && selection.length > 0) {
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Encrypt Selection")
              .setIcon("lock")
              .onClick(() => {
                new InsertSecretModal(this.app, this, {
                  editor,
                  initialSecret: selection,
                }).open();
              });
          });
        }

        const activeFile = this.app.workspace.getActiveFile();
        if (activeFile && activeFile.extension === "md") {
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Encrypt Entire Note")
              .setIcon("lock")
              .onClick(async () => {
                await this.encryptEntireFile(activeFile);
              });
          });
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Decrypt Note to Plaintext")
              .setIcon("unlock")
              .onClick(async () => {
                await this.decryptEntireFile(activeFile);
              });
          });
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Copy Note (Encrypted)")
              .setIcon("copy")
              .onClick(async () => {
                await this.copyEncryptedFile(activeFile);
              });
          });
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Copy Note (Decrypted)")
              .setIcon("clipboard-check")
              .onClick(async () => {
                await this.copyDecryptedFile(activeFile);
              });
          });
        }
      })
    );

    // 5. File Explorer Context Menu
    this.registerEvent(
      this.app.workspace.on("file-menu", (menu, file) => {
        if (file instanceof TFile && file.extension === "md") {
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Encrypt Entire Note")
              .setIcon("lock")
              .onClick(async () => {
                await this.encryptEntireFile(file);
              });
          });
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Decrypt Note to Plaintext")
              .setIcon("unlock")
              .onClick(async () => {
                await this.decryptEntireFile(file);
              });
          });
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Copy Note (Encrypted)")
              .setIcon("copy")
              .onClick(async () => {
                await this.copyEncryptedFile(file);
              });
          });
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard: Copy Note (Decrypted)")
              .setIcon("clipboard-check")
              .onClick(async () => {
                await this.copyDecryptedFile(file);
              });
          });
        }
      })
    );

    // 5. CodeMirror 6 Live Preview Extension
    this.registerEditorExtension(createVaultGuardViewPlugin(this));

    // 6. Markdown Post Processors (Reading View)
    registerPostProcessors(this);

    // 7. Reactive Paste Interceptor
    registerPasteHandler(this);

    // 8. Settings Tab
    this.addSettingTab(new VaultGuardSettingTab(this.app, this));

    // 9. Whole-File Encrypted Note View Manager
    this.fileViewManager = new EncryptedFileViewManager(this);
    this.fileViewManager.init();
  }

  updateStatusBar(): void {
    if (!this.statusBarItemEl) return;
    this.statusBarItemEl.empty();
    this.statusBarItemEl.addClass("vaultguard-status-bar-item");

    if (!this.settings.isInitialized) {
      this.statusBarItemEl.setText("⚠️ VaultGuard: Unconfigured");
      this.statusBarItemEl.setAttribute("title", "Click to initialize master passphrase");
      this.statusBarItemEl.onclick = () => {
        new UnlockModal(this.app, this, { mode: "init" }).open();
      };
      return;
    }

    const unlocked = this.session.isUnlocked();
    if (unlocked) {
      this.statusBarItemEl.setText("🔓 VaultGuard: Unlocked");
      this.statusBarItemEl.setAttribute("title", "Click to lock vault");
      this.statusBarItemEl.onclick = () => {
        this.session.lock();
        new Notice("🔒 VaultGuard locked.");
      };
    } else {
      this.statusBarItemEl.setText("🔒 VaultGuard: Locked");
      this.statusBarItemEl.setAttribute("title", "Click to unlock vault");
      this.statusBarItemEl.onclick = () => {
        new UnlockModal(this.app, this, { mode: "unlock" }).open();
      };
    }
  }

  async encryptEntireFile(file: TFile): Promise<void> {
    if (!this.settings.isInitialized) {
      new UnlockModal(this.app, this, { mode: "init" }).open();
      return;
    }
    if (!this.session.isUnlocked()) {
      new UnlockModal(this.app, this, {
        mode: "unlock",
        onSuccess: () => this.encryptEntireFile(file),
      }).open();
      return;
    }

    const content = await this.app.vault.read(file);
    if (isWholeFileEncrypted(content)) {
      new Notice(`Note "${file.basename}" is already fully encrypted with VaultGuard.`);
      return;
    }

    new EncryptFileModal(this.app, this, {
      file,
      content,
    }).open();
  }

  async decryptEntireFile(file: TFile): Promise<void> {
    if (!this.settings.isInitialized) {
      new UnlockModal(this.app, this, { mode: "init" }).open();
      return;
    }
    if (!this.session.isUnlocked()) {
      new UnlockModal(this.app, this, {
        mode: "unlock",
        onSuccess: () => this.decryptEntireFile(file),
      }).open();
      return;
    }

    const content = await this.app.vault.read(file);
    const payload = extractWholeFilePayload(content);
    if (!payload) {
      new Notice(`Note "${file.basename}" is not an encrypted note.`);
      return;
    }

    const confirmed = await confirmAction(this.app, {
      title: "Decrypt Note to Plaintext",
      message: `Permanently decrypt note "${file.basename}" back to unencrypted plaintext Markdown?`,
      confirmText: "Decrypt Note",
      danger: true,
    });
    if (!confirmed) {
      return;
    }

    try {
      const plaintext = await this.session.decryptSecret(payload);
      await this.app.vault.modify(file, plaintext);
      new Notice(`🔓 Note "${file.basename}" decrypted back to plaintext.`);
    } catch (err: any) {
      new Notice(`Failed to decrypt note: ${err.message}`);
    }
  }

  async copyEncryptedFile(file: TFile): Promise<void> {
    const content = await this.app.vault.read(file);
    if (isWholeFileEncrypted(content)) {
      await navigator.clipboard.writeText(content);
      new Notice(`📦 Copied encrypted note ciphertext to clipboard.`);
    } else {
      if (!this.settings.isInitialized) {
        new UnlockModal(this.app, this, { mode: "init" }).open();
        return;
      }
      if (!this.session.isUnlocked()) {
        new UnlockModal(this.app, this, {
          mode: "unlock",
          onSuccess: () => this.copyEncryptedFile(file),
        }).open();
        return;
      }
      try {
        const encrypted = await this.session.encryptSecret(content, file.basename, true, true);
        await navigator.clipboard.writeText(encrypted);
        new Notice(`📦 Encrypted note and copied ciphertext to clipboard.`);
      } catch (err: any) {
        new Notice(`Failed to encrypt note: ${err.message}`);
      }
    }
  }

  async copyDecryptedFile(file: TFile): Promise<void> {
    const content = await this.app.vault.read(file);
    const payload = extractWholeFilePayload(content);
    if (!payload) {
      await navigator.clipboard.writeText(content);
      new Notice(`📋 Copied note content to clipboard.`);
      return;
    }

    if (!this.session.isUnlocked()) {
      new UnlockModal(this.app, this, {
        mode: "unlock",
        onSuccess: () => this.copyDecryptedFile(file),
      }).open();
      return;
    }

    try {
      const plaintext = await this.session.decryptSecret(payload);
      await VaultGuardClipboard.writeSecret(plaintext, {
        timeoutSeconds: this.settings.clipboardWipeTimeoutSeconds,
      });
      new Notice(`📋 Decrypted note copied (auto-wipes in ${this.settings.clipboardWipeTimeoutSeconds}s).`);
    } catch (err: any) {
      new Notice(`Failed to decrypt note: ${err.message}`);
    }
  }

  onunload() {
    // Clean up whole-file encrypted banners and view states
    if (this.fileViewManager) {
      this.fileViewManager.destroy();
    }
    // Purge in-memory key on plugin unload
    this.session.lock();
    VaultGuardClipboard.cancelAutoWipe();
  }

  async loadSettings() {
    this.settings = Object.assign({}, DEFAULT_SETTINGS, await this.loadData());
  }

  async saveSettings() {
    await this.saveData(this.settings);
  }
}
