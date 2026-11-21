/**
 * KeyMask Configuration & Settings Tab
 */

import { App, PluginSettingTab, Setting, Notice, SettingDefinitionItem } from "obsidian";
import type KeyMaskPlugin from "./main";
import { UnlockModal } from "./modals/unlockModal";
import { VaultAuditModal } from "./modals/vaultAuditModal";
import { ExportSecretsModal } from "./modals/exportSecretsModal";
import { BatchDecryptModal } from "./modals/batchDecryptModal";
import { confirmAction } from "./modals/confirmModal";

export interface KeyMaskSettings {
  isInitialized: boolean;
  salt: string;
  kdfIterations: number;
  canaryToken: string;
  autoLockTimeoutMinutes: number;
  lockOnBlur: boolean;
  revealTimeoutSeconds: number;
  clipboardWipeTimeoutSeconds: number;
  interceptPaste: boolean;
}

export const DEFAULT_SETTINGS: KeyMaskSettings = {
  isInitialized: false,
  salt: "",
  kdfIterations: 600_000,
  canaryToken: "",
  autoLockTimeoutMinutes: 15,
  lockOnBlur: true,
  revealTimeoutSeconds: 5,
  clipboardWipeTimeoutSeconds: 30,
  interceptPaste: true,
};

export class KeyMaskSettingTab extends PluginSettingTab {
  plugin: KeyMaskPlugin;

  constructor(app: App, plugin: KeyMaskPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  getSettingDefinitions(): SettingDefinitionItem[] {
    return [];
  }

  private refresh(): void {
    this.display();
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    new Setting(containerEl).setName("Security & Vault Status").setHeading();

    // 1. Vault Status Banner
    const statusDiv = containerEl.createDiv({ cls: "keymask-status-banner" });
    const isUnlocked = this.plugin.session.isUnlocked();
    const isInitialized = this.plugin.settings.isInitialized;

    if (!isInitialized) {
      statusDiv.createDiv({
        cls: "keymask-status-pill unconfigured",
        text: "⚠️ Vault Not Initialized",
      });
      statusDiv.createEl("p", {
        cls: "setting-item-description",
        text: "Please initialize KeyMask with a master passphrase to secure your credentials.",
      });

      new Setting(containerEl)
        .setName("Initialize Master Passphrase")
        .setDesc("Derive the master AES-256-GCM encryption key and initialize your vault.")
        .addButton((button) =>
          button
            .setButtonText("Set Master Passphrase")
            .setCta()
            .onClick(() => {
              new UnlockModal(this.app, this.plugin, {
                mode: "init",
                onSuccess: () => this.refresh(),
              }).open();
            })
        );
    } else {
      const statusText = isUnlocked ? "🔓 Vault Unlocked" : "🔒 Vault Locked";
      const statusCls = isUnlocked ? "unlocked" : "locked";

      statusDiv.createDiv({
        cls: `keymask-status-pill ${statusCls}`,
        text: statusText,
      });

      new Setting(containerEl)
        .setName(isUnlocked ? "Lock Vault" : "Unlock Vault")
        .setDesc(
          isUnlocked
            ? "Purge in-memory decryption key immediately."
            : "Authenticate with your master passphrase to enable decryption."
        )
        .addButton((button) => {
          if (isUnlocked) {
            button
              .setButtonText("Lock Vault Now")
              .setClass("mod-warning")
              .onClick(() => {
                this.plugin.session.lock();
                new Notice("KeyMask locked.");
                this.refresh();
              });
          } else {
            button
              .setButtonText("Unlock Vault")
              .setCta()
              .onClick(() => {
                new UnlockModal(this.app, this.plugin, {
                  mode: "unlock",
                  onSuccess: () => this.refresh(),
                }).open();
              });
          }
        });

      new Setting(containerEl)
        .setName("Change Master Passphrase")
        .setDesc("Update master passphrase and re-generate vault verification canary.")
        .addButton((button) =>
          button.setButtonText("Change Passphrase").onClick(() => {
            new UnlockModal(this.app, this.plugin, {
              mode: "change",
              onSuccess: () => {
                new Notice("Master passphrase changed successfully.");
                this.refresh();
              },
            }).open();
          })
        );
    }

    // 2. Session & Auto-Lock Options
    new Setting(containerEl).setName("Session & Key Lifecycle").setHeading();

    new Setting(containerEl)
      .setName("Auto-Lock Inactivity Timeout")
      .setDesc("Minutes of idle inactivity before purging the in-memory key (0 to disable).")
      .addSlider((slider) =>
        slider
          .setLimits(0, 120, 5)
          .setValue(this.plugin.settings.autoLockTimeoutMinutes)
          .onChange(async (val) => {
            this.plugin.settings.autoLockTimeoutMinutes = val;
            await this.plugin.saveSettings();
            this.plugin.session.recordActivity();
          })
      );

    new Setting(containerEl)
      .setName("Lock on App Blur / Suspension")
      .setDesc(
        "Instantly lock vault when Obsidian loses window focus or is suspended in the background (recommended for mobile & screen-shares)."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.lockOnBlur)
          .onChange(async (val) => {
            this.plugin.settings.lockOnBlur = val;
            await this.plugin.saveSettings();
          })
      );

    // 3. UI & Masking Options
    new Setting(containerEl).setName("Interactive Masking & Clipboard").setHeading();

    new Setting(containerEl)
      .setName("Click-to-Reveal Timeout")
      .setDesc("Seconds before unmasked secrets automatically snap back to masked state.")
      .addSlider((slider) =>
        slider
          .setLimits(3, 30, 1)
          .setValue(this.plugin.settings.revealTimeoutSeconds)
          .onChange(async (val) => {
            this.plugin.settings.revealTimeoutSeconds = val;
            await this.plugin.saveSettings();
          })
      );

    new Setting(containerEl)
      .setName("Ephemeral Clipboard Auto-Wipe")
      .setDesc("Seconds before copied secrets are securely wiped from the OS clipboard (15-60s).")
      .addSlider((slider) =>
        slider
          .setLimits(15, 60, 5)
          .setValue(this.plugin.settings.clipboardWipeTimeoutSeconds)
          .onChange(async (val) => {
            this.plugin.settings.clipboardWipeTimeoutSeconds = val;
            await this.plugin.saveSettings();
          })
      );

    // 4. Reactive Leak Prevention
    new Setting(containerEl).setName("Reactive Leak Prevention").setHeading();

    new Setting(containerEl)
      .setName("Intercept Sensitive Pastes")
      .setDesc(
        "Inspect editor paste events for OpenAI/Anthropic keys, AWS tokens, GitHub PATs, and private keys, offering one-click encryption."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.interceptPaste)
          .onChange(async (val) => {
            this.plugin.settings.interceptPaste = val;
            await this.plugin.saveSettings();
          })
      );

    // 5. Vault Security Audit & Leak Scanner
    new Setting(containerEl).setName("Vault Security Audit & Leak Scanner").setHeading();

    new Setting(containerEl)
      .setName("Audit Notes for Plaintext Secrets")
      .setDesc(
        "Inspect all existing notes or choose specific folders to detect exposed API keys, credentials, and passwords, and batch encrypt them in-place."
      )
      .addButton((button) =>
        button
          .setButtonText("Launch Secret Scanner")
          .setCta()
          .onClick(() => {
            new VaultAuditModal(this.app, this.plugin).open();
          })
      );

    // 6. Data Ownership, Portability & Offboarding
    new Setting(containerEl).setName("Data Ownership, Portability & Offboarding").setHeading();

    containerEl.createEl("p", {
      cls: "setting-item-description",
      text: "KeyMask enforces zero vendor lock-in. If you ever plan to disable or remove the plugin, you can export your secrets to an external password manager or restore all your notes back to plaintext.",
    });

    new Setting(containerEl)
      .setName("Export Secrets to KeePass / MacPass")
      .setDesc("Generate an industry-standard KeePass 2.x XML file (.xml) or universal CSV compatible with MacPass, KeePassXC, 1Password, and Bitwarden.")
      .addButton((button) =>
        button
          .setButtonText("Export Secrets File")
          .onClick(() => {
            new ExportSecretsModal(this.app, this.plugin).open();
          })
      );

    new Setting(containerEl)
      .setName("Revert Vault to Plaintext (Offboarding)")
      .setDesc("Batch decrypt all KeyMask tokens in your notes back into raw Markdown text. Use this before disabling or uninstalling KeyMask if you want your notes unencrypted.")
      .addButton((button) =>
        button
          .setButtonText("Revert All to Plaintext")
          .setClass("mod-warning")
          .onClick(() => {
            new BatchDecryptModal(this.app, this.plugin).open();
          })
      );

    // 7. Danger Zone / Vault Reset
    if (isInitialized) {
      new Setting(containerEl).setName("Advanced / Danger Zone").setHeading();

      new Setting(containerEl)
        .setName("Reset KeyMask Configuration")
        .setDesc(
          "Warning: Clears the master salt and verification canary. Existing encrypted tokens in notes will become indecipherable unless you know the previous passphrase."
        )
        .addButton((button) =>
          button
            .setButtonText("Reset Vault Configuration")
            .setClass("mod-warning")
            .onClick(async () => {
              const confirmed = await confirmAction(this.app, {
                title: "Reset KeyMask Configuration",
                message: "Are you sure you want to reset KeyMask? Any secrets encrypted with the current key cannot be decrypted without the original salt and passphrase!",
                confirmText: "Reset Configuration",
                danger: true,
              });
              if (confirmed) {
                this.plugin.settings.isInitialized = false;
                this.plugin.settings.salt = "";
                this.plugin.settings.canaryToken = "";
                await this.plugin.saveSettings();
                this.plugin.session.lock();
                new Notice("KeyMask configuration has been reset.");
                this.refresh();
              }
            })
        );
    }
  }
}
