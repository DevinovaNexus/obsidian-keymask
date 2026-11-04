/**
 * VaultGuard Configuration & Settings Tab
 */

import { App, PluginSettingTab, Setting, Notice } from "obsidian";
import type VaultGuardPlugin from "./main";
import { UnlockModal } from "./modals/unlockModal";
import { VaultAuditModal } from "./modals/vaultAuditModal";
import { ExportSecretsModal } from "./modals/exportSecretsModal";
import { BatchDecryptModal } from "./modals/batchDecryptModal";

export interface VaultGuardSettings {
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

export const DEFAULT_SETTINGS: VaultGuardSettings = {
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

export class VaultGuardSettingTab extends PluginSettingTab {
  plugin: VaultGuardPlugin;

  constructor(app: App, plugin: VaultGuardPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();

    containerEl.createEl("h2", { text: "VaultGuard Settings" });

    // 1. Vault Status Banner
    const statusDiv = containerEl.createDiv({ cls: "vaultguard-status-banner" });
    const isUnlocked = this.plugin.session.isUnlocked();
    const isInitialized = this.plugin.settings.isInitialized;

    if (!isInitialized) {
      statusDiv.createEl("div", {
        cls: "vaultguard-status-pill unconfigured",
        text: "⚠️ Vault Not Initialized",
      });
      statusDiv.createEl("p", {
        cls: "setting-item-description",
        text: "Please initialize VaultGuard with a master passphrase to secure your credentials.",
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
                onSuccess: () => this.display(),
              }).open();
            })
        );
    } else {
      const statusText = isUnlocked ? "🔓 Vault Unlocked" : "🔒 Vault Locked";
      const statusCls = isUnlocked ? "unlocked" : "locked";

      statusDiv.createEl("div", {
        cls: `vaultguard-status-pill ${statusCls}`,
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
              .setWarning()
              .onClick(() => {
                this.plugin.session.lock();
                new Notice("VaultGuard locked.");
                this.display();
              });
          } else {
            button
              .setButtonText("Unlock Vault")
              .setCta()
              .onClick(() => {
                new UnlockModal(this.app, this.plugin, {
                  mode: "unlock",
                  onSuccess: () => this.display(),
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
                this.display();
              },
            }).open();
          })
        );
    }

    // 2. Session & Auto-Lock Options
    containerEl.createEl("h3", { text: "Session & Key Lifecycle" });

    new Setting(containerEl)
      .setName("Auto-Lock Inactivity Timeout")
      .setDesc("Minutes of idle inactivity before purging the in-memory key (0 to disable).")
      .addSlider((slider) =>
        slider
          .setLimits(0, 120, 5)
          .setValue(this.plugin.settings.autoLockTimeoutMinutes)
          .setDynamicTooltip()
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
    containerEl.createEl("h3", { text: "Interactive Masking & Clipboard" });

    new Setting(containerEl)
      .setName("Click-to-Reveal Timeout")
      .setDesc("Seconds before unmasked secrets automatically snap back to masked state.")
      .addSlider((slider) =>
        slider
          .setLimits(3, 30, 1)
          .setValue(this.plugin.settings.revealTimeoutSeconds)
          .setDynamicTooltip()
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
          .setDynamicTooltip()
          .onChange(async (val) => {
            this.plugin.settings.clipboardWipeTimeoutSeconds = val;
            await this.plugin.saveSettings();
          })
      );

    // 4. Reactive Leak Prevention
    containerEl.createEl("h3", { text: "Reactive Leak Prevention" });

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
    containerEl.createEl("h3", { text: "Vault Security Audit & Leak Scanner" });

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
    containerEl.createEl("h3", { text: "Data Ownership, Portability & Offboarding" });

    containerEl.createEl("p", {
      cls: "setting-item-description",
      text: "VaultGuard enforces zero vendor lock-in. If you ever plan to disable or remove the plugin, you can export your secrets to an external password manager or restore all your notes back to plaintext.",
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
      .setDesc("Batch decrypt all VaultGuard tokens in your notes back into raw Markdown text. Use this before disabling or uninstalling VaultGuard if you want your notes unencrypted.")
      .addButton((button) =>
        button
          .setButtonText("Revert All to Plaintext")
          .setWarning()
          .onClick(() => {
            new BatchDecryptModal(this.app, this.plugin).open();
          })
      );

    // 7. Danger Zone / Vault Reset
    if (isInitialized) {
      containerEl.createEl("h3", { text: "Advanced / Danger Zone" });

      new Setting(containerEl)
        .setName("Reset VaultGuard Configuration")
        .setDesc(
          "Warning: Clears the master salt and verification canary. Existing encrypted tokens in notes will become indecipherable unless you know the previous passphrase."
        )
        .addButton((button) =>
          button
            .setButtonText("Reset Vault Configuration")
            .setWarning()
            .onClick(async () => {
              const confirm = window.confirm(
                "Are you sure you want to reset VaultGuard? Any secrets encrypted with the current key cannot be decrypted without the original salt and passphrase!"
              );
              if (confirm) {
                this.plugin.settings.isInitialized = false;
                this.plugin.settings.salt = "";
                this.plugin.settings.canaryToken = "";
                await this.plugin.saveSettings();
                this.plugin.session.lock();
                new Notice("VaultGuard configuration has been reset.");
                this.display();
              }
            })
        );
    }
  }
}
