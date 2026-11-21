# KeyMask for Obsidian

> **Zero-Plaintext Credential Protection & Interactive UI Masking for Sensitive Secrets**

[![Compatible with Obsidian](https://img.shields.io/badge/Obsidian-1.5.0%2B-purple.svg)](https://obsidian.md)
[![Platforms](https://img.shields.io/badge/Platforms-Desktop%20%7C%20Mobile-blue.svg)](https://obsidian.md)
[![Encryption](https://img.shields.io/badge/Security-AES--256--GCM-green.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![License](https://img.shields.io/badge/License-MIT-orange.svg)](LICENSE)

Do you keep OpenAI/Anthropic API keys, database connection strings, personal access tokens, or sensitive passwords in your Obsidian notes? 

In typical Obsidian setups, secrets are stored in raw plaintext Markdown files. This exposes your credentials to:
- **Cloud Sync & Git History**: Plaintext secrets get synced to remote servers, backups, and Git commits.
- **Screen Sharing & Over-the-Shoulder Leaks**: Sensitive tokens stay visible on screen during video calls and meetings.
- **Clipboard History**: Copied credentials linger in OS clipboard managers indefinitely.
- **Untrusted Plugins**: Any community plugin with vault access can read plaintext notes.

**KeyMask** solves this by encrypting sensitive secrets with **AES-256-GCM** and replacing them in your editor with interactive, beautiful UI pills. Secrets stay encrypted on disk and in memory until you need them.

---

## ✨ What Makes KeyMask Special?

### 1. 🎭 Interactive UI Masking
Secrets render as clean, elegant UI pills in both **Live Preview** and **Reading View**:

```text
[ 🔑 OpenAI API Key  ••••••••••••••••••••  |  📋 Copy  |  👁️  ]
```

- **Single-Click Reveal**: Click the value or eye icon to unmask for 5 seconds.
- **Visual Countdown Ring**: An animated circular timer shows remaining visibility before auto-locking.
- **Auto-Snapback**: Masks immediately on editor blur, window change, or timeout.

### 2. ⚡ Reactive Paste Interceptor
Copy-pasting an API key or database credential into your note? KeyMask automatically recognizes sensitive token patterns (OpenAI, Anthropic, GitHub, AWS, Stripe, Database URIs, SSH keys) and immediately displays an interception prompt:
- **[ 🔒 Encrypt & Mask to Note ]** — Encrypts before the plaintext ever touches your note buffer or undo/redo history!
- **[ ⚠️ Paste Unprotected ]** — For non-sensitive false positives.

### 3. 🔍 Vault Secret Scanner (Find & Fix Leaks)
Scan your entire vault or specific folders in seconds to find any exposed API keys, passwords, or tokens that were already saved in plaintext:
- Review findings in a clean grouped table with localized line snippets.
- **One-Click Batch Encryption**: Remediate all exposed secrets in place without disrupting note formatting.

### 4. 📋 Ephemeral Self-Destructing Clipboard
Need to copy a password or API key?
- KeyMask decrypts the token directly to the system clipboard on demand.
- **Excludes Clipboard Managers**: Sets volatile metadata flags (`org.nspasteboard.ConcealedType` on macOS and clipboard exclusion flags on Windows) so managers like Raycast, Alfred, and 1Password ignore the secret.
- **Auto-Wipe Timer**: Clears the secret from your clipboard after a configurable timeout (default 30 seconds).

### 5. 📄 Full Note Encryption
Need to secure an entire note rather than individual tokens? Convert any note into a full AES-256-GCM encrypted document with zero plaintext at rest.

### 6. 🔓 Zero Vendor Lock-In & Offline Recovery
Your data is always yours:
- **Export to Password Managers**: Export vault secrets to KeePass 2.x XML (compatible with MacPass, KeePassXC) or universal CSV (1Password, Bitwarden).
- **Batch Decrypt (Offboarding)**: Revert all encrypted tokens across your vault back into standard Markdown with one click.
- **Offline HTML Recovery Tool**: Includes an offline, standalone single-file decryptor (`keymask-standalone-decryptor.html`) you can run in any browser without Obsidian installed.

---

## 🚀 Quick Start Guide

### Step 1: Set Your Master Passphrase
1. Open Obsidian. Click the **KeyMask icon** in the left ribbon or status bar.
2. Enter your master passphrase to initialize your vault.
3. KeyMask derives a strong **AES-256-GCM** key using PBKDF2 with 600,000 iterations.

---

### Step 2: Add Secrets to Your Notes

You can protect secrets using any of three simple methods:

- **Method A: Quick Insert Dialog**
  Open the Command Palette (`Cmd/Ctrl + P`) → **`KeyMask: Insert Encrypted Secret`**.
  Enter your secret and an optional label (e.g. `Production OpenAI Key`). KeyMask inserts the masked token directly into your active note.

- **Method B: Highlight & Encrypt**
  Highlight any sensitive text in an existing note → **Right-click** → **`KeyMask: Encrypt Selected Text`**.

- **Method C: Automatic Paste Detection**
  Simply paste an API key (e.g. `sk-...` or `ghp_...`). KeyMask detects the token pattern and offers to encrypt it instantly.

---

### Step 3: View & Use Your Secrets

- **To Peek**: Click the eye icon or masked text. An animated 5-second countdown ring appears, then snaps back to masked state automatically.
- **To Copy**: Click **📋 Copy**. The decrypted value is copied to your clipboard and auto-wiped after 30 seconds.
- **To Lock**: Click the status bar item or run **`KeyMask: Lock Vault`** to purge the encryption key from memory immediately.

---

## 🔍 Supported Token Detectors

KeyMask includes high-performance built-in detectors for:
- **OpenAI**: `sk-...`, `sk-proj-...`
- **Anthropic Claude**: `sk-ant-...`
- **GitHub**: Personal Access Tokens (`ghp_...`, `github_pat_...`)
- **AWS**: Access Key IDs (`AKIA...`)
- **Stripe**: Live & Restricted Secret Keys (`sk_live_...`, `rk_live_...`)
- **Database URIs**: PostgreSQL, MySQL, MongoDB, Redis connection strings
- **Private Keys**: RSA, EC, OpenSSH, PGP Private Keys (`BEGIN PRIVATE KEY`)
- **JSON Web Tokens (JWT)**: `Bearer eyJ...`

---

## ⌨️ Command Palette Shortcuts

Open the Command Palette (`Cmd/Ctrl + P`) to access KeyMask commands anytime. You can also assign custom hotkeys in **Settings → Hotkeys**:

| Command | Action |
| :--- | :--- |
| **`KeyMask: Insert Encrypted Secret`** | Opens modal to encrypt and insert a new credential |
| **`KeyMask: Encrypt Selected Text`** | Encrypts highlighted text in the active editor |
| **`KeyMask: Audit Vault for Plaintext Secrets`** | Scans notes for exposed credentials and batch-encrypts them |
| **`KeyMask: Unlock Vault`** | Prompts for master passphrase to enable decryption |
| **`KeyMask: Lock Vault`** | Purges in-memory encryption key immediately |
| **`KeyMask: Clear Ephemeral Clipboard Now`** | Manually clears any secret copied to clipboard |
| **`KeyMask: Export Secrets (KeePass XML / CSV)`** | Exports secrets to KeePass, 1Password, or Bitwarden |
| **`KeyMask: Decrypt All Notes (De-escalate Vault)`** | Restores all encrypted notes back to plain Markdown |

---

## ⚙️ Configuration & Preferences

In Obsidian **Settings → KeyMask**, you can configure:
- **Inactivity Timeout**: Automatically locks the vault after $N$ minutes of idle time.
- **Lock on App Blur**: Locks the vault whenever Obsidian is minimized or you switch apps.
- **Reveal Countdown**: Number of seconds a secret stays visible before auto-hiding (default: 5s).
- **Clipboard Auto-Wipe Timeout**: Number of seconds before the clipboard is wiped (default: 30s).
- **Paste Interceptor**: Toggle reactive detection on or off.

---

## 🔒 Security Architecture

For security audits and technical verification:
- **Cipher**: AES-256-GCM authenticated encryption with 128-bit authentication tags.
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations and a 16-byte random per-vault salt.
- **Non-Extractable Keys**: CryptoKey objects are stored with `extractable: false` in WebCrypto memory.
- **No Remote Telemetry**: KeyMask makes zero external network requests. All encryption and scanning happen locally on your device.
- **Open Source**: MIT licensed. Fully auditable codebase.

---

## 🏢 About Devinova Nexus

**Nexus** is where Devinova developers build focused software, developer tools, and productivity plugins. We specialize in local-first tooling, zero-knowledge privacy systems, and extensions for platforms like Obsidian, VS Code, and IDEs.

- 🌐 **Nexus Portal:** [nexus.devinova.in](https://nexus.devinova.in/)
- 🏢 **Parent Company:** [devinova.in](https://devinova.in/)
- 🐙 **GitHub:** [github.com/DevinovaNexus](https://github.com/DevinovaNexus)
- ✉️ **Contact:** contact@devinova.in
