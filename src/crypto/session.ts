/**
 * KeyMask Session & In-Memory Key Lifecycle Manager
 *
 * Requirements:
 * - Derived symmetric key resides exclusively as an in-memory, non-extractable WebCrypto object.
 * - Master passphrase and raw derived key are never written to disk, local storage, or session storage.
 * - Verifiable canary validation token verifies master passphrase entry on unlock without leaking passphrase hashes.
 * - Configurable auto-lock timeouts (default: 15 minutes of inactivity).
 * - Lock triggers on app suspension/blur.
 * - Event-driven notification system for UI updates.
 */

import {
  CANARY_PLAINTEXT,
  DEFAULT_KDF_ITERATIONS,
  EncryptedData,
  LEGACY_CANARY_PLAINTEXT,
  base64ToUint8Array,
  deriveKeyFromPassphrase,
  encrypt,
  decrypt,
  generateSalt,
  uint8ArrayToBase64,
} from "./engine";
import {
  SecretPayload,
  parseInline,
  serializeCodeBlock,
  serializeInline,
} from "./serializer";

export type SessionStateListener = (unlocked: boolean) => void;

export interface SessionConfig {
  getSalt: () => string;
  setSalt: (saltB64: string) => Promise<void>;
  getCanaryToken: () => string;
  setCanaryToken: (token: string) => Promise<void>;
  getKdfIterations: () => number;
  getAutoLockTimeoutMinutes: () => number;
  getLockOnBlur: () => boolean;
}

export class KeyMaskSession {
  private derivedKey: CryptoKey | null = null;
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;
  private listeners: Set<SessionStateListener> = new Set();
  private config: SessionConfig;
  private isSuspended = false;

  constructor(config: SessionConfig) {
    this.config = config;
    this.setupWindowListeners();
  }

  /**
   * Subscribe to lock/unlock state changes
   */
  public onStateChange(listener: SessionStateListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notifyListeners(): void {
    const unlocked = this.isUnlocked();
    for (const listener of this.listeners) {
      try {
        listener(unlocked);
      } catch (e) {
        console.error("KeyMask session listener error:", e);
      }
    }
  }

  public isUnlocked(): boolean {
    return this.derivedKey !== null;
  }

  public getKey(): CryptoKey | null {
    return this.derivedKey;
  }

  /**
   * Setup a new vault with master passphrase
   */
  public async initializeVault(passphrase: string): Promise<void> {
    if (!passphrase || passphrase.length < 4) {
      throw new Error("Master passphrase must be at least 4 characters.");
    }

    const salt = generateSalt();
    const saltB64 = uint8ArrayToBase64(salt);
    const iterations = this.config.getKdfIterations() || DEFAULT_KDF_ITERATIONS;

    const key = await deriveKeyFromPassphrase(passphrase, salt, iterations);

    // Encrypt canary verification token
    const encryptedCanary = await encrypt(CANARY_PLAINTEXT, key);
    const canaryToken = serializeInline({
      label: "CANARY",
      encrypted: encryptedCanary,
    });

    await this.config.setSalt(saltB64);
    await this.config.setCanaryToken(canaryToken);

    this.derivedKey = key;
    this.resetAutoLockTimer();
    this.notifyListeners();
  }

  /**
   * Unlock vault with master passphrase
   */
  public async unlock(passphrase: string): Promise<boolean> {
    if (!passphrase) {
      throw new Error("Passphrase cannot be empty.");
    }

    const saltB64 = this.config.getSalt();
    const canaryToken = this.config.getCanaryToken();

    if (!saltB64 || !canaryToken) {
      throw new Error("KeyMask has not been initialized. Please set up a master passphrase first.");
    }

    const salt = base64ToUint8Array(saltB64);
    const iterations = this.config.getKdfIterations() || DEFAULT_KDF_ITERATIONS;

    // Derive key candidate
    const candidateKey = await deriveKeyFromPassphrase(passphrase, salt, iterations);

    // Parse canary
    const canaryPayload = parseInline(canaryToken);
    if (!canaryPayload) {
      throw new Error("Canary verification token is corrupted.");
    }

    // Verify key by attempting to decrypt canary
    try {
      const decrypted = await decrypt(
        {
          iv: canaryPayload.iv,
          data: canaryPayload.data,
          tag: canaryPayload.tag,
        },
        candidateKey
      );

      if (decrypted !== CANARY_PLAINTEXT && decrypted !== LEGACY_CANARY_PLAINTEXT) {
        throw new Error("Invalid canary plaintext.");
      }
    } catch (err) {
      throw new Error("Incorrect master passphrase.");
    }

    // Passphrase verified!
    this.derivedKey = candidateKey;
    this.resetAutoLockTimer();
    this.notifyListeners();
    return true;
  }

  /**
   * Lock vault and purge key from memory
   */
  public lock(): void {
    if (this.derivedKey === null) return;
    this.derivedKey = null;
    this.clearAutoLockTimer();
    this.notifyListeners();
  }

  /**
   * Change master passphrase and re-encrypt the canary token
   */
  public async changePassphrase(currentPassphrase: string, newPassphrase: string): Promise<void> {
    // 1. Verify current passphrase
    await this.unlock(currentPassphrase);

    if (!newPassphrase || newPassphrase.length < 4) {
      throw new Error("New passphrase must be at least 4 characters.");
    }

    // 2. Generate new salt and derive new key
    const newSalt = generateSalt();
    const newSaltB64 = uint8ArrayToBase64(newSalt);
    const iterations = this.config.getKdfIterations() || DEFAULT_KDF_ITERATIONS;
    const newKey = await deriveKeyFromPassphrase(newPassphrase, newSalt, iterations);

    // 3. Encrypt new canary
    const encryptedCanary = await encrypt(CANARY_PLAINTEXT, newKey);
    const canaryToken = serializeInline({
      label: "CANARY",
      encrypted: encryptedCanary,
    });

    await this.config.setSalt(newSaltB64);
    await this.config.setCanaryToken(canaryToken);

    this.derivedKey = newKey;
    this.resetAutoLockTimer();
    this.notifyListeners();
  }

  /**
   * Reset in-memory key without changing settings (for testing or full reset)
   */
  public clear(): void {
    this.lock();
  }

  /**
   * Encrypt a secret using the active in-memory key
   */
  public async encryptSecret(
    plaintext: string,
    label?: string,
    asCodeBlock: boolean = false,
    isFile: boolean = false
  ): Promise<string> {
    if (!this.derivedKey) {
      throw new Error("Vault is locked. Unlock before encrypting.");
    }

    const encrypted = await encrypt(plaintext, this.derivedKey);

    if (asCodeBlock || isFile || plaintext.includes("\n")) {
      return serializeCodeBlock({ label, encrypted, isFile });
    } else {
      return serializeInline({ label, encrypted });
    }
  }

  /**
   * Decrypt a secret payload using the active in-memory key
   */
  public async decryptSecret(payload: SecretPayload): Promise<string> {
    if (!this.derivedKey) {
      throw new Error("Vault is locked. Unlock before decrypting.");
    }

    const encryptedData: EncryptedData = {
      iv: payload.iv,
      data: payload.data,
      tag: payload.tag,
    };

    return await decrypt(encryptedData, this.derivedKey);
  }

  /**
   * User activity detector: call on user interaction (clicks, keypresses, typing)
   */
  public recordActivity(): void {
    if (!this.isUnlocked()) return;
    this.resetAutoLockTimer();
  }

  private resetAutoLockTimer(): void {
    this.clearAutoLockTimer();
    const timeoutMinutes = this.config.getAutoLockTimeoutMinutes();
    if (timeoutMinutes <= 0) return; // 0 disables auto-lock

    this.autoLockTimer = setTimeout(() => {
      this.lock();
    }, timeoutMinutes * 60 * 1000);
  }

  private clearAutoLockTimer(): void {
    if (this.autoLockTimer !== null) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
  }

  private setupWindowListeners(): void {
    if (typeof window === "undefined") return;

    // Window blur / app suspension
    window.addEventListener("blur", () => {
      if (this.config.getLockOnBlur()) {
        this.lock();
      }
    });

    // Document visibility change (e.g. switching tabs or backgrounding mobile app)
    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "hidden" && this.config.getLockOnBlur()) {
          this.lock();
        }
      });
    }

    // Activity tracking on user interactions
    const activityEvents = ["keydown", "mousedown", "touchstart"];
    const handleActivity = () => this.recordActivity();
    for (const evt of activityEvents) {
      window.addEventListener(evt, handleActivity, { passive: true });
    }
  }
}
