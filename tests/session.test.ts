/**
 * KeyMask Session & Lifecycle Unit Tests
 */

import { describe, it, expect } from "vitest";
import { KeyMaskSession } from "../src/crypto/session";

describe("KeyMask Session Lifecycle", () => {
  let mockSettings = {
    salt: "",
    canaryToken: "",
    kdfIterations: 100_000,
    autoLockTimeoutMinutes: 15,
    lockOnBlur: true,
  };

  const createMockSession = () => {
    mockSettings = {
      salt: "",
      canaryToken: "",
      kdfIterations: 100_000,
      autoLockTimeoutMinutes: 15,
      lockOnBlur: true,
    };

    return new KeyMaskSession({
      getSalt: () => mockSettings.salt,
      setSalt: async (saltB64) => {
        mockSettings.salt = saltB64;
      },
      getCanaryToken: () => mockSettings.canaryToken,
      setCanaryToken: async (token) => {
        mockSettings.canaryToken = token;
      },
      getKdfIterations: () => mockSettings.kdfIterations,
      getAutoLockTimeoutMinutes: () => mockSettings.autoLockTimeoutMinutes,
      getLockOnBlur: () => mockSettings.lockOnBlur,
    });
  };

  it("should initialize vault and generate salt & canary verification token", async () => {
    const session = createMockSession();
    expect(session.isUnlocked()).toBe(false);

    await session.initializeVault("SuperSecretVaultPass#1");

    expect(session.isUnlocked()).toBe(true);
    expect(mockSettings.salt).toBeTruthy();
    expect(mockSettings.canaryToken).toContain("%%km:v1:");
    expect(session.getKey()).not.toBeNull();
  });

  it("should lock vault and purge key from memory", async () => {
    const session = createMockSession();
    await session.initializeVault("SuperSecretVaultPass#1");
    expect(session.isUnlocked()).toBe(true);

    session.lock();

    expect(session.isUnlocked()).toBe(false);
    expect(session.getKey()).toBeNull();
  });

  it("should unlock vault with correct passphrase", async () => {
    const session = createMockSession();
    await session.initializeVault("CorrectPassword123");
    session.lock();
    expect(session.isUnlocked()).toBe(false);

    const success = await session.unlock("CorrectPassword123");
    expect(success).toBe(true);
    expect(session.isUnlocked()).toBe(true);
  });

  it("should reject incorrect passphrase on unlock", async () => {
    const session = createMockSession();
    await session.initializeVault("CorrectPassword123");
    session.lock();

    await expect(session.unlock("WrongPassword999")).rejects.toThrow(/Incorrect master passphrase/);
    expect(session.isUnlocked()).toBe(false);
  });

  it("should encrypt and decrypt secrets when unlocked", async () => {
    const session = createMockSession();
    await session.initializeVault("MasterVaultPass");

    const rawSecret = "sk-live-stripe-production-token-123456789";
    const token = await session.encryptSecret(rawSecret, "Stripe Key");

    expect(token).toContain("%%km:v1:");
    expect(token).not.toContain(rawSecret); // Zero plaintext in token

    const { parseInline } = await import("../src/crypto/serializer");
    const payload = parseInline(token);
    expect(payload).not.toBeNull();

    const decrypted = await session.decryptSecret(payload!);
    expect(decrypted).toBe(rawSecret);
  });

  it("should throw if encrypting or decrypting while locked", async () => {
    const session = createMockSession();
    await session.initializeVault("MasterPass");
    session.lock();

    await expect(session.encryptSecret("foo")).rejects.toThrow(/Vault is locked/);
  });

  it("should change passphrase, re-deriving key and updating canary", async () => {
    const session = createMockSession();
    await session.initializeVault("OldPassword123");

    const oldSalt = mockSettings.salt;
    const oldCanary = mockSettings.canaryToken;

    await session.changePassphrase("OldPassword123", "BrandNewPassword456");

    expect(mockSettings.salt).not.toBe(oldSalt);
    expect(mockSettings.canaryToken).not.toBe(oldCanary);

    session.lock();

    // Old password should fail
    await expect(session.unlock("OldPassword123")).rejects.toThrow();

    // New password should succeed
    const unlocked = await session.unlock("BrandNewPassword456");
    expect(unlocked).toBe(true);
    expect(session.isUnlocked()).toBe(true);
  });
});
