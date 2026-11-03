/**
 * VaultGuard Cryptographic Engine Unit Tests
 */

import { describe, it, expect } from "vitest";
import {
  deriveKeyFromPassphrase,
  encrypt,
  decrypt,
  generateIV,
  generateSalt,
  uint8ArrayToBase64,
  base64ToUint8Array,
  uint8ArrayToBase64Url,
  base64UrlToUint8Array,
  stringToBase64Url,
  base64UrlToString,
  AES_KEY_LENGTH,
  AES_TAG_LENGTH,
  IV_LENGTH_BYTES,
  SALT_LENGTH_BYTES,
} from "../src/crypto/engine";

describe("Cryptographic Engine", () => {
  it("should generate cryptographically secure 16-byte random salts", () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();

    expect(salt1.byteLength).toBe(SALT_LENGTH_BYTES);
    expect(salt2.byteLength).toBe(SALT_LENGTH_BYTES);
    expect(salt1).not.toEqual(salt2);
  });

  it("should generate unique 12-byte random IVs per call", () => {
    const iv1 = generateIV();
    const iv2 = generateIV();

    expect(iv1.byteLength).toBe(IV_LENGTH_BYTES);
    expect(iv2.byteLength).toBe(IV_LENGTH_BYTES);
    expect(iv1).not.toEqual(iv2);
  });

  it("should derive non-extractable AES-256-GCM key from passphrase", async () => {
    const salt = generateSalt();
    // Using 100,000 for fast test suite execution
    const key = await deriveKeyFromPassphrase("SuperSecretPassphrase123!", salt, 100_000);

    expect(key).toBeDefined();
    expect(key.algorithm.name).toBe("AES-GCM");
    expect(key.extractable).toBe(false); // Strictly non-extractable
    expect(key.usages).toContain("encrypt");
    expect(key.usages).toContain("decrypt");
  });

  it("should encrypt and decrypt plaintext using AES-256-GCM", async () => {
    const salt = generateSalt();
    const key = await deriveKeyFromPassphrase("MasterVaultKey!#2026", salt, 100_000);
    const plaintext = "sk-proj-super-confidential-openai-api-key-test-value";

    const encrypted = await encrypt(plaintext, key);

    expect(encrypted.iv.byteLength).toBe(IV_LENGTH_BYTES);
    expect(encrypted.tag.byteLength).toBe(AES_TAG_LENGTH / 8); // 16 bytes
    expect(encrypted.data.byteLength).toBeGreaterThan(0);

    const decrypted = await decrypt(encrypted, key);
    expect(decrypted).toBe(plaintext);
  });

  it("should fail decryption when ciphertext is tampered (integrity tag mismatch)", async () => {
    const salt = generateSalt();
    const key = await deriveKeyFromPassphrase("Passphrase123", salt, 100_000);
    const plaintext = "DatabasePassword#991!";

    const encrypted = await encrypt(plaintext, key);

    // Tamper single byte of ciphertext data
    const tamperedData = new Uint8Array(encrypted.data);
    tamperedData[0] ^= 0xff;

    await expect(
      decrypt(
        {
          iv: encrypted.iv,
          data: tamperedData,
          tag: encrypted.tag,
        },
        key
      )
    ).rejects.toThrow(/Decryption failed/);
  });

  it("should fail decryption when authentication tag is tampered", async () => {
    const salt = generateSalt();
    const key = await deriveKeyFromPassphrase("Passphrase123", salt, 100_000);
    const plaintext = "StripeSecretKey_rk_live_998877";

    const encrypted = await encrypt(plaintext, key);

    // Tamper tag
    const tamperedTag = new Uint8Array(encrypted.tag);
    tamperedTag[0] ^= 0xff;

    await expect(
      decrypt(
        {
          iv: encrypted.iv,
          data: encrypted.data,
          tag: tamperedTag,
        },
        key
      )
    ).rejects.toThrow(/Decryption failed/);
  });

  it("should fail decryption when wrong key is supplied", async () => {
    const salt = generateSalt();
    const key1 = await deriveKeyFromPassphrase("CorrectPassphrase", salt, 100_000);
    const key2 = await deriveKeyFromPassphrase("WrongPassphrase", salt, 100_000);

    const encrypted = await encrypt("SecretData", key1);

    await expect(decrypt(encrypted, key2)).rejects.toThrow(/Decryption failed/);
  });

  describe("Base64 & Base64URL Helpers", () => {
    it("should roundtrip binary data with standard Base64", () => {
      const bytes = new Uint8Array([0, 15, 255, 128, 64, 32, 16, 8, 4, 2, 1]);
      const b64 = uint8ArrayToBase64(bytes);
      const restored = base64ToUint8Array(b64);
      expect(restored).toEqual(bytes);
    });

    it("should roundtrip binary data with URL-safe Base64 without + / =", () => {
      // Test bytes that would produce + and / in standard base64
      const bytes = new Uint8Array([251, 239, 255, 254, 253, 252]);
      const b64url = uint8ArrayToBase64Url(bytes);

      expect(b64url).not.toContain("+");
      expect(b64url).not.toContain("/");
      expect(b64url).not.toContain("=");

      const restored = base64UrlToUint8Array(b64url);
      expect(restored).toEqual(bytes);
    });

    it("should roundtrip UTF-8 string to base64url and back", () => {
      const original = "Stripe Live Secret Key (Production EU) 🚀";
      const encoded = stringToBase64Url(original);
      const decoded = base64UrlToString(encoded);
      expect(decoded).toBe(original);
    });
  });
});
