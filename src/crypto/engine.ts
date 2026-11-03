/**
 * VaultGuard Cryptographic Engine
 *
 * Implements:
 * - PBKDF2-HMAC-SHA256 key derivation (>= 600,000 iterations)
 * - AES-256-GCM authenticated symmetric encryption
 * - 128-bit authentication tags
 * - 12-byte cryptographically secure random nonces (IVs) per operation
 * - 16-byte cryptographically secure random salt
 * - Non-extractable CryptoKey storage
 * - W3C Web Cryptography API compliance (cross-platform desktop & mobile)
 */

export const CANARY_PLAINTEXT = "VAULTGUARD_CANARY_V1";
export const DEFAULT_KDF_ITERATIONS = 600_000;
export const AES_KEY_LENGTH = 256;
export const AES_TAG_LENGTH = 128; // in bits (16 bytes)
export const IV_LENGTH_BYTES = 12;
export const SALT_LENGTH_BYTES = 16;

export interface EncryptedData {
  iv: Uint8Array;
  data: Uint8Array;
  tag: Uint8Array;
}

/**
 * Returns the Web Crypto SubtleCrypto instance across environments
 */
export function getSubtleCrypto(): SubtleCrypto {
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    return window.crypto.subtle;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error("Web Cryptography API (crypto.subtle) is not available in this environment.");
}

/**
 * Generate a cryptographically secure random salt (16 bytes)
 */
export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(SALT_LENGTH_BYTES);
  const cryptoObj = (typeof window !== "undefined" && window.crypto) || globalThis.crypto;
  cryptoObj.getRandomValues(salt);
  return salt;
}

/**
 * Generate a cryptographically secure random nonce/IV (12 bytes)
 */
export function generateIV(): Uint8Array {
  const iv = new Uint8Array(IV_LENGTH_BYTES);
  const cryptoObj = (typeof window !== "undefined" && window.crypto) || globalThis.crypto;
  cryptoObj.getRandomValues(iv);
  return iv;
}

/**
 * Derives a non-extractable AES-256-GCM CryptoKey from a master passphrase and salt
 * using PBKDF2-HMAC-SHA256 with >= 600,000 iterations.
 */
export async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = DEFAULT_KDF_ITERATIONS
): Promise<CryptoKey> {
  if (!passphrase) {
    throw new Error("Passphrase cannot be empty.");
  }
  if (salt.byteLength < SALT_LENGTH_BYTES) {
    throw new Error(`Salt must be at least ${SALT_LENGTH_BYTES} bytes.`);
  }
  if (iterations < 100_000) {
    throw new Error("KDF iterations too low. Minimum is 100,000 (recommended >= 600,000).");
  }

  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();
  const passphraseBytes = encoder.encode(passphrase);

  // 1. Import passphrase as raw key material for PBKDF2
  const baseKey = await subtle.importKey(
    "raw",
    passphraseBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  // 2. Derive non-extractable AES-256-GCM key
  const derivedKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: iterations,
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: AES_KEY_LENGTH,
    },
    false, // extractable: false (strictly non-extractable in memory)
    ["encrypt", "decrypt"]
  );

  return derivedKey;
}

/**
 * Encrypt plaintext using AES-256-GCM.
 * Generates a fresh 12-byte IV per encryption operation.
 * Returns iv, ciphertext, and 16-byte authentication tag separately.
 */
export async function encrypt(
  plaintext: string,
  key: CryptoKey,
  customIV?: Uint8Array
): Promise<EncryptedData> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(plaintext);
  const iv = customIV ?? generateIV();

  // subtle.encrypt in AES-GCM appends the authentication tag (16 bytes) at the end
  const encryptedBuffer = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      tagLength: AES_TAG_LENGTH,
    },
    key,
    plaintextBytes
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const tagLengthBytes = AES_TAG_LENGTH / 8; // 16 bytes
  const dataLength = encryptedBytes.byteLength - tagLengthBytes;

  const data = encryptedBytes.slice(0, dataLength);
  const tag = encryptedBytes.slice(dataLength);

  return {
    iv,
    data,
    tag,
  };
}

/**
 * Decrypt ciphertext and verify 128-bit authentication tag using AES-256-GCM.
 * Throws an error if the authentication tag fails or data is corrupted.
 */
export async function decrypt(
  encrypted: EncryptedData,
  key: CryptoKey
): Promise<string> {
  const subtle = getSubtleCrypto();

  // Re-combine data and authentication tag into a single buffer as required by subtle.decrypt
  const combined = new Uint8Array(encrypted.data.byteLength + encrypted.tag.byteLength);
  combined.set(encrypted.data, 0);
  combined.set(encrypted.tag, encrypted.data.byteLength);

  try {
    const decryptedBuffer = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: encrypted.iv as BufferSource,
        tagLength: AES_TAG_LENGTH,
      },
      key,
      combined as BufferSource
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (err) {
    throw new Error("Decryption failed: integrity check or authentication tag mismatch. Data may be corrupted or key incorrect.");
  }
}

/**
 * Base64 and Base64URL Conversion Helpers
 */

export function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToUint8Array(base64: string): Uint8Array {
  // Normalize base64url if needed
  let normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  while (normalized.length % 4 !== 0) {
    normalized += "=";
  }
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  return uint8ArrayToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlToUint8Array(base64url: string): Uint8Array {
  return base64ToUint8Array(base64url);
}

export function stringToBase64Url(str: string): string {
  const encoder = new TextEncoder();
  return uint8ArrayToBase64Url(encoder.encode(str));
}

export function base64UrlToString(base64url: string): string {
  const bytes = base64UrlToUint8Array(base64url);
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}
