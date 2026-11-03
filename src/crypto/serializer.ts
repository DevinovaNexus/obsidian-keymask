/**
 * VaultGuard Secret Serializer & Parser
 *
 * Handles bidirectional serialization between in-memory cryptographic structures
 * and Markdown-compatible representations:
 * 1. Inline Markdown comments: %%vg:v1:...%%
 * 2. Fenced Code Blocks: ```vaultguard ... ```
 */

import {
  EncryptedData,
  base64ToUint8Array,
  base64UrlToString,
  base64UrlToUint8Array,
  stringToBase64Url,
  uint8ArrayToBase64,
  uint8ArrayToBase64Url,
} from "./engine";

export interface SecretPayload {
  version: 1;
  label?: string;
  iv: Uint8Array;
  data: Uint8Array;
  tag: Uint8Array;
  rawText?: string;
  isCodeBlock?: boolean;
}

/**
 * Regex matching inline VaultGuard comment tokens:
 * %%vg:v1:label=<LABEL>:iv=<IV>:data=<DATA>:tag=<TAG>%%
 */
export const INLINE_SECRET_REGEX =
  /%%vg:v1:((?:(?:label|iv|data|tag)=[A-Za-z0-9_\-\/+=]*:?)+)%%/g;

/**
 * Regex matching fenced code block VaultGuard secrets:
 * ```vaultguard
 * ...
 * ```
 */
export const CODE_BLOCK_SECRET_REGEX =
  /```vaultguard\s*\n([\s\S]*?)\n```/g;

/**
 * Serialize an encrypted secret to the standard inline comment format:
 * %%vg:v1:label=<B64_LABEL>:iv=<B64_IV>:data=<B64_DATA>:tag=<B64_TAG>%%
 */
export function serializeInline(payload: {
  label?: string;
  encrypted: EncryptedData;
}): string {
  const parts: string[] = ["vg:v1"];

  if (payload.label && payload.label.trim().length > 0) {
    const encodedLabel = stringToBase64Url(payload.label.trim());
    parts.push(`label=${encodedLabel}`);
  }

  const ivB64 = uint8ArrayToBase64Url(payload.encrypted.iv);
  const dataB64 = uint8ArrayToBase64Url(payload.encrypted.data);
  const tagB64 = uint8ArrayToBase64Url(payload.encrypted.tag);

  parts.push(`iv=${ivB64}`);
  parts.push(`data=${dataB64}`);
  parts.push(`tag=${tagB64}`);

  return `%%${parts.join(":")}%%`;
}

/**
 * Parse an inline VaultGuard comment token
 */
export function parseInline(raw: string): SecretPayload | null {
  const trimmed = raw.trim();
  if (!trimmed.startsWith("%%vg:v1:") || !trimmed.endsWith("%%")) {
    return null;
  }

  // Strip %% wrappers and vg:v1: prefix
  const content = trimmed.slice(8, -2);
  const pairs = content.split(":");

  let label: string | undefined;
  let ivStr: string | undefined;
  let dataStr: string | undefined;
  let tagStr: string | undefined;

  for (const pair of pairs) {
    const eqIdx = pair.indexOf("=");
    if (eqIdx === -1) continue;
    const key = pair.slice(0, eqIdx).trim();
    const val = pair.slice(eqIdx + 1).trim();

    if (key === "label" && val) {
      try {
        label = base64UrlToString(val);
      } catch {
        label = val; // fallback
      }
    } else if (key === "iv") {
      ivStr = val;
    } else if (key === "data") {
      dataStr = val;
    } else if (key === "tag") {
      tagStr = val;
    }
  }

  if (!ivStr || !dataStr || !tagStr) {
    return null;
  }

  try {
    const iv = base64UrlToUint8Array(ivStr);
    const data = base64UrlToUint8Array(dataStr);
    const tag = base64UrlToUint8Array(tagStr);

    return {
      version: 1,
      label,
      iv,
      data,
      tag,
      rawText: trimmed,
      isCodeBlock: false,
    };
  } catch (err) {
    return null;
  }
}

/**
 * Serialize an encrypted secret to the fenced code block format:
 * ```vaultguard
 * version: 1
 * label: Production Ed25519 Private Key
 * iv: <BASE64_12_BYTE_IV>
 * tag: <BASE64_16_BYTE_TAG>
 * data: |
 *   <BASE64_CHUNKS_OF_CIPHERTEXT>
 * ```
 */
export function serializeCodeBlock(payload: {
  label?: string;
  encrypted: EncryptedData;
}): string {
  const lines: string[] = ["```vaultguard", "version: 1"];

  if (payload.label && payload.label.trim().length > 0) {
    lines.push(`label: ${payload.label.trim()}`);
  }

  const ivB64 = uint8ArrayToBase64(payload.encrypted.iv);
  const tagB64 = uint8ArrayToBase64(payload.encrypted.tag);
  const dataB64 = uint8ArrayToBase64(payload.encrypted.data);

  lines.push(`iv: ${ivB64}`);
  lines.push(`tag: ${tagB64}`);
  lines.push("data: |");

  // Chunk data into 64-char lines for readability
  const chunkSize = 64;
  for (let i = 0; i < dataB64.length; i += chunkSize) {
    lines.push(`  ${dataB64.slice(i, i + chunkSize)}`);
  }

  lines.push("```");
  return lines.join("\n");
}

/**
 * Parse a fenced code block VaultGuard secret
 */
export function parseCodeBlock(raw: string): SecretPayload | null {
  const trimmed = raw.trim();
  let content = trimmed;

  if (trimmed.startsWith("```vaultguard")) {
    const startIdx = trimmed.indexOf("\n");
    const endIdx = trimmed.lastIndexOf("```");
    if (startIdx === -1 || endIdx <= startIdx) return null;
    content = trimmed.slice(startIdx + 1, endIdx).trim();
  }

  const lines = content.split("\n");
  let version = 1;
  let label: string | undefined;
  let ivStr: string | undefined;
  let tagStr: string | undefined;
  let inDataBlock = false;
  const dataChunks: string[] = [];

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (trimmedLine.length === 0) continue;

    if (inDataBlock) {
      // Continuation of multiline data
      if (trimmedLine.startsWith("label:") || trimmedLine.startsWith("iv:") || trimmedLine.startsWith("tag:") || trimmedLine.startsWith("version:")) {
        inDataBlock = false;
      } else {
        dataChunks.push(trimmedLine);
        continue;
      }
    }

    if (trimmedLine.startsWith("version:")) {
      version = parseInt(trimmedLine.slice(8).trim(), 10) || 1;
    } else if (trimmedLine.startsWith("label:")) {
      label = trimmedLine.slice(6).trim();
    } else if (trimmedLine.startsWith("iv:")) {
      ivStr = trimmedLine.slice(3).trim();
    } else if (trimmedLine.startsWith("tag:")) {
      tagStr = trimmedLine.slice(4).trim();
    } else if (trimmedLine.startsWith("data:")) {
      const rest = trimmedLine.slice(5).trim();
      if (rest === "|") {
        inDataBlock = true;
      } else if (rest.length > 0) {
        dataChunks.push(rest);
      }
    }
  }

  const dataStr = dataChunks.join("");
  if (!ivStr || !dataStr || !tagStr) {
    return null;
  }

  try {
    const iv = base64ToUint8Array(ivStr);
    const data = base64ToUint8Array(dataStr);
    const tag = base64ToUint8Array(tagStr);

    return {
      version: 1,
      label,
      iv,
      data,
      tag,
      rawText: trimmed,
      isCodeBlock: true,
    };
  } catch (err) {
    return null;
  }
}

/**
 * Attempts to parse either inline comment or fenced code block
 */
export function parseSecret(raw: string): SecretPayload | null {
  const trimmed = raw.trim();
  if (trimmed.startsWith("%%vg:v1:")) {
    return parseInline(trimmed);
  }
  if (trimmed.startsWith("```vaultguard") || trimmed.includes("data: |")) {
    return parseCodeBlock(trimmed);
  }
  return null;
}
