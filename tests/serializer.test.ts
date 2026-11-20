/**
 * KeyMask Serializer & Parser Unit Tests
 */

import { describe, it, expect } from "vitest";
import {
  serializeInline,
  parseInline,
  serializeCodeBlock,
  parseCodeBlock,
  parseSecret,
  isWholeFileEncrypted,
  extractWholeFilePayload,
} from "../src/crypto/serializer";
import { EncryptedData } from "../src/crypto/engine";

describe("Secret Serializer", () => {
  const dummyEncrypted: EncryptedData = {
    iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    data: new Uint8Array([100, 101, 102, 103, 104, 105, 106]),
    tag: new Uint8Array([200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215]),
  };

  it("should serialize and parse inline token with label", () => {
    const serialized = serializeInline({
      label: "Production OpenAI Key",
      encrypted: dummyEncrypted,
    });

    expect(serialized).toMatch(/^%%km:v1:label=[A-Za-z0-9_-]+:iv=[A-Za-z0-9_-]+:data=[A-Za-z0-9_-]+:tag=[A-Za-z0-9_-]+%%$/);

    const parsed = parseInline(serialized);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe(1);
    expect(parsed?.label).toBe("Production OpenAI Key");
    expect(parsed?.iv).toEqual(dummyEncrypted.iv);
    expect(parsed?.data).toEqual(dummyEncrypted.data);
    expect(parsed?.tag).toEqual(dummyEncrypted.tag);
    expect(parsed?.isCodeBlock).toBe(false);
  });

  it("should serialize and parse inline token without label", () => {
    const serialized = serializeInline({
      encrypted: dummyEncrypted,
    });

    expect(serialized).toMatch(/^%%km:v1:iv=[A-Za-z0-9_-]+:data=[A-Za-z0-9_-]+:tag=[A-Za-z0-9_-]+%%$/);

    const parsed = parseInline(serialized);
    expect(parsed).not.toBeNull();
    expect(parsed?.label).toBeUndefined();
    expect(parsed?.iv).toEqual(dummyEncrypted.iv);
    expect(parsed?.data).toEqual(dummyEncrypted.data);
    expect(parsed?.tag).toEqual(dummyEncrypted.tag);
  });

  it("should parse legacy vg:v1 inline tokens for backwards compatibility", () => {
    const legacyToken = "%%vg:v1:label=TGVnYWN5:iv=AQIDBAUGBwgJCgsM:data=ZGVmZ2hpag:tag=yMjM0NTY3ODk0NTY3OA%%";
    const parsed = parseInline(legacyToken);
    expect(parsed).not.toBeNull();
    expect(parsed?.label).toBe("Legacy");
    expect(parsed?.isCodeBlock).toBe(false);
  });

  it("should serialize and parse fenced code block", () => {
    const serialized = serializeCodeBlock({
      label: "Production Ed25519 Private Key",
      encrypted: dummyEncrypted,
    });

    expect(serialized).toContain("```keymask");
    expect(serialized).toContain("version: 1");
    expect(serialized).toContain("label: Production Ed25519 Private Key");
    expect(serialized).toContain("data: |");
    expect(serialized).toContain("```");

    const parsed = parseCodeBlock(serialized);
    expect(parsed).not.toBeNull();
    expect(parsed?.version).toBe(1);
    expect(parsed?.label).toBe("Production Ed25519 Private Key");
    expect(parsed?.iv).toEqual(dummyEncrypted.iv);
    expect(parsed?.data).toEqual(dummyEncrypted.data);
    expect(parsed?.tag).toEqual(dummyEncrypted.tag);
    expect(parsed?.isCodeBlock).toBe(true);
  });

  it("should parse legacy ```vaultguard fenced code blocks for backwards compatibility", () => {
    const modernBlock = serializeCodeBlock({
      label: "Legacy Block",
      encrypted: dummyEncrypted,
    });
    const legacyBlock = modernBlock.replace("```keymask", "```vaultguard");

    const parsed = parseCodeBlock(legacyBlock);
    expect(parsed).not.toBeNull();
    expect(parsed?.label).toBe("Legacy Block");
    expect(parsed?.isCodeBlock).toBe(true);
  });

  it("should parse either format using parseSecret", () => {
    const inline = serializeInline({
      label: "Inline Test",
      encrypted: dummyEncrypted,
    });
    const block = serializeCodeBlock({
      label: "Block Test",
      encrypted: dummyEncrypted,
    });

    const parsedInline = parseSecret(inline);
    expect(parsedInline?.label).toBe("Inline Test");
    expect(parsedInline?.isCodeBlock).toBe(false);

    const parsedBlock = parseSecret(block);
    expect(parsedBlock?.label).toBe("Block Test");
    expect(parsedBlock?.isCodeBlock).toBe(true);
  });

  it("should support whole-file encrypted containers", () => {
    const fileBlock = serializeCodeBlock({
      label: "Entire Secret File",
      encrypted: dummyEncrypted,
      isFile: true,
    });

    expect(fileBlock).toContain("type: file");
    expect(fileBlock).toContain("label: Entire Secret File");

    const parsed = parseCodeBlock(fileBlock);
    expect(parsed).not.toBeNull();
    expect(parsed?.isFilePayload).toBe(true);
    expect(parsed?.label).toBe("Entire Secret File");

    expect(isWholeFileEncrypted(fileBlock)).toBe(true);
    expect(isWholeFileEncrypted("# Normal Markdown Note\nContent here")).toBe(false);

    const extracted = extractWholeFilePayload(fileBlock);
    expect(extracted).not.toBeNull();
    expect(extracted?.isFilePayload).toBe(true);
  });

  it("should return null for malformed or invalid tokens", () => {
    expect(parseInline("%%km:v1:corrupted%%")).toBeNull();
    expect(parseInline("%%vg:v1:corrupted%%")).toBeNull();
    expect(parseInline("%%random_comment%%")).toBeNull();
    expect(parseCodeBlock("```keymask\nnot valid yaml\n```")).toBeNull();
    expect(parseCodeBlock("```vaultguard\nnot valid yaml\n```")).toBeNull();
    expect(parseSecret("not a secret")).toBeNull();
  });
});
