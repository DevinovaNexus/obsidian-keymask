/**
 * VaultGuard Pattern Matcher & Heuristics Unit Tests
 */

import { describe, it, expect } from "vitest";
import {
  detectSensitiveToken,
  maskForPreview,
  SENSITIVE_PATTERNS,
} from "../src/utils/heuristics";

describe("Leak Heuristics & Pattern Detection", () => {
  it("should detect OpenAI classic and modern project API keys", () => {
    const openaiKey = "sk-proj-abcde12345ABCDE67890fghij12345FGHIJ67890klmno12345KLMNO";
    const detected = detectSensitiveToken(openaiKey);

    expect(detected).not.toBeNull();
    expect(detected?.patternId).toBe("openai-api-key");
    expect(detected?.patternName).toBe("OpenAI API Key");
    expect(detected?.matchedText).toBe(openaiKey);
  });

  it("should detect Anthropic API keys", () => {
    const antKey = "sk-ant-" + "a".repeat(95);
    const detected = detectSensitiveToken(`Here is my key: ${antKey} please do not share`);

    expect(detected).not.toBeNull();
    expect(detected?.patternId).toBe("anthropic-api-key");
    expect(detected?.matchedText).toBe(antKey);
  });

  it("should detect GitHub Personal Access Tokens (classic and fine-grained)", () => {
    const classicPat = "ghp_" + "a".repeat(36);
    const fineGrainedPat = "github_pat_" + "a".repeat(82);

    const detected1 = detectSensitiveToken(`Authorization: token ${classicPat}`);
    expect(detected1?.patternId).toBe("github-pat");
    expect(detected1?.matchedText).toBe(classicPat);

    const detected2 = detectSensitiveToken(fineGrainedPat);
    expect(detected2?.patternId).toBe("github-pat");
    expect(detected2?.matchedText).toBe(fineGrainedPat);
  });

  it("should detect AWS Access Key IDs", () => {
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    const detected = detectSensitiveToken(`export AWS_ACCESS_KEY_ID=${awsKey}`);

    expect(detected?.patternId).toBe("aws-access-key");
    expect(detected?.matchedText).toBe(awsKey);
  });

  it("should detect Private Cryptographic Keys", () => {
    const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1W9X...
-----END RSA PRIVATE KEY-----`;

    const detected = detectSensitiveToken(privateKey);
    expect(detected?.patternId).toBe("private-key");
    expect(detected?.matchedText).toBe(privateKey);
  });

  it("should detect JWT / Bearer tokens", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const detected = detectSensitiveToken(jwt);

    expect(detected?.patternId).toBe("jwt-bearer");
    expect(detected?.matchedText).toBe(jwt);
  });

  it("should detect Stripe secret keys", () => {
    const stripeKey = "sk_live_51A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P";
    const detected = detectSensitiveToken(stripeKey);

    expect(detected?.patternId).toBe("stripe-secret-key");
  });

  it("should detect Database connection URIs", () => {
    const dbUri = "postgres://admin:SuperSecretPass99@db.prod.internal.net:5432/main_db";
    const detected = detectSensitiveToken(`DATABASE_URL=${dbUri}`);

    expect(detected?.patternId).toBe("db-connection-uri");
    expect(detected?.matchedText).toBe(dbUri);
  });

  it("should return null for non-sensitive text", () => {
    expect(detectSensitiveToken("Just an everyday grocery list and notes.")).toBeNull();
    expect(detectSensitiveToken("https://google.com/search?q=test")).toBeNull();
    expect(detectSensitiveToken("let x = 10;")).toBeNull();
  });

  it("should execute regex scanning well within 15ms budget", () => {
    const largeNote = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(1000) +
      "sk-proj-abcde12345ABCDE67890fghij12345FGHIJ67890klmno12345KLMNO " +
      "More notes here...".repeat(500);

    const start = performance.now();
    const detected = detectSensitiveToken(largeNote);
    const elapsed = performance.now() - start;

    expect(detected).not.toBeNull();
    expect(elapsed).toBeLessThan(15); // Performance budget < 15ms
  });

  it("should correctly mask strings for UI preview", () => {
    const key = "sk-proj-1234567890abcdef1234567890";
    const preview = maskForPreview(key, 4);

    expect(preview).toBe("sk-p••••••••••••7890");
  });
});
