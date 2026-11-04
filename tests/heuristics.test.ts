/**
 * VaultGuard Pattern Matcher & Heuristics Unit Tests
 */

import { describe, it, expect } from "vitest";
import {
  detectSensitiveToken,
  maskForPreview,
  scanTextForSecrets,
  isFalsePositiveSecret,
  extractSecretSnippet,
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

  it("should detect contextual passwords and secrets (password: ..., secret = ...)", () => {
    const input1 = "password: MySuperSecretPass#99!";
    const detected1 = detectSensitiveToken(input1);
    expect(detected1).not.toBeNull();
    expect(detected1?.patternId).toBe("contextual-password");
    expect(detected1?.matchedText).toBe("MySuperSecretPass#99!");

    const input2 = 'api_key = "K8#mQ2$zL9!vP4"';
    const detected2 = detectSensitiveToken(input2);
    expect(detected2).not.toBeNull();
    expect(detected2?.patternId).toBe("contextual-password");
    expect(detected2?.matchedText).toBe("K8#mQ2$zL9!vP4");
  });

  it("should detect standalone pasted passwords with mixed character types", () => {
    const password = "K8#mQ2$zL9!vP4";
    const detected = detectSensitiveToken(password);
    expect(detected).not.toBeNull();
    expect(detected?.patternId).toBe("standalone-password");
    expect(detected?.matchedText).toBe(password);
  });

  it("should return null for non-sensitive text and normal identifiers", () => {
    expect(detectSensitiveToken("Just an everyday grocery list and notes.")).toBeNull();
    expect(detectSensitiveToken("https://google.com/search?q=test")).toBeNull();
    expect(detectSensitiveToken("let x = 10;")).toBeNull();
    expect(detectSensitiveToken("DEFAULT_CONFIG_OPTIONS")).toBeNull();
    expect(detectSensitiveToken("getUserProfile")).toBeNull();
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

  describe("Document Batch Secret Scanner (scanTextForSecrets)", () => {
    it("should discover all unencrypted secrets in a document with line numbers", () => {
      const doc = `# Project Config
Here are the project credentials:
Line 3: OpenAI Key: sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef12
Line 4: Some notes here.
Line 5: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
Line 6: DB URL: postgres://admin:SuperSecretPass99@db.prod.internal.net:5432/main_db
Line 7: password: MySuperSecretPass#99!
`;

      const findings = scanTextForSecrets(doc);
      expect(findings.length).toBe(4);

      expect(findings[0].patternId).toBe("openai-api-key");
      expect(findings[0].lineNumber).toBe(3);

      expect(findings[1].patternId).toBe("aws-access-key");
      expect(findings[1].lineNumber).toBe(5);

      expect(findings[2].patternId).toBe("db-connection-uri");
      expect(findings[2].lineNumber).toBe(6);

      expect(findings[3].patternId).toBe("contextual-password");
      expect(findings[3].lineNumber).toBe(7);
      expect(findings[3].matchedText).toBe("MySuperSecretPass#99!");
    });

    it("should ignore secrets already encrypted with VaultGuard tokens", () => {
      const doc = `# Secure Document
Already encrypted token:
%%vg:v1:label=T1BFTkFJ:iv=UEyGQGybafBD6EBz:data=FVFmaRHX2h7S7e5G1ZHb_HFX4WE:tag=M44gLh8Ajj1UDHzsaXdspw%%

Unencrypted token:
sk-proj-9999999990abcdef1234567890abcdef1234567890abcdef12
`;

      const findings = scanTextForSecrets(doc);
      expect(findings.length).toBe(1);
      expect(findings[0].matchedText).toBe("sk-proj-9999999990abcdef1234567890abcdef1234567890abcdef12");
    });

    it("should support safe reverse-order document replacement", () => {
      let doc = "Key1: sk-proj-1111111110abcdef1234567890abcdef1234567890abcdef12 and Key2: AKIAIOSFODNN7EXAMPLE";
      const findings = scanTextForSecrets(doc);
      expect(findings.length).toBe(2);

      // Replace in reverse order (highest index to lowest)
      const reversed = [...findings].sort((a, b) => b.startIndex - a.startIndex);
      for (const finding of reversed) {
        const replacement = `%%vg:v1:mock_encrypted_${finding.patternId}%%`;
        doc = doc.slice(0, finding.startIndex) + replacement + doc.slice(finding.endIndex);
      }

      expect(doc).toBe("Key1: %%vg:v1:mock_encrypted_openai-api-key%% and Key2: %%vg:v1:mock_encrypted_aws-access-key%%");
    });

    it("should filter out non-password words and documentation placeholders", () => {
      expect(isFalsePositiveSecret("Committed")).toBe(true);
      expect(isFalsePositiveSecret("plaintext")).toBe(true);
      expect(isFalsePositiveSecret("none")).toBe(true);
      expect(isFalsePositiveSecret("null")).toBe(true);
      expect(isFalsePositiveSecret("<password>")).toBe(true);
      expect(isFalsePositiveSecret("${PASSWORD}")).toBe(true);
      expect(isFalsePositiveSecret("process.env.API_KEY")).toBe(true);

      expect(isFalsePositiveSecret("SuperSecret99!")).toBe(false);
      expect(isFalsePositiveSecret("anudeep@123")).toBe(false);
      expect(isFalsePositiveSecret("8(V6VeCc][*c)<)P")).toBe(false);

      const doc = `
# Security Analysis
Password: Committed in plaintext
Password: none
Password: <enter-password-here>
password: SuperSecret99!
`;
      const findings = scanTextForSecrets(doc);
      expect(findings.length).toBe(1);
      expect(findings[0].matchedText).toBe("SuperSecret99!");
    });

    it("should extract localized snippet centered on secret for long lines", () => {
      const longPrefix = "A".repeat(5000);
      const longSuffix = "B".repeat(5000);
      const secret = "SuperSecret99!";
      const line = `${longPrefix} password: ${secret} ${longSuffix}`;

      const snippet = extractSecretSnippet(line, secret, 20);
      expect(snippet.before.startsWith("... ")).toBe(true);
      expect(snippet.after.endsWith(" ...")).toBe(true);
      expect(snippet.matchedMasked).toBe("Supe••••••••••••t99!");
      expect(snippet.before.length).toBeLessThan(40);
      expect(snippet.after.length).toBeLessThan(40);
    });
  });
});
