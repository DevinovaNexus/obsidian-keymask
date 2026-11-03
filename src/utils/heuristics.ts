/**
 * VaultGuard Pattern Matchers & Leak Heuristics
 *
 * High-performance compiled regex matchers executed during paste events
 * to intercept sensitive credentials before they touch the note buffer.
 *
 * Performance budget: < 15ms per evaluation.
 */

export interface TokenPattern {
  id: string;
  name: string;
  regex: RegExp;
  suggestedLabel: string;
}

export interface DetectedToken {
  patternId: string;
  patternName: string;
  suggestedLabel: string;
  matchedText: string;
  startIndex: number;
  endIndex: number;
}

/**
 * Compiled high-performance regex patterns
 */
export const SENSITIVE_PATTERNS: TokenPattern[] = [
  {
    id: "anthropic-api-key",
    name: "Anthropic API Key",
    regex: /\b(sk-ant-[a-zA-Z0-9_-]{90,})\b/,
    suggestedLabel: "Anthropic API Key",
  },
  {
    id: "openai-api-key",
    name: "OpenAI API Key",
    // Covers classic sk-... and modern sk-proj-..., excluding sk-ant-
    regex: /\b(sk-(?!ant-)[a-zA-Z0-9_-]{48,})\b/,
    suggestedLabel: "OpenAI API Key",
  },
  {
    id: "github-pat",
    name: "GitHub Personal Access Token",
    // Supports classic ghp_ tokens (36-40 chars) and fine-grained github_pat_ (82+ chars)
    regex: /\b(ghp_[a-zA-Z0-9]{30,40}|github_pat_[a-zA-Z0-9_]{80,90})\b/,
    suggestedLabel: "GitHub Token",
  },
  {
    id: "aws-access-key",
    name: "AWS Access Key ID",
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    suggestedLabel: "AWS Access Key",
  },
  {
    id: "private-key",
    name: "Private Cryptographic Key",
    regex: /(-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA)? ?PRIVATE KEY-----[\s\S]*?-----END (?:RSA|EC|OPENSSH|PGP|DSA)? ?PRIVATE KEY-----)/,
    suggestedLabel: "Private Key",
  },
  {
    id: "jwt-bearer",
    name: "JWT / Bearer Token",
    regex: /\b(ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}(?:\.[A-Za-z0-9._-]+)?)\b/,
    suggestedLabel: "JWT Token",
  },
  {
    id: "stripe-secret-key",
    name: "Stripe Secret Key",
    regex: /\b([rs]k_live_[0-9a-zA-Z]{24,})\b/,
    suggestedLabel: "Stripe Secret Key",
  },
  {
    id: "slack-token",
    name: "Slack API Token",
    regex: /\b(xox[baprs]-[0-9a-zA-Z-]{10,})\b/,
    suggestedLabel: "Slack Token",
  },
  {
    id: "google-api-key",
    name: "Google Cloud API Key",
    regex: /\b(AIza[0-9A-Za-z\\-_]{35})\b/,
    suggestedLabel: "Google API Key",
  },
  {
    id: "db-connection-uri",
    name: "Database Connection URI with Credentials",
    regex: /\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s:@/]+@[^\s/]+(?:\/[^\s]*)?)\b/,
    suggestedLabel: "Database Credentials",
  },
];

/**
 * Scans text for sensitive credential patterns.
 * Returns the first matching detected token, or null if no credentials found.
 */
export function detectSensitiveToken(text: string): DetectedToken | null {
  if (!text || text.length < 16) {
    return null;
  }

  // Quick heuristic check: if text is huge (e.g. megabytes), don't freeze editor;
  // scan first 200KB where credentials usually reside.
  const sample = text.length > 200_000 ? text.slice(0, 200_000) : text;

  for (const pattern of SENSITIVE_PATTERNS) {
    const match = pattern.regex.exec(sample);
    if (match) {
      const matchedText = match[1] || match[0];
      const startIndex = match.index;
      return {
        patternId: pattern.id,
        patternName: pattern.name,
        suggestedLabel: pattern.suggestedLabel,
        matchedText,
        startIndex,
        endIndex: startIndex + matchedText.length,
      };
    }
  }

  return null;
}

/**
 * Utility to mask a credential for safe preview display in UI
 * (e.g. sk-proj-123456... -> sk-proj-12••••••••••••34)
 */
export function maskForPreview(token: string, visibleChars = 4): string {
  if (token.length <= visibleChars * 2) {
    return "••••••••";
  }
  const prefix = token.slice(0, visibleChars);
  const suffix = token.slice(-visibleChars);
  return `${prefix}••••••••••••${suffix}`;
}
