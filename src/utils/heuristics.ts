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
  {
    id: "contextual-password",
    name: "Password / Secret Credential",
    // Matches keys like password: ..., secret = "...", auth_token: ...
    regex: /\b(?:password|passwd|pwd|passphrase|secret|api_key|apikey|auth_token)\s*[:=]\s*["']?([^\s"']{6,})["']?/i,
    suggestedLabel: "Password",
  },
];

/**
 * Checks if a standalone single-token string looks like a password:
 * - 8 to 128 characters without internal whitespace
 * - Not a URL or file path
 * - Mixed character classes (at least 3 of lowercase, uppercase, digits, symbols)
 */
export function isLikelyPassword(str: string): boolean {
  const trimmed = str.trim();
  if (trimmed.length < 8 || trimmed.length > 128 || /\s/.test(trimmed)) {
    return false;
  }

  // Exclude common URLs, emails, and paths
  if (/^(?:https?:\/\/|file:\/\/|\/|\.\/|mailto:|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i.test(trimmed)) {
    return false;
  }

  // Count character categories
  let types = 0;
  if (/[a-z]/.test(trimmed)) types++;
  if (/[A-Z]/.test(trimmed)) types++;
  if (/[0-9]/.test(trimmed)) types++;
  if (/[^a-zA-Z0-9]/.test(trimmed)) types++;

  // Must have at least 3 character types, and contain either symbols or digits
  if (types >= 3 && (/[^a-zA-Z0-9]/.test(trimmed) || /[0-9]/.test(trimmed))) {
    // Avoid uppercase constants like DEFAULT_CONFIG_OPTIONS
    if (/^[A-Z0-9_]+$/.test(trimmed) && !/[a-z]/.test(trimmed) && !/[^A-Z0-9_]/.test(trimmed)) {
      return false;
    }
    return true;
  }

  return false;
}

/**
 * Scans text for sensitive credential patterns.
 * Returns the first matching detected token, or null if no credentials found.
 */
export function detectSensitiveToken(text: string): DetectedToken | null {
  if (!text || text.trim().length < 6) {
    return null;
  }

  // Quick heuristic check: if text is huge (e.g. megabytes), don't freeze editor;
  // scan first 200KB where credentials usually reside.
  const sample = text.length > 200_000 ? text.slice(0, 200_000) : text;

  // 1. Scan known regex patterns
  for (const pattern of SENSITIVE_PATTERNS) {
    const match = pattern.regex.exec(sample);
    if (match) {
      const matchedText = match[1] || match[0];
      const matchSubIndex = match[1] ? match[0].indexOf(match[1]) : 0;
      const startIndex = match.index + matchSubIndex;
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

  // 2. Check for standalone pasted password or high-entropy secret
  const trimmed = sample.trim();
  if (isLikelyPassword(trimmed)) {
    const startIndex = sample.indexOf(trimmed);
    return {
      patternId: "standalone-password",
      patternName: "Password / Sensitive Secret",
      suggestedLabel: "Password",
      matchedText: trimmed,
      startIndex,
      endIndex: startIndex + trimmed.length,
    };
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
