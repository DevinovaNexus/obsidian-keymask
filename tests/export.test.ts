/**
 * KeyMask KeePass / MacPass Export Format Tests
 */

import { describe, it, expect } from "vitest";
import {
  generateKeePassXML,
  generateCSV,
  DecryptedExportEntry,
} from "../src/utils/exporter";

describe("KeePass & MacPass Export Specifications", () => {
  const sampleEntries: DecryptedExportEntry[] = [
    {
      title: "Stripe Live Key & Production DB",
      password: "sk_live_1234567890abcdef<secret>&pass='test'\"quoted\"",
      group: "KeyMask/Production",
      url: "obsidian://open?vault=MainVault&file=Notes/Billing.md",
      notes: "Location: Notes/Billing.md:14\nPattern: Stripe Secret Key",
    },
    {
      title: "AWS Root Key",
      password: "AKIAIOSFODNN7EXAMPLE",
      group: "KeyMask",
      url: "obsidian://open?vault=MainVault&file=AWS.md",
      notes: "AWS admin credential",
    },
  ];

  it("should generate valid KeePass 2.x XML compliant with MacPass & KeePassXC", () => {
    const xml = generateKeePassXML(sampleEntries, "TestVault");

    expect(xml).toContain('<?xml version="1.0" encoding="utf-8" standalone="yes"?>');
    expect(xml).toContain("<KeePassFile>");
    expect(xml).toContain("<DatabaseName>TestVault Secrets</DatabaseName>");
    expect(xml).toContain("<Name>KeyMask</Name>");
    expect(xml).toContain("<Key>Title</Key>");
    expect(xml).toContain("<Key>Password</Key>");
    expect(xml).toContain("<Key>URL</Key>");
    expect(xml).toContain("<Key>Notes</Key>");

    // Verify XML escaping of special characters (&, <, >, ", ')
    expect(xml).toContain("Stripe Live Key &amp; Production DB");
    expect(xml).toContain("&lt;secret&gt;&amp;pass=&apos;test&apos;&quot;quoted&quot;");
    expect(xml).not.toContain("<secret>");
  });

  it("should generate standard password CSV compliant with password managers", () => {
    const csv = generateCSV(sampleEntries);

    expect(csv).toContain('"Group","Title","Username","Password","URL","Notes"');
    expect(csv).toContain('"KeyMask/Production"');
    expect(csv).toContain('"Stripe Live Key & Production DB"');
    expect(csv).toContain('"AKIAIOSFODNN7EXAMPLE"');
  });
});
