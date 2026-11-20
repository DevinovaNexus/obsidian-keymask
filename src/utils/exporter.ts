/**
 * KeyMask Export Generators (KeePass XML & CSV)
 *
 * Zero-dependency pure functions for generating standard password manager files:
 * 1. KeePass 2.x XML (.xml) - Native support in MacPass, KeePassXC, and KeePass
 * 2. Universal Password CSV (.csv) - Supported by Bitwarden, 1Password, etc.
 */

export interface DecryptedExportEntry {
  title: string;
  password: string;
  notes: string;
  url: string;
  group: string;
}

/**
 * Generates KeePass 2.x XML specification compatible with MacPass, KeePassXC, and KeePass
 */
export function generateKeePassXML(
  entries: DecryptedExportEntry[],
  vaultName: string
): string {
  const escapeXml = (unsafe: string) => {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&apos;");
  };

  const xmlEntries = entries
    .map((e) => {
      return `      <Entry>
        <String>
          <Key>Title</Key>
          <Value>${escapeXml(e.title)}</Value>
        </String>
        <String>
          <Key>UserName</Key>
          <Value></Value>
        </String>
        <String>
          <Key>Password</Key>
          <Value>${escapeXml(e.password)}</Value>
        </String>
        <String>
          <Key>URL</Key>
          <Value>${escapeXml(e.url)}</Value>
        </String>
        <String>
          <Key>Notes</Key>
          <Value>${escapeXml(e.notes)}</Value>
        </String>
      </Entry>`;
    })
    .join("\n");

  return `<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile>
  <Meta>
    <Generator>KeyMask Obsidian Plugin</Generator>
    <DatabaseName>${escapeXml(vaultName)} Secrets</DatabaseName>
    <DatabaseDescription>Exported credentials from Obsidian vault: ${escapeXml(vaultName)}</DatabaseDescription>
  </Meta>
  <Root>
    <Group>
      <Name>KeyMask</Name>
${xmlEntries}
    </Group>
  </Root>
</KeePassFile>`;
}

/**
 * Generates universal CSV format
 */
export function generateCSV(entries: DecryptedExportEntry[]): string {
  const escapeCsv = (str: string) => {
    return `"${str.replace(/"/g, '""')}"`;
  };

  const header = `"Group","Title","Username","Password","URL","Notes"`;
  const rows = entries.map((e) =>
    [
      escapeCsv(e.group),
      escapeCsv(e.title),
      escapeCsv(""),
      escapeCsv(e.password),
      escapeCsv(e.url),
      escapeCsv(e.notes),
    ].join(",")
  );

  return [header, ...rows].join("\n");
}
