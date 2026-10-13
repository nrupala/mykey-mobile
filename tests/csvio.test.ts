// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
// See LICENSING.md. (Mirrors the desktop import engine's behaviour;
// the goldens below are the desktop parsers' outputs for the same
// inputs, checked against importers.py semantics.)

import { describe, expect, it } from "vitest";
import {
  chromiumEntries,
  classifyImport,
  detectCsvFormat,
  exportCsv,
  firefoxEntries,
  genericMapEntries,
  parseCsvText,
  parseImportCsv,
  rowsFromCsv,
} from "../src/vault/csvio.js";
import { VaultSession } from "../src/vault/vault.js";

const CHROMIUM_CSV = [
  "name,url,username,password,note",
  "github,https://github.com,octocat,gh-pass-123,work account",
  '"Example, Bank",https://bank.example.com,alice,bank-pass-456,"note with ""quotes"""',
  ",,,,",
].join("\r\n");

const FIREFOX_CSV = [
  "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged",
  "https://example.com,alice,ff-pass-1,,,,,,",
  "https://shop.example.org,bob,ff-pass-2,Member area,,,,,",
].join("\n");

describe("csv parser", () => {
  it("handles quotes, embedded commas/newlines, CRLF and BOM", () => {
    const table = parseCsvText("\uFEFFa,b\r\n\"x,\ny\",\"q\"\"z\"\r\n1,2");
    expect(table).toEqual([["a", "b"], ["x,\ny", 'q"z'], ["1", "2"]]);
  });

  it("rowsFromCsv strips header whitespace and fills gaps", () => {
    const { headers, rows } = rowsFromCsv(" name , url \nx,");
    expect(headers).toEqual(["name", "url"]);
    expect(rows).toEqual([{ name: "x", url: "" }]);
  });
});

describe("format detection (desktop signature order)", () => {
  it("detects chromium with and without the note column", () => {
    expect(detectCsvFormat(["name", "url", "username", "password", "note"]))
      .toBe("chromium");
    expect(detectCsvFormat(["name", "url", "username", "password"]))
      .toBe("chromium");
  });
  it("detects firefox by httpRealm", () => {
    expect(detectCsvFormat(["url", "username", "password", "httpRealm"]))
      .toBe("firefox");
  });
  it("falls back to generic for unknown headers", () => {
    expect(detectCsvFormat(["Site", "Login", "Secret"])).toBe("generic");
    expect(detectCsvFormat(["folder", "favorite", "type", "name", "login_username", "login_password"]))
      .toBe("generic");
  });
});

describe("chromium + firefox parsers (desktop semantics)", () => {
  it("chromium: name→service, note→notes, blanks dropped by parse", () => {
    const { rows } = rowsFromCsv(CHROMIUM_CSV);
    const all = chromiumEntries(rows);
    expect(all).toHaveLength(3);
    expect(all[0]).toMatchObject({
      service: "github", username: "octocat", password: "gh-pass-123",
      url: "https://github.com", notes: "work account",
      totp_secret: "", tags: [], favourite: false,
    });
    expect(all[1]!.service).toBe("Example, Bank");
    expect(all[1]!.notes).toBe('note with "quotes"');
    const parsed = parseImportCsv(CHROMIUM_CSV);
    expect(parsed.format).toBe("chromium");
    expect(parsed.entries).toHaveLength(2); // the all-blank row is dropped
  });

  it("firefox: url becomes the service when no hostname column", () => {
    const { rows } = rowsFromCsv(FIREFOX_CSV);
    const entries = firefoxEntries(rows);
    expect(entries[0]).toMatchObject({
      service: "https://example.com", username: "alice",
      password: "ff-pass-1", url: "https://example.com",
    });
    const parsed = parseImportCsv(FIREFOX_CSV);
    expect(parsed.format).toBe("firefox");
    expect(parsed.entries).toHaveLength(2);
  });

  it("generic mapping picks the chosen columns", () => {
    const { rows } = rowsFromCsv("Site,Login,Secret\nmail.example,carol,s3cret");
    const entries = genericMapEntries(rows, {
      service: "Site", username: "Login", password: "Secret",
    });
    expect(entries[0]).toMatchObject({
      service: "mail.example", username: "carol", password: "s3cret",
      url: "", notes: "",
    });
  });
});

describe("classification (desktop preview_import semantics)", () => {
  const existing = [
    { service: "GitHub", username: "OctoCat", password: "same-pw" },
    { service: "bank", username: "alice", password: "old-pw" },
  ];
  it("new / duplicate / conflict by case-insensitive key + password", () => {
    const cls = classifyImport(
      [
        { service: "github", username: "octocat", password: "same-pw", url: "", notes: "", totp_secret: "", tags: [], favourite: false },
        { service: "BANK", username: "ALICE", password: "new-pw", url: "", notes: "", totp_secret: "", tags: [], favourite: false },
        { service: "fresh", username: "dan", password: "pw", url: "", notes: "", totp_secret: "", tags: [], favourite: false },
      ],
      existing,
    );
    expect(cls.duplicates).toHaveLength(1);
    expect(cls.conflicts).toHaveLength(1);
    expect(cls.fresh).toHaveLength(1);
    expect(cls.fresh[0]!.service).toBe("fresh");
  });
});

describe("session import (desktop resolve_import policies)", () => {
  it("applies skip / overwrite / keep_both and persists through serialize", async () => {
    const session = await VaultSession.createNew("Import-Test-Password-1");
    await session.addEntry({
      service: "bank", username: "alice", password: "old-pw",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    });
    const incoming = [
      { service: "bank", username: "alice", password: "new-pw", url: "https://bank.example", notes: "", totp_secret: "", tags: [], favourite: false },
      { service: "github", username: "octocat", password: "gh-pw", url: "", notes: "", totp_secret: "", tags: [], favourite: false },
    ];

    let stats = await session.importEntries(incoming, "skip");
    expect(stats).toMatchObject({ added: 1, conflicts: 1, skippedConflicts: 1, overwritten: 0 });
    expect(session.listEntries().find((e) => e.service === "bank")!.password).toBe("old-pw");

    stats = await session.importEntries(incoming, "overwrite");
    expect(stats).toMatchObject({ added: 0, duplicates: 1, conflicts: 1, overwritten: 1 });
    expect(session.listEntries().find((e) => e.service === "bank")!.password).toBe("new-pw");

    stats = await session.importEntries(
      [{ ...incoming[0]!, password: "third-pw" }], "keep_both",
    );
    expect(stats).toMatchObject({ conflicts: 1, keptBoth: 1 });
    expect(session.listEntries().filter((e) => e.service === "bank")).toHaveLength(2);

    // Everything survives a serialize → reopen round trip.
    const bytes = await session.serialize();
    const reopened = await VaultSession.openWithPassword(bytes, "Import-Test-Password-1");
    expect(reopened.listEntries()).toHaveLength(3);
  });
});

describe("csv export (desktop export_vault_to_csv shape)", () => {
  it("header, columns, CRLF, RFC 4180 quoting", () => {
    const csv = exportCsv([
      { service: "github", username: "octocat", password: "plain", url: "https://github.com", notes: "" },
      { service: 'a,"b"', username: "u", password: 'p"x', url: "", notes: "line1\nline2" },
    ]);
    const lines = csv.split("\r\n");
    expect(lines[0]).toBe("Service,Username,Password,URL,Notes");
    expect(lines[1]).toBe("github,octocat,plain,https://github.com,");
    expect(csv).toContain('"a,""b""",u,"p""x",,"line1\nline2"');
    expect(csv.endsWith("\r\n")).toBe(true);
  });

  it("round-trips through the chromium importer column names it shares", () => {
    // Desktop export headers are Title-case; the file a user gets
    // back must at least parse cleanly (generic mapping path).
    const csv = exportCsv([
      { service: "github", username: "octocat", password: "pw", url: "https://github.com", notes: "n" },
    ]);
    const { headers, rows } = rowsFromCsv(csv);
    expect(headers).toEqual(["Service", "Username", "Password", "URL", "Notes"]);
    expect(rows[0]).toMatchObject({ Service: "github", Password: "pw" });
  });
});
