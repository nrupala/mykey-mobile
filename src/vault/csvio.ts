// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (the import/export
// engine). It is NOT licensed under Apache 2.0, MIT, or any other
// open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.
//
// The import *format definitions* (which columns each exporter
// emits) are Apache 2.0 material per LICENSING.md; the parsing /
// dedupe / conflict engine here mirrors the desktop engine
// (importers.py) so both clients classify a file identically.

/** CSV import/export for the web client.
 *
 * Import scope (mirroring the desktop importer's behaviour for
 * these formats): Chromium-family exports (Chrome, Edge, Brave,
 * Opera, Vivaldi, Arc, Google Password Manager), Firefox exports,
 * and a generic column mapping for anything else. The file is
 * parsed locally, in memory, and never uploaded anywhere.
 *
 * Export mirrors the desktop's export_vault_to_csv exactly:
 * columns Service, Username, Password, URL, Notes, RFC 4180
 * quoting, CRLF line endings. */

import type { VaultEntry } from "./vault.js";

/** A record parsed from an import file. Import sources carry no
 * password set date, so the rotation fields are deliberately not
 * part of this shape: the vault records imported passwords as
 * "date not recorded" (see VaultSession.importEntries). */
export type ImportRecord = Omit<
  VaultEntry,
  "id" | "created" | "updated" | "password_set_at" | "rotate_days"
>;
export type ConflictPolicy = "skip" | "overwrite" | "keep_both";
export type CsvFormat = "chromium" | "firefox" | "generic";

export interface ImportClassification {
  fresh: ImportRecord[];
  duplicates: ImportRecord[];
  conflicts: ImportRecord[];
}

export interface ImportStats {
  added: number;
  duplicates: number;
  conflicts: number;
  overwritten: number;
  keptBoth: number;
  skippedConflicts: number;
}

// ------------------------------------------------------------------
// CSV parsing (RFC 4180, close enough to Python's csv module for
// browser-exported files: quoted fields, embedded commas/quotes/
// newlines, CRLF or LF endings, UTF-8 BOM tolerated).
// ------------------------------------------------------------------

export function parseCsvText(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  const pushField = () => {
    row.push(field);
    field = "";
  };
  const pushRow = () => {
    pushField();
    // Skip blank lines the way Python's csv reader does.
    if (!(row.length === 1 && row[0] === "")) rows.push(row);
    row = [];
  };
  for (; i < text.length; i++) {
    const ch = text[i]!;
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      pushField();
    } else if (ch === "\r") {
      if (text[i + 1] === "\n") i++;
      pushRow();
    } else if (ch === "\n") {
      pushRow();
    } else {
      field += ch;
    }
  }
  if (field !== "" || row.length > 0) pushRow();
  return rows;
}

export function rowsFromCsv(text: string): {
  headers: string[];
  rows: Array<Record<string, string>>;
} {
  const table = parseCsvText(text);
  if (table.length === 0) throw new Error("CSV has no header row");
  const headers = table[0]!.map((h) => h.trim());
  const rows = table.slice(1).map((cells) => {
    const rec: Record<string, string> = {};
    headers.forEach((h, idx) => {
      rec[h] = cells[idx] ?? "";
    });
    return rec;
  });
  return { headers, rows };
}

// ------------------------------------------------------------------
// Entry construction — mirrors importers.py's _entry().
// ------------------------------------------------------------------

function entryFrom(p: Partial<ImportRecord>): ImportRecord {
  return {
    service: (p.service ?? "").trim(),
    username: (p.username ?? "").trim(),
    password: p.password ?? "",
    url: (p.url ?? "").trim(),
    notes: p.notes ?? "",
    totp_secret: (p.totp_secret ?? "").trim(),
    tags: [...(p.tags ?? [])],
    favourite: Boolean(p.favourite),
  };
}

export function chromiumEntries(
  rows: Array<Record<string, string>>,
): ImportRecord[] {
  return rows.map((r) =>
    entryFrom({
      service: r["name"], username: r["username"], password: r["password"],
      url: r["url"], notes: r["note"],
    }),
  );
}

export function firefoxEntries(
  rows: Array<Record<string, string>>,
): ImportRecord[] {
  return rows.map((r) =>
    entryFrom({
      service: r["hostname"] || r["url"], username: r["username"],
      password: r["password"], url: r["url"],
    }),
  );
}

export type GenericMapping = Partial<
  Record<"service" | "username" | "password" | "url" | "notes" | "totp_secret", string>
>;

export function genericMapEntries(
  rows: Array<Record<string, string>>,
  mapping: GenericMapping,
): ImportRecord[] {
  const pick = (row: Record<string, string>, field: keyof GenericMapping) => {
    const col = mapping[field];
    return col ? (row[col] ?? "") : "";
  };
  return rows.map((r) =>
    entryFrom({
      service: pick(r, "service"), username: pick(r, "username"),
      password: pick(r, "password"), url: pick(r, "url"),
      notes: pick(r, "notes"), totp_secret: pick(r, "totp_secret"),
    }),
  );
}

// ------------------------------------------------------------------
// Format detection — mirrors detect_format()'s header-signature
// order for the formats this client imports. Anything else falls
// back to the generic column mapping.
// ------------------------------------------------------------------

const SIGNATURES: ReadonlyArray<readonly [CsvFormat, readonly string[]]> = [
  ["firefox", ["url", "username", "password", "httpRealm"]],
  ["chromium", ["name", "url", "username", "password", "note"]],
  ["chromium", ["name", "url", "username", "password"]],
];

export function detectCsvFormat(headers: string[]): CsvFormat {
  const set = new Set(headers);
  for (const [fmt, required] of SIGNATURES) {
    if (required.every((h) => set.has(h))) return fmt;
  }
  return "generic";
}

export function parseImportCsv(
  text: string,
): { format: CsvFormat; headers: string[]; entries: ImportRecord[] } {
  const { headers, rows } = rowsFromCsv(text);
  const format = detectCsvFormat(headers);
  if (format === "generic") return { format, headers, entries: [] };
  const parsed =
    format === "chromium" ? chromiumEntries(rows) : firefoxEntries(rows);
  // The desktop drops rows that carry neither a service nor a name.
  return {
    format,
    headers,
    entries: parsed.filter((e) => e.service || e.username),
  };
}

// ------------------------------------------------------------------
// Classification — mirrors preview_import(): a record keys on
// (service, username), case-insensitive. Same password = duplicate;
// different password = conflict.
// ------------------------------------------------------------------

function keyOf(e: { service: string; username: string }): string {
  // The desktop keys on the (service, username) tuple; a NUL
  // separator keeps the flattened key collision-free.
  return `${e.service.toLowerCase()}` + "\u0000" + `${e.username.toLowerCase()}`;
}

export function classifyImport(
  incoming: ImportRecord[],
  existing: Array<{ service: string; username: string; password: string }>,
): ImportClassification {
  const byKey = new Map(existing.map((e) => [keyOf(e), e]));
  const out: ImportClassification = { fresh: [], duplicates: [], conflicts: [] };
  for (const rec of incoming) {
    const current = byKey.get(keyOf(rec));
    if (!current) out.fresh.push(rec);
    else if (current.password === rec.password) out.duplicates.push(rec);
    else out.conflicts.push(rec);
  }
  return out;
}

// ------------------------------------------------------------------
// Export — byte-compatible shape with the desktop exporter.
// ------------------------------------------------------------------

function csvField(value: string): string {
  return /[",\r\n]/.test(value)
    ? `"${value.replace(/"/g, '""')}"`
    : value;
}

export const EXPORT_FILENAME = "mykey_export.csv";
export const EXPORT_HEADER = ["Service", "Username", "Password", "URL", "Notes"];

export function exportCsv(
  entries: Array<Pick<VaultEntry, "service" | "username" | "password" | "url" | "notes">>,
): string {
  const lines = [EXPORT_HEADER.map(csvField).join(",")];
  for (const e of entries) {
    lines.push(
      [e.service, e.username, e.password, e.url, e.notes].map(csvField).join(","),
    );
  }
  return lines.join("\r\n") + "\r\n";
}
