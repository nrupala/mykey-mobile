// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** Android autofill matching — the rules that decide which vault
 * entries may be offered for a fill request, and how they are
 * labelled. This module is pure (no DOM, no platform calls) so the
 * rules are unit-tested directly; the native service supplies the
 * facts (web domain, or package name + signing-certificate hash)
 * and this module supplies the judgment.
 *
 * Safety rules, in order:
 *  - Browser fills match on the entry's website host: exact host,
 *    or a dot-boundary subdomain relationship in either direction.
 *    Lookalikes never match ("evilexample.com" is not a subdomain
 *    of "example.com"; "example.com.evil.com" belongs to evil.com).
 *  - App fills match ONLY on an entry's stored Android binding:
 *    same package name AND the same signing-certificate hash the
 *    entry was linked with. A re-signed or cloned app has a
 *    different certificate, so it can never match silently — at
 *    most it is listed, clearly flagged, for an explicit one-off
 *    fill by the user.
 *  - Nothing here ever sees a password label: chooser/dataset
 *    labels are built from service + username only.
 */

import type { AndroidAppBinding, VaultEntry } from "./vault.js";

export interface AutofillTarget {
  /** The site's host for browser fills (e.g. "accounts.example.com"). */
  webDomain: string | null;
  /** The requesting app's package for native-app fills. */
  packageName: string | null;
  /** SHA-256 of the requesting app's signing certificate (hex). */
  certSha256: string | null;
  /** Human name of the requesting app/browser, for display. */
  appLabel: string | null;
}

/** Extract the lowercase host from a stored entry URL. Entries are
 * usually stored as full URLs, but tolerate bare hosts and junk.
 * Parsed by hand (no URL construction): the client builds no
 * network addresses, by policy (see docs/TRANSPORT_SECURITY.md). */
export function hostOfUrl(raw: string): string | null {
  let value = (raw ?? "").trim().toLowerCase();
  if (!value) return null;
  // Strip any scheme, then take the authority up to the first
  // path/query/fragment delimiter.
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  const authority = value.split(/[/?#]/, 1)[0] ?? "";
  // Strip userinfo and port (bracketed IPv6 kept intact).
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  const host = hostPort.startsWith("[")
    ? hostPort.slice(0, hostPort.indexOf("]") + 1)
    : hostPort.split(":", 1)[0] ?? "";
  return host || null;
}

/** Normalize a host/domain supplied by the platform (may arrive as
 * a bare host, a URL, or with a trailing dot). Anything that is
 * not host-shaped (spaces, junk) normalizes to null — a malformed
 * target must match nothing, never everything. */
export function normalizeHost(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const host = hostOfUrl(raw) ?? raw.trim().toLowerCase().replace(/\.$/, "");
  if (!host || !/^[a-z0-9]+([.-][a-z0-9]+)*$/.test(host)) return null;
  return host;
}

/** True when two hosts are the same site for fill purposes: equal,
 * or one is a dot-boundary subdomain of the other. */
export function hostsMatch(a: string, b: string): boolean {
  if (a === b) return true;
  return a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

/** Entries whose website matches the requested web domain. */
export function matchEntriesForDomain(
  entries: VaultEntry[],
  webDomain: string | null,
): VaultEntry[] {
  if (!webDomain) return [];
  const wanted = normalizeHost(webDomain);
  if (!wanted) return [];
  return entries.filter((e) => {
    const host = hostOfUrl(e.url);
    return host !== null && hostsMatch(host, wanted);
  });
}

/** How an entry stands against an app fill request. */
export type AppMatch =
  | "bound" // binding matches package + certificate: safe to offer
  | "cert-mismatch" // bound to this package, different signing key
  | "other-app" // bound to a different package
  | "unbound"; // no binding yet: linking can be offered

export function classifyAppMatch(
  binding: AndroidAppBinding | null,
  packageName: string | null,
  certSha256: string | null,
): AppMatch {
  if (!binding) return "unbound";
  if (!packageName || binding.package !== packageName) return "other-app";
  const cert = (certSha256 ?? "").trim().toLowerCase().replace(/:/g, "");
  return cert && cert === binding.cert_sha256 ? "bound" : "cert-mismatch";
}

/** Entries bound to exactly this app (package + certificate). */
export function matchEntriesForApp(
  entries: VaultEntry[],
  packageName: string | null,
  certSha256: string | null,
): VaultEntry[] {
  return entries.filter(
    (e) => classifyAppMatch(e.android_app, packageName, certSha256) === "bound",
  );
}

export interface ChooserGroups {
  /** Safe matches, offered first. */
  matched: VaultEntry[];
  /** Bound to this package but signed with a different key —
   * possible clone; offered only with the warning attached. */
  certMismatch: VaultEntry[];
  /** Everything else (unbound and other apps' entries). */
  others: VaultEntry[];
}

/** Split the vault into what the fill chooser shows, per target. */
export function groupEntriesForTarget(
  entries: VaultEntry[],
  target: AutofillTarget,
): ChooserGroups {
  if (target.webDomain) {
    const matched = matchEntriesForDomain(entries, target.webDomain);
    const ids = new Set(matched.map((e) => e.id));
    return { matched, certMismatch: [], others: entries.filter((e) => !ids.has(e.id)) };
  }
  if (target.packageName) {
    const matched: VaultEntry[] = [];
    const certMismatch: VaultEntry[] = [];
    const others: VaultEntry[] = [];
    for (const e of entries) {
      const cls = classifyAppMatch(e.android_app, target.packageName, target.certSha256);
      if (cls === "bound") matched.push(e);
      else if (cls === "cert-mismatch") certMismatch.push(e);
      else others.push(e);
    }
    return { matched, certMismatch, others };
  }
  return { matched: [], certMismatch: [], others: [...entries] };
}

/** The only text a dataset/chooser row may carry: service plus
 * username. Passwords never appear in labels — Android shows
 * dataset labels to the keyboard and the shade before any fill. */
export function chooserLabel(entry: VaultEntry): { title: string; subtitle: string } {
  return {
    title: entry.service,
    subtitle: entry.username ? entry.username : "No username",
  };
}

/** A plain-words name for the fill destination, for headings. */
export function targetName(target: AutofillTarget): string {
  if (target.webDomain) return target.webDomain;
  if (target.appLabel) return target.appLabel;
  if (target.packageName) return target.packageName;
  return "this app";
}
