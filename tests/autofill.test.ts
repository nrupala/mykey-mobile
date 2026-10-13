// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// Android autofill matching rules: web-domain association,
// package + signing-certificate binding, lookalike refusal,
// dataset label masking, and the free-cap seam. These rules are
// the security boundary of the autofill service — a wrong match
// hands a password to the wrong app or site.

import { describe, expect, it } from "vitest";
import {
  classifyAppMatch,
  groupEntriesForTarget,
  hostsMatch,
  matchEntriesForApp,
  matchEntriesForDomain,
  normalizeHost,
  chooserLabel,
} from "../src/vault/autofill.js";
import { cleanAndroidApp, VaultSession, type VaultEntry } from "../src/vault/vault.js";
import { FREE_ENTRY_LIMIT, LicenceRequiredError } from "../src/vault/licence.js";

const CERT_A = "a".repeat(64);
const CERT_B = "b".repeat(64);

function entry(partial: Partial<VaultEntry>): VaultEntry {
  return {
    id: partial.id ?? Math.random().toString(36).slice(2),
    service: partial.service ?? "svc",
    username: partial.username ?? "user",
    password: partial.password ?? "s3cret-value",
    url: partial.url ?? "",
    notes: partial.notes ?? "",
    tags: partial.tags ?? [],
    favourite: false,
    totp_secret: "",
    created: 1_700_000_000,
    updated: 1_700_000_000,
    password_set_at: null,
    rotate_days: null,
    android_app: partial.android_app ?? null,
    kind: "login",
    passkey: null,
  };
}

describe("host normalization + matching", () => {
  it("extracts hosts from urls and bare hosts", () => {
    expect(normalizeHost("https://Example.COM:8443/path?q=1")).toBe("example.com");
    expect(normalizeHost("example.com/login")).toBe("example.com");
    expect(normalizeHost("not a url at all")).toBeNull();
    expect(normalizeHost("")).toBeNull();
  });

  it("matches exact hosts and dot-boundary subdomains both ways", () => {
    expect(hostsMatch("example.com", "example.com")).toBe(true);
    expect(hostsMatch("login.example.com", "example.com")).toBe(true);
    expect(hostsMatch("example.com", "login.example.com")).toBe(true);
  });

  it("refuses lookalike hosts", () => {
    expect(hostsMatch("evilexample.com", "example.com")).toBe(false);
    expect(hostsMatch("example.com.evil.com", "example.com")).toBe(false);
    expect(hostsMatch("example-com.evil.org", "example.com")).toBe(false);
    expect(hostsMatch("exam ple.com", "example.com")).toBe(false);
  });
});

describe("domain matching", () => {
  const entries = [
    entry({ id: "1", service: "GitHub", url: "https://github.com" }),
    entry({ id: "2", service: "Gist", url: "https://gist.github.com" }),
    entry({ id: "3", service: "Bank", url: "https://bank.example" }),
    entry({ id: "4", service: "NoUrl", url: "" }),
  ];

  it("returns entries whose site matches the request domain", () => {
    const got = matchEntriesForDomain(entries, "github.com").map((e) => e.id);
    expect(got.sort()).toEqual(["1", "2"]);
  });

  it("a subdomain request matches the parent entry", () => {
    const got = matchEntriesForDomain(entries, "login.bank.example").map((e) => e.id);
    expect(got).toEqual(["3"]);
  });

  it("a lookalike domain matches nothing", () => {
    expect(matchEntriesForDomain(entries, "github.com.evil.com")).toEqual([]);
    expect(matchEntriesForDomain(entries, "evilgithub.com")).toEqual([]);
    expect(matchEntriesForDomain(entries, null)).toEqual([]);
  });
});

describe("app binding classification", () => {
  const bound = { package: "com.example.shop", cert_sha256: CERT_A, label: "Shop" };

  it("bound only when package AND cert match", () => {
    expect(classifyAppMatch(bound, "com.example.shop", CERT_A)).toBe("bound");
    // A re-signed / cloned app must NOT match silently.
    expect(classifyAppMatch(bound, "com.example.shop", CERT_B)).toBe("cert-mismatch");
    // A lookalike package never matches, even with the same cert.
    expect(classifyAppMatch(bound, "com.example.shop.clone", CERT_A)).toBe("other-app");
    expect(classifyAppMatch(bound, "com.example.shop", null)).toBe("cert-mismatch");
    expect(classifyAppMatch(null, "com.example.shop", CERT_A)).toBe("unbound");
    expect(classifyAppMatch(bound, null, CERT_A)).toBe("other-app");
  });

  it("matchEntriesForApp returns only bound entries", () => {
    const entries = [
      entry({ id: "bound", android_app: bound }),
      entry({ id: "clone", android_app: { package: "com.example.shop", cert_sha256: CERT_B } }),
      entry({ id: "plain" }),
    ];
    expect(matchEntriesForApp(entries, "com.example.shop", CERT_A).map((e) => e.id)).toEqual(["bound"]);
  });

  it("grouping separates matched / cert-mismatch / others", () => {
    const entries = [
      entry({ id: "bound", android_app: bound }),
      entry({ id: "mismatch", android_app: { package: "com.example.shop", cert_sha256: CERT_B } }),
      entry({ id: "plain" }),
    ];
    const g = groupEntriesForTarget(entries, {
      packageName: "com.example.shop", appLabel: "Shop",
      webDomain: null, certSha256: CERT_A,
    });
    expect(g.matched.map((e) => e.id)).toEqual(["bound"]);
    expect(g.certMismatch.map((e) => e.id)).toEqual(["mismatch"]);
    expect(g.others.map((e) => e.id)).toEqual(["plain"]);
  });
});

describe("binding validation (cleanAndroidApp)", () => {
  it("accepts a well-formed binding and normalizes the cert", () => {
    const got = cleanAndroidApp({
      package: " com.example.shop ",
      cert_sha256: CERT_A.toUpperCase().replace(/(.{2})/g, "$1:").slice(0, -1),
      label: " Shop ",
    });
    expect(got).toEqual({ package: "com.example.shop", cert_sha256: CERT_A, label: "Shop" });
  });

  it("drops malformed bindings", () => {
    expect(cleanAndroidApp(null)).toBeNull();
    expect(cleanAndroidApp("com.example.shop")).toBeNull();
    expect(cleanAndroidApp({ package: "", cert_sha256: CERT_A })).toBeNull();
    expect(cleanAndroidApp({ package: "com.example.shop", cert_sha256: "xyz" })).toBeNull();
    expect(cleanAndroidApp({ package: "com.example.shop", cert_sha256: CERT_A.slice(0, 63) })).toBeNull();
  });
});

describe("dataset / chooser labels never carry the password", () => {
  it("chooserLabel is service + username only", () => {
    const e = entry({ service: "GitHub", username: "octocat", password: "hunter2-hunter2" });
    const label = chooserLabel(e);
    expect(label.title).toContain("GitHub");
    expect(label.subtitle).toContain("octocat");
    expect(label.title).not.toContain("hunter2");
    expect(label.subtitle).not.toContain("hunter2");
  });
});

describe("free-cap seam", () => {
  it("the save path runs into the vault's own cap (licensing landed)", async () => {
    // The PR-era placeholder seam (freeEntryLimit /
    // wouldExceedFreeCap in a stub licence.ts) is gone: the
    // licensing wave landed and the cap now lives in
    // VaultSession.addEntry — the exact call the autofill confirm
    // screen makes, binding included. An unlicensed vault stops
    // at FREE_ENTRY_LIMIT (50) with a LicenceRequiredError, which
    // the confirm screen surfaces to the user.
    const s = await VaultSession.createNew("autofill-cap-test-master");
    expect(FREE_ENTRY_LIMIT).toBe(50);
    expect(s.entryLimit()).toBe(FREE_ENTRY_LIMIT);
    const input = (service: string) => ({
      service, username: "user", password: "pw",
      url: "", notes: "", totp_secret: "", tags: [] as string[], favourite: false,
      android_app: { package: "com.example.shop", cert_sha256: CERT_A },
    });
    for (let i = 0; i < FREE_ENTRY_LIMIT; i++) await s.addEntry(input(`svc-${i}`));
    expect(s.listEntries()).toHaveLength(FREE_ENTRY_LIMIT);
    expect(s.listEntries()[0]!.android_app?.package).toBe("com.example.shop");
    await expect(s.addEntry(input("one-too-many"))).rejects.toThrow(LicenceRequiredError);
  });
});
