// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright (c) 2026 2351485 ALBERTA INC.

// Transport gates: encryption in transit + no-network posture.
//
// These tests encode the claims in docs/TRANSPORT_SECURITY.md so
// they cannot silently regress:
//  * the client contains no network-call primitives at all;
//  * the CSP forbids connections (connect-src 'none');
//  * the Android app requests no permissions (no INTERNET);
//  * the service worker does no runtime caching of network data;
//  * the only external links are the user-invoked allowlist;
//  * bytes that leave via export/share are the encrypted vault
//    container, never plaintext;
//  * plaintext CSV export stays behind its confirm gate.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { VaultSession } from "../src/vault/vault.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

const srcFiles = walk(join(root, "src")).filter((f) => f.endsWith(".ts"));
const surfaceFiles = [
  ...srcFiles,
  join(root, "index.html"),
  join(root, "capacitor.config.ts"),
  join(root, "vite.config.ts"),
];
const read = (p: string) => readFileSync(p, "utf8");

describe("transport gates — no network surface", () => {
  it("no network-call primitives anywhere in the client source", () => {
    const forbidden = [
      /\bfetch\s*\(/,
      /XMLHttpRequest/,
      /WebSocket/,
      /EventSource/,
      /sendBeacon/,
      /rejectUnauthorized/,
      /NODE_TLS_REJECT_UNAUTHORIZED/,
    ];
    const offenders: string[] = [];
    for (const f of surfaceFiles) {
      const text = read(f);
      for (const pat of forbidden) {
        if (pat.test(text)) offenders.push(`${f}: ${pat}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("CSP forbids all connections", () => {
    const html = read(join(root, "index.html"));
    expect(html).toContain("connect-src 'none'");
    expect(html).toContain("default-src 'self'");
  });

  it("Android manifest requests no permissions at all", () => {
    const manifest = read(
      join(root, "android/app/src/main/AndroidManifest.xml"),
    );
    expect(manifest).not.toContain("<uses-permission");
    expect(manifest).toContain('android:allowBackup="false"');
  });

  it("service worker does precache only — no runtime caching", () => {
    const vite = read(join(root, "vite.config.ts"));
    expect(vite).toContain("runtimeCaching: []");
  });

  it("external URLs are exactly the user-invoked allowlist", () => {
    const allowed = new Set([
      "http://www.apache.org/licenses/LICENSE-2.0",
      "https://nrupalakolkar.com",
      "https://muse.ai/join",
    ]);
    const offenders: string[] = [];
    for (const f of surfaceFiles) {
      for (const m of read(f).matchAll(/https?:\/\/[^\s'")<]+/g)) {
        if (!allowed.has(m[0])) offenders.push(`${f}: ${m[0]}`);
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe("transport gates — what leaves the device", () => {
  it("serialized vault bytes are the encrypted container, no plaintext", async () => {
    const s = await VaultSession.createNew("Transport-Gate-Password-1");
    await s.addEntry({
      service: "gate-service",
      username: "gate-user",
      password: "gate-secret-123",
      url: "",
      notes: "",
      totp_secret: "JBSWY3DPEHPK3PXP",
      tags: [],
      favourite: false,
    });
    const bytes = await s.serialize();
    const text = new TextDecoder().decode(bytes);
    const header = JSON.parse(text) as { format?: string };
    expect(header.format).toBe("MKVLT");
    for (const plain of ["gate-secret-123", "JBSWY3DPEHPK3PXP", "gate-user"]) {
      expect(text).not.toContain(plain);
    }
  });

  it("CSV export stays behind the confirm gate in the UI", () => {
    const app = read(join(root, "src/ui/app.ts"));
    expect(app).toContain("confirmBox");
    expect(app).toMatch(/exportBtn\.disabled = !confirmBox\.checked/);
  });
});
