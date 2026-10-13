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

/** Android-app binding preservation (interop seam fix).
 *
 * The desktop engine and the Android autofill flow store an
 * `android_app` binding ({package, cert_sha256, label?}) in an
 * entry's encrypted metadata. This client never edits bindings,
 * but it must CARRY them: before this fix the TS metadata field
 * list did not include `android_app`, so opening such a vault and
 * saving anything silently dropped every binding. These tests
 * stand in for a desktop-written vault by planting a binding on
 * the live entry (the TS UI has no binding editor by design),
 * then prove it survives serialize → open → serialize → open,
 * and that a malformed binding is normalized to null on load —
 * never carried into a position where it could match an app. */

import { describe, expect, it } from "vitest";

import {
  VaultSession,
  cleanAndroidApp,
  type AndroidAppBinding,
  type VaultEntry,
} from "../src/vault/vault.js";

const MASTER = "Binding-Test-Password-1";
const CERT = "0123456789abcdef".repeat(4);
const BINDING: AndroidAppBinding = {
  package: "com.example.bank",
  cert_sha256: CERT,
  label: "Example Bank",
};

function liveEntries(s: VaultSession): VaultEntry[] {
  return (s as unknown as { entriesList: VaultEntry[] }).entriesList;
}

async function newBoundSession(): Promise<VaultSession> {
  const s = await VaultSession.createNew(MASTER);
  await s.addEntry({
    service: "bank.example.com",
    username: "user",
    password: "fixture-pw",
    url: "",
    notes: "",
    totp_secret: "",
    tags: [],
    favourite: false,
  });
  liveEntries(s)[0].android_app = { ...BINDING };
  return s;
}

describe("android_app binding round trip", () => {
  it("survives serialize → open → serialize → open verbatim", async () => {
    const s = await newBoundSession();
    const bytes1 = await s.serialize();
    const reopened = await VaultSession.openWithPassword(bytes1, MASTER);
    expect(reopened.listEntries()[0].android_app).toEqual(BINDING);
    const bytes2 = await reopened.serialize();
    const again = await VaultSession.openWithPassword(bytes2, MASTER);
    expect(again.listEntries()[0].android_app).toEqual(BINDING);
  });

  it("an unbound entry stays unbound (null, not undefined)", async () => {
    const s = await VaultSession.createNew(MASTER);
    await s.addEntry({
      service: "plain.example.com",
      username: "user",
      password: "fixture-pw",
      url: "",
      notes: "",
      totp_secret: "",
      tags: [],
      favourite: false,
    });
    const reopened = await VaultSession.openWithPassword(await s.serialize(), MASTER);
    expect(reopened.listEntries()[0].android_app).toBeNull();
  });

  it("a malformed binding planted in the file loads as null", async () => {
    const s = await newBoundSession();
    liveEntries(s)[0].android_app = {
      package: "com.example.bank",
      cert_sha256: "not-a-cert",
    } as AndroidAppBinding;
    const reopened = await VaultSession.openWithPassword(await s.serialize(), MASTER);
    expect(reopened.listEntries()[0].android_app).toBeNull();
  });
});

describe("cleanAndroidApp (Python clean_android_app parity)", () => {
  it("normalizes case, colons and padding like the desktop", () => {
    const colon = CERT.match(/.{2}/g)!.join(":");
    expect(
      cleanAndroidApp({ package: " com.example.bank ", cert_sha256: colon.toUpperCase() }),
    ).toEqual({ package: "com.example.bank", cert_sha256: CERT });
  });

  it("drops label when blank, keeps it when real", () => {
    expect(cleanAndroidApp({ package: "a.b", cert_sha256: CERT, label: "  " })).toEqual({
      package: "a.b",
      cert_sha256: CERT,
    });
    expect(cleanAndroidApp({ package: "a.b", cert_sha256: CERT, label: " Bank " })).toEqual({
      package: "a.b",
      cert_sha256: CERT,
      label: "Bank",
    });
  });

  it("refuses non-objects, blank packages and short certs", () => {
    expect(cleanAndroidApp(null)).toBeNull();
    expect(cleanAndroidApp("com.example.bank")).toBeNull();
    expect(cleanAndroidApp({ package: " ", cert_sha256: CERT })).toBeNull();
    expect(cleanAndroidApp({ package: "a.b", cert_sha256: CERT.slice(2) })).toBeNull();
    expect(cleanAndroidApp({ package: "a.b" })).toBeNull();
  });
});
