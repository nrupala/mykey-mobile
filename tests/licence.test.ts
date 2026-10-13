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

/** Licensing wave tests — the mirror of the desktop suite
 * (mykey tests/test_licensing.py). Shared-fixture contract:
 * SHARED_TOKEN below was minted ONCE from TEST_SEED_HEX by the
 * Python implementation; this suite verifies the identical
 * string AND mints a byte-identical token from the same seed +
 * payload with @noble/curves. If either side's canonicalization
 * drifts, both suites fail. */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  LicenceInvalidError,
  LicenceRequiredError,
  buildToken,
  computePasscode,
  normalizeToken,
  publicKeyB64FromSeed,
  verifyToken,
  type LicencePayload,
} from "../src/vault/licence.js";
import { exportCsv } from "../src/vault/csvio.js";
import { VaultSession } from "../src/vault/vault.js";

const TEST_SEED_HEX =
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TEST_SEED = new Uint8Array(
  TEST_SEED_HEX.match(/.{2}/g)!.map((h) => parseInt(h, 16)),
);
const TEST_PUBLIC_B64 = publicKeyB64FromSeed(TEST_SEED);
const TEST_DOB = "1990-05-17";

const TEST_PAYLOAD: LicencePayload = {
  licence_id: "lic-test000000000001",
  licensee: "test-buyer@example.com",
  product: "mykey",
  edition: "unlimited",
  issued_at: "2026-10-13T00:00:00Z",
  payment_date: "2026-10-01",
  serial: "0123456789abcdeffedcba9876543210",
  passcode:
    "370B EF86 0C2C 5F40 B556 CAD0 239F B711 " +
    "0E4E 612B B292 4C45 89E5 68D0 9FE2 8DE8",
  max_connections: 20,
};
const SHARED_TOKEN = "MKLIC1.eyJlZGl0aW9uIjoidW5saW1pdGVkIiwiaXNzdWVkX2F0IjoiMjAyNi0xMC0xM1QwMDowMDowMFoiLCJsaWNlbmNlX2lkIjoibGljLXRlc3QwMDAwMDAwMDAwMDEiLCJsaWNlbnNlZSI6InRlc3QtYnV5ZXJAZXhhbXBsZS5jb20iLCJtYXhfY29ubmVjdGlvbnMiOjIwLCJwYXNzY29kZSI6IjM3MEIgRUY4NiAwQzJDIDVGNDAgQjU1NiBDQUQwIDIzOUYgQjcxMSAwRTRFIDYxMkIgQjI5MiA0QzQ1IDg5RTUgNjhEMCA5RkUyIDhERTgiLCJwYXltZW50X2RhdGUiOiIyMDI2LTEwLTAxIiwicHJvZHVjdCI6Im15a2V5Iiwic2VyaWFsIjoiMDEyMzQ1Njc4OWFiY2RlZmZlZGNiYTk4NzY1NDMyMTAifQ.ENHUW7GNXGTHx5nUy1JK_cpCowiZrG16UNm8fXEXMRWgDNHIVOWL0z-YVqIpIXkD1N16NFbzSB69UeJg-EpmCg";

const MASTER = "licence-test-master-1";
const entry = (service: string, password = "pw") => ({
  service, username: "user", password,
  url: "", notes: "", totp_secret: "", tags: [] as string[], favourite: false,
});

async function testSession(): Promise<VaultSession> {
  const s = await VaultSession.createNew(MASTER);
  s.licencePublicKeyB64 = TEST_PUBLIC_B64;
  return s;
}

async function reopen(bytes: Uint8Array): Promise<VaultSession> {
  const s = await VaultSession.openWithPassword(bytes, MASTER);
  s.licencePublicKeyB64 = TEST_PUBLIC_B64;
  return s;
}

describe("shared licence fixture (minted by the Python client)", () => {
  it("test authority key matches the Python-derived public key", () => {
    expect(TEST_PUBLIC_B64).toBe("A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=");
  });

  it("verifies the shared token", () => {
    expect(verifyToken(SHARED_TOKEN, TEST_PUBLIC_B64)).toEqual(TEST_PAYLOAD);
  });

  it("mints a byte-identical token from the same seed + payload", () => {
    expect(buildToken(TEST_PAYLOAD, TEST_SEED)).toBe(SHARED_TOKEN);
  });

  it("rejects the test token against the production authority", () => {
    expect(() => verifyToken(SHARED_TOKEN)).toThrow(LicenceInvalidError);
  });

  it("fails closed on tampering", () => {
    const mid = Math.floor(SHARED_TOKEN.length / 2);
    const flipped =
      SHARED_TOKEN.slice(0, mid) +
      (SHARED_TOKEN[mid] === "A" ? "B" : "A") +
      SHARED_TOKEN.slice(mid + 1);
    for (const bad of [
      flipped,
      SHARED_TOKEN.slice(0, -2) + "AA",
      "MKLIC1..",
      "",
      "not a licence",
    ]) {
      expect(() => verifyToken(bad, TEST_PUBLIC_B64)).toThrow(LicenceInvalidError);
    }
  });

  it("passcode matches the Python computation", () => {
    expect(
      computePasscode("test-buyer@example.com", "2026-10-01", TEST_DOB,
        TEST_PAYLOAD.serial),
    ).toBe(TEST_PAYLOAD.passcode);
    expect(
      computePasscode("Test-Buyer@Example.com", "2026-10-01", TEST_DOB,
        TEST_PAYLOAD.serial),
    ).toBe(TEST_PAYLOAD.passcode); // email case-folded, like Python
  });

  it("grouped paste normalizes back to the token", () => {
    const grouped = SHARED_TOKEN.replace(/(.{6})/g, "$1 ").trim();
    expect(normalizeToken(" " + grouped + "\n")).toBe(SHARED_TOKEN);
  });
});

describe("entry cap", () => {
  it("caps at exactly 50; the 51st add is refused plainly", async () => {
    const s = await testSession();
    for (let i = 0; i < 50; i++) await s.addEntry(entry(`svc-${i}`));
    expect(s.listEntries()).toHaveLength(50);
    await expect(s.addEntry(entry("one-too-many"))).rejects.toThrow(
      LicenceRequiredError,
    );
    // Edits still work at the cap.
    const first = s.listEntries()[0]!;
    await s.updateEntry(first.id, { password: "rotated" });
    // Delete one -> one add fits -> cap bites again.
    await s.deleteEntry(first.id);
    await s.addEntry(entry("backfill"));
    await expect(s.addEntry(entry("nope"))).rejects.toThrow(LicenceRequiredError);
  });

  it("a licence in the vault lifts the cap and travels on save", async () => {
    const s = await testSession();
    const payload = s.setLicenceKey(SHARED_TOKEN);
    expect(payload.licence_id).toBe(TEST_PAYLOAD.licence_id);
    expect(s.isLicensed()).toBe(true);
    for (let i = 0; i < 55; i++) await s.addEntry(entry(`svc-${i}`));
    const again = await reopen(await s.serialize());
    expect(again.isLicensed()).toBe(true);
    expect(again.licenceKey()).toBe(SHARED_TOKEN);
    expect(again.listEntries()).toHaveLength(55);
  });

  it("a bad key is refused and stores nothing", async () => {
    const s = await testSession();
    expect(() => s.setLicenceKey("MKLIC1.garbage.garbage")).toThrow(
      LicenceInvalidError,
    );
    expect(s.isLicensed()).toBe(false);
    expect(s.licenceKey()).toBe("");
  });

  it("the device slot alone licenses a fresh vault", async () => {
    const s = await testSession();
    expect(s.isLicensed()).toBe(false);
    s.setDeviceLicence(TEST_PAYLOAD);
    expect(s.isLicensed()).toBe(true);
    expect(s.connectionLimit()).toBe(20);
    s.setDeviceLicence(null);
    expect(s.isLicensed()).toBe(false);
  });

  it("grandfathered 60-entry vault opens, exports; only adding pauses",
    async () => {
      const s = await testSession();
      s.setLicenceKey(SHARED_TOKEN);
      for (let i = 0; i < 60; i++) await s.addEntry(entry(`svc-${i}`, `pw-${i}`));
      // Licence removed (as if the vault travelled to a fresh device).
      (s as unknown as { core: Record<string, unknown> }).core.settings = {};
      const human = await reopen(await s.serialize());
      expect(human.isLicensed()).toBe(false);
      expect(human.listEntries()).toHaveLength(60);
      expect(human.getEntry(human.listEntries()[5]!.id).password).toBe("pw-5");
      expect(exportCsv(human.listEntries()).split("\r\n")).toHaveLength(62);
      await expect(human.addEntry(entry("blocked"))).rejects.toThrow(
        LicenceRequiredError,
      );
      for (const e of human.listEntries().slice(0, 11)) {
        await human.deleteEntry(e.id);
      }
      expect(human.listEntries()).toHaveLength(49);
      await human.addEntry(entry("fits-now"));
      await expect(human.addEntry(entry("blocked-2"))).rejects.toThrow(
        LicenceRequiredError,
      );
    });

  it("import fills to the limit and reports heldBack exactly", async () => {
    const s = await testSession();
    for (let i = 0; i < 48; i++) await s.addEntry(entry(`svc-${i}`));
    const records = [0, 1, 2, 3, 4].map((i) => entry(`imp-${i}`, `pw-${i}`));
    let stats = await s.importEntries(records);
    expect(stats.added).toBe(2);
    expect(stats.heldBack).toBe(3);
    expect(s.listEntries()).toHaveLength(50);
    s.setLicenceKey(SHARED_TOKEN);
    stats = await s.importEntries(records);
    expect(stats.added).toBe(3);
    expect(stats.heldBack).toBe(0);
    expect(s.listEntries()).toHaveLength(53);
  });
});

describe("connections pool (one combined pool, per vault)", () => {
  it("counts active devices + agents + paired browsers", async () => {
    const s = await testSession();
    const core = (s as unknown as { core: Record<string, any> }).core;
    core.devices = {
      d1: { enrolled_at: 1 },
      d2: { enrolled_at: 1 },
      d3: { enrolled_at: 1, revoked_at: 2 }, // revoked: no place held
    };
    core.agents = { a1: {}, a2: {} };
    core.settings = { browser_pairings: [{ id: "b1" }] };
    expect(s.connectionCount()).toBe(5); // 2 devices + 2 agents + 1 browser
    expect(s.browserPairingCount()).toBe(1);
    expect(s.connectionLimit()).toBe(4); // free pool
    expect(s.licenceStatusLine()).toBe(
      "Free · 0 of 50 passwords · 5 of 4 connections",
    );
  });

  it("honours a licence's own pool size", async () => {
    const s = await testSession();
    const small = buildToken({ ...TEST_PAYLOAD, max_connections: 7 }, TEST_SEED);
    s.setLicenceKey(small);
    expect(s.connectionLimit()).toBe(7);
    expect(s.licenceStatusLine()).toContain("0 of 7 connections");
  });
});

describe("cross-client fixtures", () => {
  const here = dirname(fileURLToPath(import.meta.url));
  const pyFixture = join(here, "fixtures", "py-licensed.mykey");

  it("opens the Python-written licensed vault as licensed", async () => {
    if (!existsSync(pyFixture)) {
      // Generated by scripts/make_fixtures.py from the desktop
      // repo; present in CI, may be absent in a bare checkout.
      return;
    }
    const bytes = new Uint8Array(readFileSync(pyFixture));
    const s = await VaultSession.openWithPassword(bytes, "cross-client fixture 1");
    s.licencePublicKeyB64 = TEST_PUBLIC_B64;
    expect(s.isLicensed()).toBe(true);
    expect(s.listEntries().length).toBeGreaterThanOrEqual(1);
  });

  it("writes the TS licensed-vault fixture for the desktop suite", async () => {
    const s = await VaultSession.createNew("cross-client fixture 1");
    s.licencePublicKeyB64 = TEST_PUBLIC_B64;
    s.setLicenceKey(SHARED_TOKEN);
    await s.addEntry(entry("fixture-service", "fixture-pw"));
    const bytes = await s.serialize();
    writeFileSync(join(here, "fixtures", "ts-licensed.mykey"), bytes);
    const again = await VaultSession.openWithPassword(
      bytes, "cross-client fixture 1");
    again.licencePublicKeyB64 = TEST_PUBLIC_B64;
    expect(again.isLicensed()).toBe(true);
  });
});
