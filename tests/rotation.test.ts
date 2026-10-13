// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// Password age + rotation (owner directive, 2026-10-13), mirroring
// the Python engine's tests/test_rotation.py: the set-date clock,
// the 180-day default, per-entry overrides and Never at both
// levels, due boundaries, pre-feature files opening with the
// creation-time fallback, unknown fields tolerated, and import
// overwrite clearing the date — in both clients' shared semantics.

import { describe, expect, it } from "vitest";
import { aesGcmDecrypt, aesGcmEncrypt } from "../src/vault/crypto.js";
import { utf8Decode, utf8Encode } from "../src/vault/encoding.js";
import {
  rotationDueCount,
  rotationLine,
  rotationReport,
  rotationStatus,
} from "../src/vault/rotation.js";
import {
  VaultSession,
  computeEntryHash,
  type VaultEntry,
} from "../src/vault/vault.js";

const DAY = 86400;
const T0 = 1_800_000_000;
const MASTER = "Rotation-Test-2026";

function statusOf(psa: number | null, rotate: number | null,
                  def: number | null, now: number) {
  return rotationStatus({ password_set_at: psa, rotate_days: rotate }, def, now);
}

// -- pure status semantics (same values as the Python suite) --------

describe("rotationStatus semantics", () => {
  it("applies the 180-day default and computes the due date", () => {
    const s = statusOf(T0, null, 180, T0);
    expect(s.state).toBe("ok");
    expect(s.rotate_days).toBe(180);
    expect(s.due_at).toBe(T0 + 180 * DAY);
  });

  it("honours the due-soon / overdue boundaries exactly", () => {
    const due = T0 + 180 * DAY;
    expect(statusOf(T0, 180, 180, due - 14 * DAY - 1).state).toBe("ok");
    expect(statusOf(T0, 180, 180, due - 14 * DAY).state).toBe("due_soon");
    expect(statusOf(T0, 180, 180, due - 1).state).toBe("due_soon");
    expect(statusOf(T0, 180, 180, due).state).toBe("overdue");
    expect(statusOf(T0, 180, 180, due + 30 * DAY).state).toBe("overdue");
    expect(statusOf(T0, 180, 180, due).days_left).toBe(0);
    expect(statusOf(T0, 180, 180, due - 10 * DAY).days_left).toBe(10);
  });

  it("per-entry override wins; Never honoured at both levels", () => {
    expect(statusOf(T0, 30, 180, T0).due_at).toBe(T0 + 30 * DAY);
    expect(statusOf(T0, 0, 180, T0 + 9999 * DAY).state).toBe("off");
    expect(statusOf(T0, null, 0, T0 + 9999 * DAY).state).toBe("off");
    expect(statusOf(T0, null, null, T0).state).toBe("off");
    expect(statusOf(T0, 45, 0, T0).state).toBe("ok");
  });

  it("no recorded date reads as unknown", () => {
    const s = statusOf(null, null, 180, T0);
    expect(s.state).toBe("unknown");
    expect(s.due_at).toBeNull();
    expect(rotationLine({ password_set_at: null, rotate_days: null }, 180))
      .toBe("Password date not recorded");
  });

  it("formats the plain-language line like the desktop", () => {
    const t = Math.floor(new Date(2026, 9, 13).getTime() / 1000); // 13 Oct 2026 local
    expect(rotationLine({ password_set_at: t, rotate_days: null }, 180, t))
      .toBe("Password set 13 Oct 2026 · change by 11 Apr 2027");
    expect(rotationLine({ password_set_at: t, rotate_days: null }, 0, t))
      .toBe("Password set 13 Oct 2026 · change date off");
  });

  it("report sorts attention-first and counts due entries", () => {
    const mk = (service: string, psa: number | null, rotate: number | null) =>
      ({ service, username: "", password_set_at: psa, rotate_days: rotate } as VaultEntry);
    const entries = [
      mk("fine", T0, null), mk("never", T0, 0), mk("overdue", T0 - 200 * DAY, null),
      mk("soon", T0 - 170 * DAY, null), mk("nodate", null, null),
    ];
    const report = rotationReport(entries, 180, T0);
    expect(report.map((r) => r.service))
      .toEqual(["overdue", "soon", "nodate", "fine", "never"]);
    expect(report.map((r) => r.state))
      .toEqual(["overdue", "due_soon", "unknown", "ok", "off"]);
    expect(rotationDueCount(entries, 180, T0)).toBe(2);
  });
});

// -- session behaviour ------------------------------------------------

describe("VaultSession rotation behaviour", () => {
  it("new entries start their clock; settings default is 180", async () => {
    const s = await VaultSession.createNew(MASTER);
    expect(s.vaultSettings().default_rotate_days).toBe(180);
    const before = Math.floor(Date.now() / 1000);
    const e = await s.addEntry({
      service: "github", username: "octocat", password: "pw-one-123456",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    });
    expect(e.password_set_at).toBeGreaterThanOrEqual(before);
    expect(e.password_set_at).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 1);
    expect(e.rotate_days).toBeNull();
  });

  it("password change resets the clock; other edits never do", async () => {
    const s = await VaultSession.createNew(MASTER);
    const e = await s.addEntry({
      service: "github", username: "octocat", password: "pw-one-123456",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    });
    const old = T0 - 500 * DAY;
    await s.markPasswordChanged(e.id, old);
    expect(s.getEntry(e.id).password_set_at).toBe(old);
    for (const fields of [
      { notes: "rotated via the app" }, { url: "https://example.com" },
      { tags: ["dev"] }, { favourite: true },
      { totp_secret: "JBSWY3DPEHPK3PXP" },
    ]) {
      const updated = await s.updateEntry(e.id, fields);
      expect(updated.password_set_at).toBe(old);
    }
    const changed = await s.updateEntry(e.id, { password: "pw-two-123456" });
    expect(changed.password_set_at).toBeGreaterThan(old);
    // Re-saving the SAME password is not a change.
    const psa = changed.password_set_at;
    const again = await s.updateEntry(e.id, { password: "pw-two-123456" });
    expect(again.password_set_at).toBe(psa);
  });

  it("fields and settings survive a serialize → reopen round trip", async () => {
    const s = await VaultSession.createNew(MASTER);
    const e = await s.addEntry({
      service: "github", username: "octocat", password: "pw-one-123456",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
      rotate_days: 30,
    });
    const backdated = T0 - 10 * DAY;
    await s.markPasswordChanged(e.id, backdated);
    s.setDefaultRotateDays(45);
    const bytes = await s.serialize();
    const reopened = await VaultSession.openWithPassword(bytes, MASTER);
    const entry = reopened.getEntry(e.id);
    expect(entry.password_set_at).toBe(backdated);
    expect(entry.rotate_days).toBe(30);
    expect(reopened.vaultSettings().default_rotate_days).toBe(45);
    // Never as the vault default also round-trips (stored null).
    reopened.setDefaultRotateDays(null);
    const again = await VaultSession.openWithPassword(
      await reopened.serialize(), MASTER);
    expect(again.vaultSettings().default_rotate_days).toBeNull();
  });

  it("rejects invalid rotation periods", async () => {
    const s = await VaultSession.createNew(MASTER);
    const e = await s.addEntry({
      service: "github", username: "", password: "pw-one-123456",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    });
    await expect(s.updateEntry(e.id, { rotate_days: -1 })).rejects.toThrow();
    await expect(s.updateEntry(e.id, { rotate_days: 1.5 })).rejects.toThrow();
    expect(() => s.setDefaultRotateDays(-5)).toThrow();
  });

  it("imports record no date; an import overwrite clears it", async () => {
    const s = await VaultSession.createNew(MASTER);
    const rec = {
      service: "imported", username: "u", password: "pw-imported-1",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    };
    await s.importEntries([rec]);
    expect(s.listEntries()[0]!.password_set_at).toBeNull();
    const victim = await s.addEntry({
      service: "victim", username: "", password: "original-pw-123",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    });
    expect(victim.password_set_at).not.toBeNull();
    await s.importEntries(
      [{ ...rec, service: "victim", username: "", password: "imported-pw-999" }],
      "overwrite",
    );
    const after = s.listEntries().find((x) => x.service === "victim")!;
    expect(after.password).toBe("imported-pw-999");
    expect(after.password_set_at).toBeNull();
  });
});

// -- files written before the feature --------------------------------

async function rewriteSecretBlob(
  session: VaultSession,
  bytes: Uint8Array,
  mutate: (secret: Record<string, unknown>) => void,
): Promise<Uint8Array> {
  const anyS = session as unknown as Record<string, any>;
  const file = JSON.parse(utf8Decode(bytes));
  const obj = file.entries[0];
  const dek = anyS.deks.get(obj.id).pw as Uint8Array;
  const secret = JSON.parse(utf8Decode(
    (await aesGcmDecrypt(dek, obj.secret, utf8Encode(`secret:v3:${obj.id}`)))!,
  ));
  mutate(secret);
  obj.secret = await aesGcmEncrypt(
    dek, utf8Encode(JSON.stringify(secret)), utf8Encode(`secret:v3:${obj.id}`));
  const core = JSON.parse(utf8Decode(
    (await aesGcmDecrypt(anyS.vk, file.core, utf8Encode(`core:v3:${file.vault_id}`)))!,
  ));
  core.entry_hashes[obj.id] = computeEntryHash(obj);
  file.core = await aesGcmEncrypt(
    anyS.vk, utf8Encode(JSON.stringify(core)), utf8Encode(`core:v3:${file.vault_id}`));
  return utf8Encode(JSON.stringify(file));
}

describe("pre-feature and future files", () => {
  it("opens a file whose secret blob has no rotation fields", async () => {
    const s = await VaultSession.createNew(MASTER);
    const e = await s.addEntry({
      service: "github", username: "octocat", password: "pw-one-123456",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    });
    const stripped = await rewriteSecretBlob(s, await s.serialize(), (secret) => {
      delete secret.password_set_at;
      delete secret.rotate_days;
    });
    const fresh = await VaultSession.openWithPassword(stripped, MASTER);
    const entry = fresh.getEntry(e.id);
    // Fallback: the set date is the entry creation time.
    expect(entry.password_set_at).toBe(entry.created);
    expect(entry.rotate_days).toBeNull();
    // A save writes the fields back, and a notes edit keeps the date.
    await fresh.updateEntry(e.id, { notes: "saved by the new client" });
    const again = await VaultSession.openWithPassword(
      await fresh.serialize(), MASTER);
    expect(again.getEntry(e.id).password_set_at).toBe(entry.created);
  });

  it("tolerates unknown fields in the secret blob", async () => {
    const s = await VaultSession.createNew(MASTER);
    const e = await s.addEntry({
      service: "github", username: "octocat", password: "pw-one-123456",
      url: "", notes: "", totp_secret: "", tags: [], favourite: false,
    });
    const withFuture = await rewriteSecretBlob(s, await s.serialize(), (secret) => {
      secret.future_field = { nested: [1, 2, 3] };
    });
    const fresh = await VaultSession.openWithPassword(withFuture, MASTER);
    expect(fresh.getEntry(e.id).password).toBe("pw-one-123456");
    expect(fresh.getEntry(e.id).password_set_at).toBe(e.password_set_at);
  });
});
