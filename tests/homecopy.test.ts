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

/** The vault's home (homecopy wave): the reconciliation decision
 * is the safety core — an older copy must never silently replace
 * a newer one — so the decision matrix is pinned exhaustively,
 * and the service is driven end-to-end over a fake folder
 * adapter: writes on persist, failure honesty (recorded, never
 * silent, never blocking), conflict preservation, setup probes,
 * and recovery detection. The native SAF bridge itself is
 * compile-verified in CI and exercised on a real phone via
 * docs/DEVICE_TEST_VAULT_HOME.md. */

import { describe, expect, it } from "vitest";

import {
  decideReconcile,
  defaultMirrorBook,
  defaultMirrorConfig,
  deriveHomeStatus,
  digestHex,
  HomeCopyService,
  preservedFileName,
  vaultIdOfBytes,
  type HomeCopyAdapter,
  type HomeFolderInfo,
  type MirrorBook,
  type MirrorConfig,
  type MirrorStateStore,
} from "../src/vault/homecopy.js";
import { utf8Encode } from "../src/vault/encoding.js";
import { FAQ_MARKDOWN, HELP_MARKDOWN } from "../src/ui/help.js";

/** Stand-in vault bytes: the header carries the vault id in
 * plaintext, exactly like the real file. */
function vaultBytes(id: string, marker: string): Uint8Array {
  return utf8Encode(JSON.stringify({ vault_id: id, payload: marker }));
}

class FakeAdapter implements HomeCopyAdapter {
  folderName = "My Drive";
  granted = true;
  file: Uint8Array | null = null;
  preserved: Array<{ name: string; bytes: Uint8Array }> = [];
  failWrites = false;
  cancelPick = false;

  async pickFolder(): Promise<{ folderName: string } | null> {
    if (this.cancelPick) return null;
    this.granted = true;
    return { folderName: this.folderName };
  }

  async folderInfo(): Promise<HomeFolderInfo | null> {
    if (!this.granted) return null;
    return {
      folderName: this.folderName,
      hasFile: this.file !== null,
      modifiedAt: null,
      size: this.file ? this.file.length : null,
    };
  }

  async readHomeFile(): Promise<Uint8Array | null> {
    return this.file;
  }

  async writeHomeFile(bytes: Uint8Array): Promise<void> {
    if (this.failWrites) throw new Error("folder is gone");
    this.file = bytes;
  }

  async writePreservedFile(bytes: Uint8Array, name: string): Promise<void> {
    this.preserved.push({ name, bytes });
  }

  async forgetFolder(): Promise<void> {
    this.granted = false;
  }
}

class MemStates implements MirrorStateStore {
  cfg: MirrorConfig = defaultMirrorConfig();
  bk: MirrorBook = defaultMirrorBook();
  async getConfig(): Promise<MirrorConfig> {
    return { ...this.cfg };
  }
  async setConfig(c: MirrorConfig): Promise<void> {
    this.cfg = { ...c };
  }
  async getBook(): Promise<MirrorBook> {
    return { ...this.bk };
  }
  async setBook(b: MirrorBook): Promise<void> {
    this.bk = { ...b };
  }
}

function enabledSetup(): { adapter: FakeAdapter; states: MemStates; svc: HomeCopyService } {
  const adapter = new FakeAdapter();
  const states = new MemStates();
  states.cfg = {
    enabled: true,
    folderName: "My Drive",
    vaultId: "vault-1",
    offeredForVaultId: "vault-1",
  };
  return { adapter, states, svc: new HomeCopyService(adapter, states) };
}

describe("decideReconcile", () => {
  const A = vaultBytes("vault-1", "a");
  const B = vaultBytes("vault-1", "b");
  const C = vaultBytes("vault-1", "c");
  const bookAB: MirrorBook = {
    ...defaultMirrorBook(),
    vaultId: "vault-1",
    cacheDigest: digestHex(A),
    homeDigest: digestHex(A),
  };
  const decide = (
    cache: Uint8Array,
    home: Uint8Array | null,
    book: MirrorBook = bookAB,
    cacheId: string | null = "vault-1",
    homeId: string | null = "vault-1",
  ) =>
    decideReconcile({
      cacheDigest: digestHex(cache),
      cacheVaultId: cacheId,
      homeDigest: home ? digestHex(home) : null,
      homeVaultId: homeId,
      book,
    }).kind;

  it("no home file is no-home", () => {
    expect(decide(A, null)).toBe("no-home");
  });

  it("identical copies are in sync", () => {
    expect(decide(A, A)).toBe("in-sync");
  });

  it("only the home copy moved: home is newer", () => {
    expect(decide(A, B)).toBe("home-newer");
  });

  it("only the device copy moved: cache is newer", () => {
    expect(decide(B, A)).toBe("cache-newer");
  });

  it("both copies moved: conflict, never a guess", () => {
    expect(decide(B, C)).toBe("conflict");
  });

  it("a different vault's home file is recognised before anything else", () => {
    expect(decide(A, B, bookAB, "vault-1", "vault-2")).toBe("different-vault");
  });

  it("bookkeeping from another vault earns no agreement point", () => {
    const foreignBook: MirrorBook = {
      ...defaultMirrorBook(),
      vaultId: "vault-9",
      cacheDigest: digestHex(A),
      homeDigest: digestHex(A),
    };
    // With no valid agreement point, two differing copies can
    // only be a conflict — the conservative answer.
    expect(decide(A, B, foreignBook)).toBe("conflict");
  });
});

describe("small pure pieces", () => {
  it("vaultIdOfBytes reads the plaintext header and rejects junk", () => {
    expect(vaultIdOfBytes(vaultBytes("vault-7", "x"))).toBe("vault-7");
    expect(vaultIdOfBytes(utf8Encode("not json"))).toBeNull();
    expect(vaultIdOfBytes(null)).toBeNull();
  });

  it("preservedFileName is dated and provider-safe", () => {
    const name = preservedFileName(new Date(2026, 9, 14, 15, 30, 22));
    expect(name).toBe("vault-conflict-20261014-153022.mykey");
  });

  it("status lines speak plainly", () => {
    const notSetup = deriveHomeStatus({
      supported: true,
      configured: false,
      config: defaultMirrorConfig(),
      book: defaultMirrorBook(),
    });
    expect(notSetup.kind).toBe("not-setup");
    expect(notSetup.line).toContain("only copy is inside the app");

    const off = deriveHomeStatus({
      supported: true,
      configured: true,
      config: { ...defaultMirrorConfig(), enabled: false, folderName: "My Drive" },
      book: defaultMirrorBook(),
    });
    expect(off.kind).toBe("off");
    expect(off.line).toContain("stays in the folder until you delete it yourself");

    const ok = deriveHomeStatus({
      supported: true,
      configured: true,
      config: { ...defaultMirrorConfig(), enabled: true, folderName: "My Drive" },
      book: { ...defaultMirrorBook(), lastWriteAt: Date.now() },
    });
    expect(ok.kind).toBe("ok");
    expect(ok.line).toContain("My Drive");
    expect(ok.line).toContain("updated");
  });
});

describe("HomeCopyService writes", () => {
  it("writes the home file on persist and records the agreement", async () => {
    const { adapter, states, svc } = enabledSetup();
    const bytes = vaultBytes("vault-1", "v1");
    await svc.afterPersist(bytes);
    expect(adapter.file).toEqual(bytes);
    expect(states.bk.cacheDigest).toBe(digestHex(bytes));
    expect(states.bk.homeDigest).toBe(digestHex(bytes));
    expect(states.bk.lastWriteAt).not.toBeNull();
    expect(states.bk.lastError).toBeNull();
  });

  it("does nothing while turned off", async () => {
    const { adapter, states, svc } = enabledSetup();
    states.cfg = { ...states.cfg, enabled: false };
    await svc.afterPersist(vaultBytes("vault-1", "v1"));
    expect(adapter.file).toBeNull();
  });

  it("a failed write is recorded and noticed once — never silent, never thrown", async () => {
    const { adapter, states, svc } = enabledSetup();
    adapter.failWrites = true;
    await svc.afterPersist(vaultBytes("vault-1", "v1")); // must not throw
    expect(states.bk.lastError).toContain("folder is gone");
    const notice = await svc.takePendingNotice();
    expect(notice).toContain("could not be updated");
    expect(await svc.takePendingNotice()).toBeNull();
  });

  it("never writes during an unresolved conflict", async () => {
    const { adapter, states, svc } = enabledSetup();
    const homeBefore = vaultBytes("vault-1", "home");
    adapter.file = homeBefore;
    states.bk = {
      ...states.bk,
      conflict: { cacheDigest: "x", homeDigest: "y", detectedAt: Date.now() },
    };
    await svc.afterPersist(vaultBytes("vault-1", "device"));
    expect(adapter.file).toEqual(homeBefore);
  });

  it("never writes another vault's home", async () => {
    const { adapter, states, svc } = enabledSetup();
    states.cfg = { ...states.cfg, vaultId: "vault-2" };
    await svc.afterPersist(vaultBytes("vault-1", "v1"));
    expect(adapter.file).toBeNull();
  });
});

describe("HomeCopyService reconcile", () => {
  it("an empty home folder receives the device copy", async () => {
    const { adapter, svc } = enabledSetup();
    const bytes = vaultBytes("vault-1", "v1");
    const rec = await svc.reconcile(bytes);
    expect(rec.decision.kind).toBe("cache-newer");
    expect(adapter.file).toEqual(bytes);
  });

  it("a newer home file wins and is handed to the caller", async () => {
    const { adapter, states, svc } = enabledSetup();
    const agreed = vaultBytes("vault-1", "agreed");
    const homeNewer = vaultBytes("vault-1", "home-moved");
    states.bk = {
      ...states.bk,
      vaultId: "vault-1",
      cacheDigest: digestHex(agreed),
      homeDigest: digestHex(agreed),
    };
    adapter.file = homeNewer;
    const rec = await svc.reconcile(agreed);
    expect(rec.decision.kind).toBe("home-newer");
    expect(rec.homeBytes).toEqual(homeNewer);
    // Bookkeeping already expects the swap.
    expect(states.bk.cacheDigest).toBe(digestHex(homeNewer));
  });

  it("both copies moved: conflict recorded, nothing overwritten", async () => {
    const { adapter, states, svc } = enabledSetup();
    const agreed = vaultBytes("vault-1", "agreed");
    const homeMoved = vaultBytes("vault-1", "home-moved");
    states.bk = {
      ...states.bk,
      vaultId: "vault-1",
      cacheDigest: digestHex(agreed),
      homeDigest: digestHex(agreed),
    };
    adapter.file = homeMoved;
    const rec = await svc.reconcile(vaultBytes("vault-1", "device-moved"));
    expect(rec.decision.kind).toBe("conflict");
    expect(states.bk.conflict).not.toBeNull();
    expect(adapter.file).toEqual(homeMoved);
  });

  it("a different vault in the folder: hands off, flagged, nothing written", async () => {
    const { adapter, states, svc } = enabledSetup();
    const foreign = vaultBytes("vault-2", "foreign");
    adapter.file = foreign;
    const rec = await svc.reconcile(vaultBytes("vault-1", "mine"));
    expect(rec.decision.kind).toBe("different-vault");
    expect(states.bk.foreignHome).toBe(true);
    expect(adapter.file).toEqual(foreign);
  });
});

describe("conflict resolution", () => {
  it("device wins: the home copy is preserved, then replaced", async () => {
    const { adapter, states, svc } = enabledSetup();
    const device = vaultBytes("vault-1", "device");
    const home = vaultBytes("vault-1", "home");
    adapter.file = home;
    states.bk = {
      ...states.bk,
      conflict: {
        cacheDigest: digestHex(device),
        homeDigest: digestHex(home),
        detectedAt: Date.now(),
      },
    };
    await svc.resolveConflict("device", device, home);
    expect(adapter.preserved).toHaveLength(1);
    expect(adapter.preserved[0]!.bytes).toEqual(home);
    expect(adapter.preserved[0]!.name).toMatch(/^vault-conflict-\d{8}-\d{6}\.mykey$/);
    expect(adapter.file).toEqual(device);
    expect(states.bk.conflict).toBeNull();
  });

  it("home wins: the device copy is preserved, the home file untouched", async () => {
    const { adapter, states, svc } = enabledSetup();
    const device = vaultBytes("vault-1", "device");
    const home = vaultBytes("vault-1", "home");
    adapter.file = home;
    await svc.resolveConflict("home", device, home);
    expect(adapter.preserved[0]!.bytes).toEqual(device);
    expect(adapter.file).toEqual(home);
    expect(states.bk.conflict).toBeNull();
    expect(states.bk.cacheDigest).toBe(digestHex(home));
  });
});

describe("setup probes", () => {
  it("empty folder: setup writes the current vault and enables", async () => {
    const adapter = new FakeAdapter();
    const states = new MemStates();
    const svc = new HomeCopyService(adapter, states);
    const current = vaultBytes("vault-1", "v1");
    const probe = await svc.pickAndProbe(current);
    expect(probe?.kind).toBe("empty");
    await svc.completeSetup(current, probe!);
    expect(adapter.file).toEqual(current);
    expect(states.cfg.enabled).toBe(true);
    expect(states.cfg.vaultId).toBe("vault-1");
  });

  it("a different vault's folder is refused, loudly", async () => {
    const adapter = new FakeAdapter();
    adapter.file = vaultBytes("vault-2", "foreign");
    const states = new MemStates();
    const svc = new HomeCopyService(adapter, states);
    const current = vaultBytes("vault-1", "v1");
    const probe = await svc.pickAndProbe(current);
    expect(probe?.kind).toBe("different-vault");
    await expect(svc.completeSetup(current, probe!)).rejects.toThrow(
      "different vault",
    );
    expect(states.cfg.enabled).toBe(false);
  });

  it("same vault, different bytes, device chosen: folder copy preserved first", async () => {
    const adapter = new FakeAdapter();
    const homeOld = vaultBytes("vault-1", "home-old");
    adapter.file = homeOld;
    const states = new MemStates();
    const svc = new HomeCopyService(adapter, states);
    const current = vaultBytes("vault-1", "device-current");
    const probe = await svc.pickAndProbe(current);
    expect(probe?.kind).toBe("same-vault-diff");
    await svc.completeSetup(current, probe!, "device");
    expect(adapter.preserved[0]!.bytes).toEqual(homeOld);
    expect(adapter.file).toEqual(current);
  });

  it("same vault, different bytes, home chosen: home bytes come back", async () => {
    const adapter = new FakeAdapter();
    const homeOld = vaultBytes("vault-1", "home-old");
    adapter.file = homeOld;
    const states = new MemStates();
    const svc = new HomeCopyService(adapter, states);
    const current = vaultBytes("vault-1", "device-current");
    const probe = await svc.pickAndProbe(current);
    const back = await svc.completeSetup(current, probe!, "home");
    expect(back).toEqual(homeOld);
    expect(adapter.file).toEqual(homeOld);
  });

  it("no vault on the device: a found file is a recovery candidate", async () => {
    const adapter = new FakeAdapter();
    adapter.file = vaultBytes("vault-1", "stranded");
    const states = new MemStates();
    const svc = new HomeCopyService(adapter, states);
    const probe = await svc.pickAndProbe(null);
    expect(probe?.kind).toBe("found");
    const candidate = await svc.recoveryCandidate();
    expect(candidate?.folderName).toBe("My Drive");
    expect(candidate?.bytes).toEqual(adapter.file);
  });

  it("no home file, no offer: recovery candidate is null", async () => {
    const { svc } = enabledSetup();
    expect(await svc.recoveryCandidate()).toBeNull();
  });
});

describe("the offer", () => {
  it("is made once per vault, and never where no home can exist", async () => {
    const states = new MemStates();
    const svc = new HomeCopyService(new FakeAdapter(), states);
    expect(await svc.offerNeeded("vault-1")).toBe(true);
    await svc.markOffered("vault-1");
    expect(await svc.offerNeeded("vault-1")).toBe(false);
    expect(await svc.offerNeeded("vault-2")).toBe(true);

    const webSvc = new HomeCopyService(null, states);
    expect(webSvc.supported()).toBe(false);
    expect(await webSvc.offerNeeded("vault-1")).toBe(false);
  });
});

describe("help text states the home model", () => {
  it("HELP carries the owner's line and the uninstall truth", () => {
    expect(HELP_MARKDOWN).toContain(
      "Your vault is a file. MyKey is its opener. The file alone opens nothing.",
    );
    expect(HELP_MARKDOWN).toContain("removing the app does not remove your vault");
  });

  it("FAQ answers the uninstall question with the home model", () => {
    expect(FAQ_MARKDOWN).toContain("What happens if I uninstall the app?");
    expect(FAQ_MARKDOWN).toContain("uninstalling removes only the app");
    expect(FAQ_MARKDOWN).toContain(
      "If you never gave your vault a home, the only copy was the working copy inside the app",
    );
  });
});
