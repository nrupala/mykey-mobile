// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// THE LEAK SUITE — the owner's merge gate for this wave. Each test
// is named after the gate it proves. Gates 1, 2, 5 and 6 are ALSO
// proven against the real Python host (desktop pytest suite +
// tests/host-integration.test.ts here); the versions in this file
// prove the extension side end-to-end.

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ALL_SECRETS, GITHUB, MASTER } from "./support/fixtures.js";
import {
  LOGIN_PAGE,
  installPage,
  loadContentEntry,
} from "./support/pages.js";
import { makeWorld, type World } from "./support/setup.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = join(HERE, "..");
const GITHUB_TAB = { id: 7, url: "https://github.com/login" };

let fetchCalls = 0;
const realFetch = globalThis.fetch;

beforeEach(() => {
  fetchCalls = 0;
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("network is forbidden in the extension");
  }) as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  vi.restoreAllMocks();
});

/** Run the full happy-path flow against a world and its page. */
async function fullFlow(
  world: World,
  afterPage?: (dom: ReturnType<typeof installPage>) => void,
) {
  const { api, core } = world;
  const dom = installPage(LOGIN_PAGE, GITHUB_TAB.url);
  afterPage?.(dom);
  await loadContentEntry(api);
  await core.unlock(MASTER);
  await core.matches(GITHUB_TAB);
  await core.fill(GITHUB_TAB, GITHUB.id);
  const totp = await core.totp(GITHUB_TAB, GITHUB.id);
  await core.copyCredentials(GITHUB_TAB, GITHUB.id);
  return { dom, totpCode: totp.code };
}

describe("LEAK GATE 1 — frame capture shows only ciphertext", () => {
  it("no fixture secret appears anywhere in the recorded wire frames", async () => {
    const world = await makeWorld();
    const { totpCode } = await fullFlow(world);
    const wire = world.host.wireLog.join("\n");
    expect(wire).toContain('"ct"'); // the channel really sealed
    for (const secret of [...ALL_SECRETS, totpCode]) {
      expect(wire, `wire leaked: ${secret}`).not.toContain(secret);
    }
  });
});

describe("LEAK GATE 2 — wrong-origin pages get nothing", () => {
  const EVIL = [
    "https://github.com.evil.com/login",
    "https://evil-github.com/login",
    "http://github.com/login",
    "https://github.com:8443/login",
    "https://login.github.com/login", // subdomain, no permission
    "https://github.com@evil.com/login",
  ];

  it("no matches on any lookalike or mismatched origin", async () => {
    const { core } = await makeWorld();
    await core.unlock(MASTER);
    for (const url of EVIL) {
      const res = await core.matches({ id: 3, url });
      expect(res.matches, url).toEqual([]);
    }
  });

  it("an entry bound on the right origin cannot be filled on another", async () => {
    const { core, host } = await makeWorld();
    await core.unlock(MASTER);
    await core.matches(GITHUB_TAB);
    const fillCallsBefore = host.calls.filter((c) => c.kind === "fill").length;
    await expect(
      core.fill({ id: 7, url: "https://example.com/login" }, GITHUB.id),
    ).rejects.toThrow(/different origin/);
    const fillCallsAfter = host.calls.filter((c) => c.kind === "fill").length;
    expect(fillCallsAfter).toBe(fillCallsBefore); // host never even asked
  });
});

describe("LEAK GATE 3 — iframes get nothing; fills hit the top frame", () => {
  it("every script injection targets frame 0 only", async () => {
    const world = await makeWorld();
    await fullFlow(world);
    expect(world.api.scriptCalls.length).toBeGreaterThan(0);
    for (const call of world.api.scriptCalls) {
      expect(call.target.frameIds).toEqual([0]);
    }
  });
});

describe("LEAK GATE 4 — no secret in console, storage, DOM, messages, errors", () => {
  it("console stays clean through the whole flow", async () => {
    const logged: string[] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        logged.push(args.map(String).join(" "));
      });
    }
    const world = await makeWorld();
    await fullFlow(world);
    await world.core
      .unlock("wrong-password")
      .catch((e: Error) => logged.push(e.message));
    const all = logged.join("\n");
    for (const secret of ALL_SECRETS) {
      expect(all, `console leaked: ${secret}`).not.toContain(secret);
    }
  });

  it("extension storage at rest holds no vault secret", async () => {
    const world = await makeWorld();
    await fullFlow(world);
    const dump = `${world.api.local.dump()}\n${world.api.session.dump()}`;
    for (const secret of ALL_SECRETS) {
      expect(dump, `storage leaked: ${secret}`).not.toContain(secret);
    }
  });

  it("the page DOM holds the password only inside the password field", async () => {
    const world = await makeWorld();
    let postSpy: ReturnType<typeof vi.spyOn> | undefined;
    const { dom } = await fullFlow(world, (page) => {
      postSpy = vi.spyOn(page.window, "postMessage");
    });
    const doc = dom.window.document;
    // text anywhere
    expect(doc.body.textContent).not.toContain(GITHUB.password);
    // attribute values anywhere
    const carriers: string[] = [];
    doc.querySelectorAll("*").forEach((el: Element) => {
      for (const attr of el.attributes ?? []) {
        if (attr.value.includes(GITHUB.password)) {
          carriers.push(`${el.tagName}@${attr.name}`);
        }
      }
      if (el instanceof dom.window.HTMLInputElement) {
        const input = el as unknown as HTMLInputElement;
        if (input.value.includes(GITHUB.password)) {
          carriers.push(`${el.tagName}#${input.id}`);
        }
      }
    });
    expect(carriers).toEqual(["INPUT#p"]);
    // window.postMessage was never used by our code during the flow
    expect(postSpy).toBeDefined();
    expect(postSpy).not.toHaveBeenCalled();
  });

  it("error messages carry no secrets", async () => {
    const { core } = await makeWorld();
    const wrong = await core.unlock("wrong-password").catch((e: Error) => e);
    expect(String(wrong)).not.toContain(MASTER);
    expect(String(wrong).length).toBeLessThan(200);
  });
});

describe("LEAK GATE 5 — lock wipes the extension's fill ability", () => {
  it("after lock: no cached plaintext, no fills, no matches", async () => {
    const world = await makeWorld();
    const { core } = world;
    await fullFlow(world);
    expect(core.inspect().boundEntries).toBeGreaterThan(0);
    await core.lock();
    const state = core.inspect();
    expect(state.unlocked).toBe(false);
    expect(state.matchTabs).toBe(0);
    expect(state.boundEntries).toBe(0);
    expect(state.pendingSave).toBe(false);
    await expect(core.fill(GITHUB_TAB, GITHUB.id)).rejects.toThrow();
    await expect(core.matches(GITHUB_TAB)).rejects.toMatchObject({
      code: "locked",
    });
    const dump = `${world.api.local.dump()}\n${world.api.session.dump()}`;
    for (const secret of ALL_SECRETS) {
      expect(dump).not.toContain(secret);
    }
  });

  it("a host-side lock mid-session wipes the cache on the next call", async () => {
    const world = await makeWorld();
    const { core } = world;
    await core.unlock(MASTER);
    await core.matches(GITHUB_TAB);
    expect(core.inspect().boundEntries).toBe(1);
    // Simulate the desktop app going away: status now reports a
    // locked vault on a fresh connection.
    world.host.unlocked = false;
    await expect(core.fill(GITHUB_TAB, GITHUB.id)).rejects.toThrow();
  });
});

describe("LEAK GATE 6 — revoked / expired / disabled pairings are refused", () => {
  it.each(["revoked", "expired", "disabled"] as const)(
    "%s pairing cannot connect",
    async (state) => {
      const world = await makeWorld();
      world.host.pairingState = state;
      await expect(world.core.connect()).rejects.toThrow();
      expect((await world.core.status()).connected).toBe(false);
    },
  );
});

describe("LEAK GATE 8 — zero network requests; minimal manifest", () => {
  it("the whole flow makes no fetch calls", async () => {
    const world = await makeWorld();
    await fullFlow(world);
    expect(fetchCalls).toBe(0);
  });

  it("manifests stay inside the permission allowlist, no host access", () => {
    const allow = new Set([
      "activeTab",
      "alarms",
      "clipboardRead",
      "clipboardWrite",
      "nativeMessaging",
      "offscreen",
      "scripting",
      "storage",
    ]);
    for (const name of ["manifest.chromium.json", "manifest.firefox.json"]) {
      const raw = readFileSync(join(EXT_ROOT, name), "utf8");
      const manifest = JSON.parse(raw) as Record<string, unknown>;
      const perms = manifest.permissions as string[];
      for (const perm of perms) {
        expect(allow.has(perm), `${name}: ${perm}`).toBe(true);
      }
      expect(manifest.host_permissions).toBeUndefined();
      expect(manifest.content_scripts).toBeUndefined();
      expect(raw).not.toContain("<all_urls>");
      // background service/scripts present, no remote code possible
      expect(raw).not.toContain("http://");
      expect(raw).not.toContain("https://");
    }
  });

  it("extension sources contain no network APIs at all", () => {
    const srcDir = join(EXT_ROOT, "src");
    for (const file of readdirSync(srcDir)) {
      if (!file.endsWith(".ts")) continue;
      const text = readFileSync(join(srcDir, file), "utf8");
      for (const banned of ["fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "EventSource"]) {
        expect(text.includes(banned), `${file} uses ${banned}`).toBe(false);
      }
    }
  });
});
