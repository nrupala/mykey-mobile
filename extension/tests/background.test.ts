// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// BackgroundCore behaviour against the fake host: connect, unlock,
// match, fill into a real (jsdom) page through the real content
// module, TOTP, copy, save-capture, subdomain toggle, lock.

import { describe, expect, it } from "vitest";
import { HostRefused } from "../src/channel.js";
import { GITHUB, MASTER } from "./support/fixtures.js";
import {
  LOGIN_PAGE,
  OTP_PAGE,
  installPage,
  loadContentEntry,
} from "./support/pages.js";
import { makeWorld } from "./support/setup.js";

const GITHUB_TAB = { id: 7, url: "https://github.com/login" };

async function unlockedWorld() {
  const world = await makeWorld();
  await world.core.unlock(MASTER);
  return world;
}

describe("BackgroundCore", () => {
  it("connects and reports status; wrong password is refused cleanly", async () => {
    const { core } = await makeWorld();
    await expect(core.unlock("wrong-password")).rejects.toBeInstanceOf(
      HostRefused,
    );
    const status = await core.status();
    expect(status.paired).toBe(true);
    expect(status.connected).toBe(true);
    expect(status.unlocked).toBe(false);
  });

  it("matches entries for the tab origin only", async () => {
    const { core } = await unlockedWorld();
    const res = await core.matches(GITHUB_TAB);
    expect(res.origin).toBe("https://github.com");
    expect(res.matches.map((m) => m.id)).toEqual([GITHUB.id]);
    const bank = await core.matches({
      id: 8,
      url: "https://secure.bank.example:8443/login",
    });
    expect(bank.matches).toHaveLength(1);
    const wrongPort = await core.matches({
      id: 9,
      url: "https://secure.bank.example/login",
    });
    expect(wrongPort.matches).toEqual([]);
  });

  it("fills the page through the real content module, top frame only", async () => {
    const { api, core } = await unlockedWorld();
    const dom = installPage(LOGIN_PAGE, GITHUB_TAB.url);
    await loadContentEntry(api);
    await core.matches(GITHUB_TAB);
    await core.fill(GITHUB_TAB, GITHUB.id);
    const doc = dom.window.document;
    expect((doc.getElementById("u") as HTMLInputElement).value).toBe(
      GITHUB.username,
    );
    expect((doc.getElementById("p") as HTMLInputElement).value).toBe(
      GITHUB.password,
    );
    for (const call of api.scriptCalls) {
      expect(call.target.frameIds).toEqual([0]);
    }
  });

  it("fills a TOTP code as a separate explicit action", async () => {
    const { api, core } = await unlockedWorld();
    const dom = installPage(OTP_PAGE, "https://github.com/verify");
    await loadContentEntry(api);
    const tab = { id: 7, url: "https://github.com/verify" };
    await core.matches(tab);
    const res = await core.totp(tab, GITHUB.id);
    expect(res.filled).toBe(true);
    expect(res.code).toMatch(/^\d{6}$/);
    void dom;
  });

  it("hands credentials to the popup for copying — the core never holds a clipboard copy", async () => {
    const { api, core, clipboard } = await unlockedWorld();
    await core.matches(GITHUB_TAB);
    const creds = await core.copyCredentials(GITHUB_TAB, GITHUB.id);
    expect(creds).toEqual({
      username: GITHUB.username,
      password: GITHUB.password,
    });
    // The popup applies the clipboard rule; the background itself
    // wrote nothing anywhere.
    expect(clipboard.current).toBe("");
    expect(api.session.dump()).not.toContain(GITHUB.password);
    expect(api.local.dump()).not.toContain(GITHUB.password);
  });

  it("captures a same-tab login, prompts in-page, saves on yes", async () => {
    const { api, core, host } = await unlockedWorld();
    api.tabsState.active = { id: 7, url: "https://newsite.example/login" };
    const dom = installPage(LOGIN_PAGE, "https://newsite.example/login");
    await loadContentEntry(api);
    const doc = dom.window.document;
    (doc.getElementById("u") as HTMLInputElement).value = "newuser";
    (doc.getElementById("p") as HTMLInputElement).value = "brand-new-pw-1";
    doc
      .querySelector("form")
      ?.dispatchEvent(new dom.window.Event("submit", { bubbles: true }));
    // The content script reports through runtime messages.
    const captured = api.messageLog.find(
      (m) => (m as { type?: string }).type === "mk-captured",
    ) as { origin: string; username: string; password: string };
    expect(captured).toBeTruthy();
    await core.onCaptured(7, captured);
    const promptCall = api.scriptCalls.find((c) =>
      c.args?.some((a) => typeof a === "string" && a.length >= 16),
    );
    expect(promptCall).toBeTruthy();
    const token = promptCall?.args?.[0] as string;
    const res = await core.saveChoice(token, true);
    expect(res.saved).toBe(true);
    expect(host.savedLogins).toEqual([
      {
        origin: "https://newsite.example",
        username: "newuser",
        password: "brand-new-pw-1",
      },
    ]);
  });

  it("does not prompt when the login is already saved unchanged", async () => {
    const { api, core, host } = await unlockedWorld();
    void api;
    await core.onCaptured(7, {
      origin: "https://github.com",
      username: GITHUB.username,
      password: GITHUB.password,
    });
    expect((await core.status()).pendingSave).toBeNull();
    expect(host.savedLogins).toEqual([]);
  });

  it("holds a cross-tab capture as a pending save until the user decides", async () => {
    const { core, host } = await unlockedWorld();
    await core.onCaptured(7, {
      origin: "https://newsite.example",
      username: "newuser",
      password: "brand-new-pw-1",
    });
    const status = await core.status();
    expect(status.pendingSave?.username).toBe("newuser");
    const res = await core.pendingSaveAction(true);
    expect(res.saved).toBe(true);
    expect(host.savedLogins).toHaveLength(1);
  });

  it("turns on subdomain fills per entry, through the host", async () => {
    const { core, host } = await unlockedWorld();
    const subTab = { id: 11, url: "https://login.example.com/" };
    expect((await core.matches(subTab)).matches).toEqual([]);
    await core.matches({ id: 12, url: "https://example.com/" });
    await core.setSubdomains(
      { id: 12, url: "https://example.com/" },
      "entry-example",
      true,
    );
    expect(host.subdomains.has("entry-example")).toBe(true);
    expect((await core.matches(subTab)).matches).toHaveLength(1);
  });

  it("generates passwords at the desktop's rules (16 minimum, refuses less)", async () => {
    const { core } = await unlockedWorld();
    expect(() => core.generate(4)).toThrow(/at least 16/);
    expect(core.generate(16)).toHaveLength(16);
    expect(core.generate(24)).toHaveLength(24);
  });
});
