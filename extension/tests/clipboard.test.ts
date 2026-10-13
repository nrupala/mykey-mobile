// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// The house clipboard rule: clear after N seconds (60-300, default
// 60), only if the clipboard still holds what we put there; clear
// immediately on lock; never keep the copied value itself around.

import { describe, expect, it } from "vitest";
import {
  CLIPBOARD_SESSION_KEY,
  clampClipboardSeconds,
  clearClipboardNow,
  copySecretWithClear,
  runClipboardClear,
} from "../src/clipboard.js";
import { FakeStorageArea } from "./support/fakeapi.js";

function deps(now = 1_000_000) {
  const state = {
    current: "",
    alarms: [] as number[],
    session: new FakeStorageArea(),
    nowValue: now,
  };
  return {
    state,
    api: {
      writeText: async (t: string) => {
        state.current = t;
      },
      readText: async () => state.current,
      session: state.session,
      setAlarm: (when: number) => state.alarms.push(when),
      now: () => state.nowValue,
    },
  };
}

describe("clampClipboardSeconds", () => {
  it("enforces the 60-300 window with a 60 default", () => {
    expect(clampClipboardSeconds(Number.NaN)).toBe(60);
    expect(clampClipboardSeconds(30)).toBe(60);
    expect(clampClipboardSeconds(9999)).toBe(300);
    expect(clampClipboardSeconds(120)).toBe(120);
  });
});

describe("copy + timed clear", () => {
  it("stores only a hash + deadline, never the secret", async () => {
    const { state, api } = deps();
    await copySecretWithClear(api, "FIXTURE-PW-ALPHA-123", 60);
    const dump = state.session.dump();
    expect(dump).not.toContain("FIXTURE-PW-ALPHA-123");
    expect(state.alarms).toEqual([1_000_000 + 60_000]);
    const pending = state.session.data.get(CLIPBOARD_SESSION_KEY) as {
      hash: string;
      deadline: number;
    };
    expect(pending.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(pending.deadline).toBe(1_060_000);
  });

  it("clears when the clipboard still holds our copy", async () => {
    const { state, api } = deps();
    await copySecretWithClear(api, "FIXTURE-PW-ALPHA-123", 60);
    state.nowValue += 61_000;
    expect(await runClipboardClear(api)).toBe("cleared");
    expect(state.current).toBe("");
    expect(state.session.data.has(CLIPBOARD_SESSION_KEY)).toBe(false);
  });

  it("leaves the user's newer clipboard content alone", async () => {
    const { state, api } = deps();
    await copySecretWithClear(api, "FIXTURE-PW-ALPHA-123", 60);
    state.current = "something the user copied later";
    state.nowValue += 61_000;
    expect(await runClipboardClear(api)).toBe("left-newer-content");
    expect(state.current).toBe("something the user copied later");
  });

  it("clears immediately on lock regardless of the timer", async () => {
    const { state, api } = deps();
    await copySecretWithClear(api, "FIXTURE-PW-ALPHA-123", 300);
    await clearClipboardNow(api);
    expect(state.current).toBe("");
    expect(state.session.data.has(CLIPBOARD_SESSION_KEY)).toBe(false);
  });
});
