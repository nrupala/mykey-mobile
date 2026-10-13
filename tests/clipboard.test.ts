// Clipboard self-clear rule (owner directive, 2026-10-13).
//
// A copied secret stays on the clipboard 60 seconds by default;
// the user may set 60–300 seconds; anything outside is clamped at
// the single validation point. The guard clears only what it put
// there, lock clears immediately, and a re-copy restarts the timer.
//
// Every copy action in src/ui/app.ts (passwords, TOTP codes,
// recovery material) routes through copySecret → clipboardGuard,
// so exercising the guard with a password and with a TOTP code
// covers both paths.

import { describe, expect, it } from "vitest";
import {
  CLIPBOARD_CLEAR_DEFAULT_SECONDS,
  CLIPBOARD_CLEAR_MAX_SECONDS,
  CLIPBOARD_CLEAR_MIN_SECONDS,
  ClipboardGuard,
  clampClipboardClearSeconds,
  type ClipboardBackend,
} from "../src/platform/clipboard.js";
import { DEFAULT_SETTINGS } from "../src/vault/store.js";

class FakeBackend implements ClipboardBackend {
  content = "";
  failRead = false;
  async write(text: string): Promise<void> {
    this.content = text;
  }
  async read(): Promise<string> {
    if (this.failRead) throw new Error("browser refused clipboard read");
    return this.content;
  }
  async clear(): Promise<void> {
    this.content = "";
  }
}

/** Manual clock: timers fire only when advance() reaches them. */
class ManualTimers {
  private now = 0;
  private seq = 0;
  private pending = new Map<number, { at: number; fn: () => void }>();

  set = (fn: () => void, ms: number): ReturnType<typeof setTimeout> => {
    const id = ++this.seq;
    this.pending.set(id, { at: this.now + ms, fn });
    return id as unknown as ReturnType<typeof setTimeout>;
  };

  clear = (id: ReturnType<typeof setTimeout>): void => {
    this.pending.delete(id as unknown as number);
  };

  advance(ms: number): void {
    const target = this.now + ms;
    for (;;) {
      let nextId: number | null = null;
      let nextAt = Infinity;
      for (const [id, t] of this.pending) {
        if (t.at <= target && t.at < nextAt) {
          nextAt = t.at;
          nextId = id;
        }
      }
      if (nextId === null) break;
      const t = this.pending.get(nextId)!;
      this.pending.delete(nextId);
      this.now = t.at;
      t.fn();
    }
    this.now = target;
  }
}

async function flush(): Promise<void> {
  for (let i = 0; i < 5; i++) {
    await new Promise<void>((r) => setImmediate(r));
  }
}

function makeGuard() {
  const backend = new FakeBackend();
  const timers = new ManualTimers();
  const guard = new ClipboardGuard(backend, timers);
  return { guard, backend, timers };
}

describe("clipboard clear delay — the constant and its bounds", () => {
  it("defaults to 60 seconds, in the module and in app settings", () => {
    expect(CLIPBOARD_CLEAR_DEFAULT_SECONDS).toBe(60);
    expect(DEFAULT_SETTINGS.clipboardClearSeconds).toBe(60);
  });

  it("bounds are 60 and 300", () => {
    expect(CLIPBOARD_CLEAR_MIN_SECONDS).toBe(60);
    expect(CLIPBOARD_CLEAR_MAX_SECONDS).toBe(300);
  });

  it("clamps values below 60 and above 300 instead of accepting them", () => {
    expect(clampClipboardClearSeconds(59)).toBe(60);
    expect(clampClipboardClearSeconds(301)).toBe(300);
    expect(clampClipboardClearSeconds(0)).toBe(60);
    expect(clampClipboardClearSeconds(10_000)).toBe(300);
  });

  it("honours in-bounds values", () => {
    expect(clampClipboardClearSeconds(60)).toBe(60);
    expect(clampClipboardClearSeconds(120)).toBe(120);
    expect(clampClipboardClearSeconds(300)).toBe(300);
  });

  it("falls back to the default on garbage", () => {
    expect(clampClipboardClearSeconds(undefined)).toBe(60);
    expect(clampClipboardClearSeconds(NaN)).toBe(60);
    expect(clampClipboardClearSeconds("abc")).toBe(60);
  });
});

describe("ClipboardGuard", () => {
  it("clears at exactly 60 seconds by default", async () => {
    const { guard, backend, timers } = makeGuard();
    await guard.copy("s3cret", CLIPBOARD_CLEAR_DEFAULT_SECONDS);
    timers.advance(59_999);
    await flush();
    expect(backend.content).toBe("s3cret");
    timers.advance(1);
    await flush();
    expect(backend.content).toBe("");
    expect(guard.hasPending).toBe(false);
  });

  it("uses the configured value (120s honoured, not the default)", async () => {
    const { guard, backend, timers } = makeGuard();
    await guard.copy("s3cret", 120);
    timers.advance(60_000);
    await flush();
    expect(backend.content).toBe("s3cret");
    timers.advance(60_000);
    await flush();
    expect(backend.content).toBe("");
  });

  it("does NOT clear content the user copied afterwards", async () => {
    const { guard, backend, timers } = makeGuard();
    await guard.copy("s3cret", 60);
    backend.content = "something the user copied elsewhere";
    timers.advance(60_000);
    await flush();
    expect(backend.content).toBe("something the user copied elsewhere");
  });

  it("lock (clearNow) clears immediately, whatever the setting", async () => {
    const { guard, backend, timers } = makeGuard();
    await guard.copy("s3cret", 300);
    await guard.clearNow();
    expect(backend.content).toBe("");
    expect(guard.hasPending).toBe(false);
    timers.advance(300_000); // the dead timer must not act later
    await flush();
    expect(backend.content).toBe("");
  });

  it("clearNow still respects the match guard", async () => {
    const { guard, backend } = makeGuard();
    await guard.copy("s3cret", 60);
    backend.content = "not ours anymore";
    await guard.clearNow();
    expect(backend.content).toBe("not ours anymore");
  });

  it("a new copy restarts the timer", async () => {
    const { guard, backend, timers } = makeGuard();
    await guard.copy("first", 60);
    timers.advance(50_000);
    await guard.copy("second", 60);
    timers.advance(10_000); // first copy's deadline passes here
    await flush();
    expect(backend.content).toBe("second");
    timers.advance(50_000); // second copy's own 60s now elapse
    await flush();
    expect(backend.content).toBe("");
  });

  it("a TOTP code copy follows the same rule", async () => {
    const { guard, backend, timers } = makeGuard();
    await guard.copy("287082", 60); // a sign-in code, same path as passwords
    timers.advance(60_000);
    await flush();
    expect(backend.content).toBe("");
  });

  it("degrades honestly when the clipboard cannot be read", async () => {
    const { guard, backend, timers } = makeGuard();
    await guard.copy("s3cret", 60);
    backend.failRead = true;
    timers.advance(60_000);
    await flush();
    // Unverifiable = not ours to wipe; nothing was falsely cleared.
    expect(backend.content).toBe("s3cret");
    expect(guard.hasPending).toBe(false);
  });
});
