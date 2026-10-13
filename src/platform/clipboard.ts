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

/** Clipboard self-clear for copied secrets.
 *
 * The rule (owner directive, 2026-10-13 — restricting leakage):
 * a password copied from the app stays on the clipboard for a
 * short, bounded time — 1 minute by default — then clears itself.
 * The user may choose a longer delay, but only inside hard bounds:
 * never less than 60 seconds, never more than 300. Values outside
 * the bounds are clamped at the single validation point in this
 * module (`clampClipboardClearSeconds`), never silently accepted.
 *
 * Behaviour:
 * - copying a secret starts the timer; copying again restarts it;
 * - when the timer fires, the clipboard is cleared ONLY if its
 *   current content is still exactly what the app put there —
 *   anything the user copied afterwards, from anywhere, is left
 *   untouched;
 * - locking the vault clears a pending copied secret immediately
 *   (same content-still-matches guard).
 *
 * Platforms: on Android the copy goes through the app's own
 * SensitiveClipboard plugin, which marks the clip sensitive
 * (ClipboardManager EXTRA_IS_SENSITIVE) so system previews and
 * keyboard history treat it as a secret. On the web/PWA the async
 * Clipboard API is used; some browsers refuse to read or overwrite
 * the clipboard without focus/permission — then the clear honestly
 * does not happen (the timer still fired; we never claim a clear
 * we could not perform) and the paste-target app keeps whatever
 * the user last copied there by hand.
 */

import { Capacitor, registerPlugin } from "@capacitor/core";

// Leakage rule bounds (owner, 2026-10-13): 60s default, 60–300s.
export const CLIPBOARD_CLEAR_DEFAULT_SECONDS = 60;
export const CLIPBOARD_CLEAR_MIN_SECONDS = 60;
export const CLIPBOARD_CLEAR_MAX_SECONDS = 300;

/** The single validation point for the clear delay. */
export function clampClipboardClearSeconds(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return CLIPBOARD_CLEAR_DEFAULT_SECONDS;
  return Math.max(
    CLIPBOARD_CLEAR_MIN_SECONDS,
    Math.min(CLIPBOARD_CLEAR_MAX_SECONDS, Math.round(n)),
  );
}

// ------------------------------------------------------------------
// Backends
// ------------------------------------------------------------------

export interface ClipboardBackend {
  write(text: string): Promise<void>;
  read(): Promise<string>;
  clear(): Promise<void>;
}

interface SensitiveClipboardPlugin {
  write(options: { value: string }): Promise<void>;
  read(): Promise<{ value: string }>;
  clear(): Promise<void>;
}

/** Native plugin implemented in the Android app project
 * (SensitiveClipboardPlugin.java); only invoked on native. */
const SensitiveClipboard =
  registerPlugin<SensitiveClipboardPlugin>("SensitiveClipboard");

const nativeBackend: ClipboardBackend = {
  async write(text) {
    await SensitiveClipboard.write({ value: text });
  },
  async read() {
    const r = await SensitiveClipboard.read();
    return r.value ?? "";
  },
  async clear() {
    await SensitiveClipboard.clear();
  },
};

const webBackend: ClipboardBackend = {
  async write(text) {
    await navigator.clipboard.writeText(text);
  },
  async read() {
    return navigator.clipboard.readText();
  },
  async clear() {
    await navigator.clipboard.writeText("");
  },
};

export function defaultClipboardBackend(): ClipboardBackend {
  return Capacitor.isNativePlatform() ? nativeBackend : webBackend;
}

// ------------------------------------------------------------------
// The guard
// ------------------------------------------------------------------

interface TimerFns {
  set: (fn: () => void, ms: number) => ReturnType<typeof setTimeout>;
  clear: (id: ReturnType<typeof setTimeout>) => void;
}

const realTimers: TimerFns = {
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (id) => clearTimeout(id),
};

/** Owns the one pending copied secret and its clear timer.
 * Backend and timers are injectable for tests. */
export class ClipboardGuard {
  private pending: string | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private backend: ClipboardBackend,
    private timers: TimerFns = realTimers,
  ) {}

  get hasPending(): boolean {
    return this.pending !== null;
  }

  /** Place a secret on the clipboard and arm its clear timer.
   * Throws if the platform refused the write (caller reports it). */
  async copy(value: string, seconds: number): Promise<void> {
    await this.backend.write(value);
    this.pending = value;
    this.restart(clampClipboardClearSeconds(seconds));
  }

  /** Lock path: clear the pending secret now, not at timer expiry. */
  async clearNow(): Promise<void> {
    this.stopTimer();
    const value = this.pending;
    this.pending = null;
    if (value !== null) await this.clearIfCurrent(value);
  }

  private restart(seconds: number): void {
    this.stopTimer();
    this.timer = this.timers.set(() => {
      void this.expire();
    }, seconds * 1000);
  }

  private stopTimer(): void {
    if (this.timer !== null) {
      this.timers.clear(this.timer);
      this.timer = null;
    }
  }

  private async expire(): Promise<void> {
    this.timer = null;
    const value = this.pending;
    this.pending = null;
    if (value !== null) await this.clearIfCurrent(value);
  }

  /** Clear only if the clipboard still holds exactly what we put
   * there. A failed read means "not verifiably ours" — leave the
   * clipboard alone rather than wipe something the user copied. */
  private async clearIfCurrent(value: string): Promise<void> {
    try {
      const current = await this.backend.read();
      if (current === value) await this.backend.clear();
    } catch {
      /* clipboard unreadable or clear refused — leave it */
    }
  }
}

/** The app-wide guard used by every copy action (passwords, TOTP
 * codes, recovery material all route through it via copySecret). */
export const clipboardGuard = new ClipboardGuard(defaultClipboardBackend());
