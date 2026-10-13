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

/** The house clipboard rule, extension side: a copied secret clears
 * itself after a bounded delay (default 60s, settable on the
 * desktop between 60 and 300 — the host reports the current value
 * in its status, and it is the single source of truth).
 *
 * Clearing discipline:
 * - Only the SHA-256 of the copied value is kept (in session
 *   storage) alongside the deadline — never the secret itself.
 * - At the deadline, the clearer reads the clipboard back where the
 *   platform allows and overwrites ONLY if the content still hashes
 *   to what we copied. If the platform cannot read the clipboard
 *   back at all, it overwrites anyway: the promise made to the user
 *   ("this clears after N seconds") outranks the small chance of
 *   replacing something they copied in the meantime, and that
 *   fallback is documented rather than silent.
 * - On vault lock, any pending copied secret is cleared immediately
 *   through the same path.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { utf8Encode } from "../../src/vault/encoding.js";
import type { StorageArea } from "./webext.js";

export const CLIPBOARD_ALARM = "mykey-clipboard-clear";
export const CLIPBOARD_SESSION_KEY = "mkclip.pending";

export const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 60;
export const MIN_CLIPBOARD_CLEAR_SECONDS = 60;
export const MAX_CLIPBOARD_CLEAR_SECONDS = 300;

export function clampClipboardSeconds(value: number): number {
  if (!Number.isFinite(value)) return DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  return Math.min(
    MAX_CLIPBOARD_CLEAR_SECONDS,
    Math.max(MIN_CLIPBOARD_CLEAR_SECONDS, Math.floor(value)),
  );
}

export function hashForClipboard(text: string): string {
  return Array.from(sha256(utf8Encode(text)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface ClipboardDeps {
  writeText(text: string): Promise<void>;
  readText(): Promise<string | null>; // null = platform cannot read back
  session: StorageArea;
  setAlarm(when: number): void;
  now(): number;
}

/** Copy a secret and schedule its clearing. */
export async function copySecretWithClear(
  deps: ClipboardDeps,
  text: string,
  seconds: number,
): Promise<void> {
  const bounded = clampClipboardSeconds(seconds);
  await deps.writeText(text);
  await deps.session.set({
    [CLIPBOARD_SESSION_KEY]: {
      hash: hashForClipboard(text),
      deadline: deps.now() + bounded * 1000,
    },
  });
  deps.setAlarm(deps.now() + bounded * 1000);
}

/** Run one clearing pass. Returns what happened, for tests and for
 * the options page's honest status line. */
export async function runClipboardClear(
  deps: ClipboardDeps,
): Promise<"cleared" | "left-newer-content" | "nothing-pending" | "cleared-unverified"> {
  const stored = await deps.session.get([CLIPBOARD_SESSION_KEY]);
  const pending = stored[CLIPBOARD_SESSION_KEY] as
    | { hash: string; deadline: number }
    | undefined;
  if (!pending) return "nothing-pending";
  if (deps.now() < pending.deadline) return "nothing-pending";
  const current = await deps.readText();
  await deps.session.remove([CLIPBOARD_SESSION_KEY]);
  if (current === null) {
    await deps.writeText("");
    return "cleared-unverified";
  }
  if (hashForClipboard(current) !== pending.hash) {
    return "left-newer-content";
  }
  await deps.writeText("");
  return "cleared";
}

/** Lock-time clear: ignore the deadline, apply the same
 * hash discipline right now. */
export async function clearClipboardNow(deps: ClipboardDeps): Promise<void> {
  const stored = await deps.session.get([CLIPBOARD_SESSION_KEY]);
  const pending = stored[CLIPBOARD_SESSION_KEY] as
    | { hash: string; deadline: number }
    | undefined;
  if (!pending) return;
  await deps.session.set({
    [CLIPBOARD_SESSION_KEY]: { ...pending, deadline: 0 },
  });
  await runClipboardClear(deps);
}
