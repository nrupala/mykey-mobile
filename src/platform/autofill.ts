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

/** Android autofill bridge — talks to the app's own native
 * MyKeyAutofill Capacitor plugin (Kotlin, in the android/ module).
 *
 * The shape of the flow (see docs/FEATURE_MATRIX.md):
 *  - The native AutofillService answers Android with a single
 *    dataset that carries no secrets — only an authentication
 *    intent. Tapping it opens the auth activity, which brings this
 *    app forward with a one-time request token.
 *  - This layer then runs the normal unlock + chooser in the web
 *    UI, and hands the chosen username/password back through
 *    completeFill(). Secrets cross the bridge only at that moment,
 *    in-process, after the user's tap — they are never placed in
 *    datasets, labels, intents, or storage by the native side.
 *  - Save requests work the other way: the native service keeps
 *    the just-typed credentials in memory only (never on disk);
 *    this layer fetches them once the user is inside the unlocked
 *    app and confirms the new entry.
 *
 * In the pure web PWA none of this exists and every call is a
 * no-op/null — Android only.
 */

import { Capacitor, registerPlugin } from "@capacitor/core";
import type { AutofillTarget } from "../vault/autofill.js";
import { isNativeApp } from "./biometric.js";

export interface AutofillRequest extends AutofillTarget {
  kind: "fill";
  token: string;
}

export interface AutofillSaveRequest extends AutofillTarget {
  kind: "save";
  token: string;
}

export type PendingAutofill = AutofillRequest | AutofillSaveRequest;

interface MyKeyAutofillPlugin {
  getPendingRequest(): Promise<PendingAutofill | null>;
  getPendingSaveValues(options: { token: string }): Promise<{
    username: string;
    password: string;
  } | null>;
  completeFill(options: {
    token: string;
    username: string;
    password: string;
  }): Promise<{ completed: boolean }>;
  cancelRequest(options: { token: string }): Promise<void>;
  acknowledgeSave(options: { token: string }): Promise<void>;
  setSessionState(options: { unlocked: boolean; expiresAtMs: number }): Promise<void>;
  serviceState(): Promise<{ supported: boolean; enabled: boolean }>;
  openAutofillSettings(): Promise<void>;
  addListener(
    eventName: "autofillRequest",
    listenerFunc: () => void,
  ): Promise<{ remove: () => Promise<void> }>;
}

const NativeAutofill = registerPlugin<MyKeyAutofillPlugin>("MyKeyAutofill");

export function autofillAvailable(): boolean {
  return isNativeApp() && Capacitor.getPlatform() === "android";
}

/** The pending fill/save request the native side is waiting on,
 * if the app was (re)launched by an autofill intent. */
export async function pendingAutofillRequest(): Promise<PendingAutofill | null> {
  if (!autofillAvailable()) return null;
  try {
    return (await NativeAutofill.getPendingRequest()) ?? null;
  } catch {
    return null;
  }
}

/** Credentials from a save request. Fetched only when the user is
 * in the unlocked app looking at the confirm screen: until this
 * call, the values exist only in the native service's memory. */
export async function pendingAutofillSaveValues(
  token: string,
): Promise<{ username: string; password: string } | null> {
  if (!autofillAvailable()) return null;
  try {
    return (await NativeAutofill.getPendingSaveValues({ token })) ?? null;
  } catch {
    return null;
  }
}

/** Hand the user's chosen credentials to the waiting autofill
 * session. Returns false when the request went away (the user
 * took too long, or the target app closed the form). */
export async function completeAutofillFill(
  token: string,
  username: string,
  password: string,
): Promise<boolean> {
  if (!autofillAvailable()) return false;
  try {
    const r = await NativeAutofill.completeFill({ token, username, password });
    return Boolean(r?.completed);
  } catch {
    return false;
  }
}

export async function cancelAutofillRequest(token: string): Promise<void> {
  if (!autofillAvailable()) return;
  try {
    await NativeAutofill.cancelRequest({ token });
  } catch {
    /* already gone */
  }
}

/** Tell the native side the save request has been dealt with
 * (saved or discarded), so it stops being offered. */
export async function acknowledgeAutofillSave(token: string): Promise<void> {
  if (!autofillAvailable()) return;
  try {
    await NativeAutofill.acknowledgeSave({ token });
  } catch {
    /* already gone */
  }
}

/** Keep the native dataset label honest ("Unlock MyKey" vs
 * "Fill with MyKey"): a hint only — the real gate is this app's
 * session, re-checked in the UI before anything is filled. */
export async function reportAutofillSession(
  unlocked: boolean,
  expiresAtMs: number,
): Promise<void> {
  if (!autofillAvailable()) return;
  try {
    await NativeAutofill.setSessionState({ unlocked, expiresAtMs });
  } catch {
    /* label hint only */
  }
}

export async function autofillServiceState(): Promise<{
  supported: boolean;
  enabled: boolean;
}> {
  if (!autofillAvailable()) return { supported: false, enabled: false };
  try {
    return await NativeAutofill.serviceState();
  } catch {
    return { supported: false, enabled: false };
  }
}

export async function openAutofillSettings(): Promise<void> {
  if (!autofillAvailable()) return;
  try {
    await NativeAutofill.openAutofillSettings();
  } catch {
    /* settings screen unavailable */
  }
}

/** Fires when an autofill intent reaches the already-running app. */
export async function onAutofillRequest(cb: () => void): Promise<void> {
  if (!autofillAvailable()) return;
  try {
    await NativeAutofill.addListener("autofillRequest", cb);
  } catch {
    /* native only */
  }
}
