// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core. It is NOT licensed
// under Apache 2.0, MIT, or any other open licence. No patent
// licence is granted by this file; all patent rights are expressly
// reserved. See LICENSING.md.

/** Android Credential Manager bridge (passkey wave).
 *
 * The native side (Kotlin, android/.../passkey/) parks a pending
 * create/get request from the system Credential Manager in
 * PasskeyBridge and launches the app; the app, once the vault is
 * unlocked (that unlock IS the user verification), completes or
 * fails the request through this plugin. The warm index carries
 * passkey METADATA only (credential id, rpId, user names) so the
 * system picker can show entries while the vault is locked — the
 * same disclosure class as the entry metadata the OS already sees
 * for autofill. No key material, ever.
 *
 * Web/PWA: every function is a no-op returning null — there is no
 * credential-provider role for a web page.
 */

import { Capacitor, registerPlugin } from "@capacitor/core";
import { isNativeApp } from "./biometric.js";

export interface PasskeyWarmItem {
  credentialId: string; // base64url
  rpId: string;
  username: string;
  displayName: string;
}

export interface PendingPasskeyRequest {
  bridgeId: string;
  kind: "create" | "get";
  origin: string;
  requestJson: string;
  callingPackage?: string;
}

interface MyKeyPasskeyPlugin {
  getPendingRequest(): Promise<{ pending: PendingPasskeyRequest | null }>;
  completeRequest(opts: { bridgeId: string; responseJson: string }): Promise<void>;
  failRequest(opts: { bridgeId: string; reason: string }): Promise<void>;
  setWarmIndex(opts: { items: PasskeyWarmItem[] }): Promise<void>;
  clearWarmIndex(): Promise<void>;
  addListener(
    eventName: "passkeyRequest",
    listener: (pending: PendingPasskeyRequest) => void,
  ): Promise<{ remove: () => Promise<void> }>;
}

const plugin = registerPlugin<MyKeyPasskeyPlugin>("MyKeyPasskey");

function native(): boolean {
  return isNativeApp() && Capacitor.isPluginAvailable("MyKeyPasskey");
}

export async function getPendingPasskeyRequest(): Promise<PendingPasskeyRequest | null> {
  if (!native()) return null;
  try {
    const { pending } = await plugin.getPendingRequest();
    return pending ?? null;
  } catch {
    return null;
  }
}

export async function completePasskeyRequest(bridgeId: string, responseJson: string): Promise<void> {
  if (!native()) return;
  await plugin.completeRequest({ bridgeId, responseJson });
}

export async function failPasskeyRequest(bridgeId: string, reason: string): Promise<void> {
  if (!native()) return;
  try {
    await plugin.failRequest({ bridgeId, reason });
  } catch {
    /* the native side may already have timed the request out */
  }
}

export async function setPasskeyWarmIndex(items: PasskeyWarmItem[]): Promise<void> {
  if (!native()) return;
  try {
    await plugin.setWarmIndex({ items });
  } catch {
    /* warm index is a picker nicety, never a blocker */
  }
}

export async function clearPasskeyWarmIndex(): Promise<void> {
  if (!native()) return;
  try {
    await plugin.clearWarmIndex();
  } catch {
    /* ignore */
  }
}
