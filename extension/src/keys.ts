// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (pairing identity for
// the browser extension). It is NOT licensed under Apache 2.0, MIT,
// or any other open licence. No patent licence is granted by this
// file; all patent rights are expressly reserved. See
// LICENSING.md.

/** The extension's pairing identity: one X25519 keypair, generated
 * on first use. The PRIVATE key never leaves this browser profile;
 * it lives in extension local storage (per-extension, not readable
 * by web pages). It is an identity key, not a vault secret: it can
 * prove "I am the paired browser" and agree channel keys, and it
 * holds no vault key material — a stolen pairing key without the
 * master password opens nothing, and the pairing can be revoked
 * from the desktop.
 *
 * The public side travels in the pairing payload the human carries
 * to the desktop; the desktop's host public key is pinned here from
 * the host payload the human carries back. Both sides show the same
 * grouped-hex fingerprint for the human comparison.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import {
  b64decode,
  b64encode,
} from "../../src/vault/encoding.js";
import { keyFingerprint } from "./channel.js";
import type { StorageArea } from "./webext.js";

export const PAIRING_PAYLOAD_FORMAT = "MKEXTPAIR";
export const HOST_PAYLOAD_FORMAT = "MKHOST";

const KEY_PRIV = "mkext.priv";
const KEY_PUB = "mkext.pub";
const KEY_HOST_PUB = "mkext.hostPub";
const KEY_HOST_FP = "mkext.hostFingerprint";

export interface PairingIdentity {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  fingerprint: string;
}

export async function loadOrCreateIdentity(
  storage: StorageArea,
): Promise<PairingIdentity> {
  const stored = await storage.get([KEY_PRIV, KEY_PUB]);
  if (typeof stored[KEY_PRIV] === "string" && typeof stored[KEY_PUB] === "string") {
    const privateKey = b64decode(stored[KEY_PRIV] as string);
    const publicKey = b64decode(stored[KEY_PUB] as string);
    return { privateKey, publicKey, fingerprint: keyFingerprint(publicKey) };
  }
  return createIdentity(storage);
}

export async function createIdentity(
  storage: StorageArea,
): Promise<PairingIdentity> {
  const privateKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(privateKey);
  await storage.set({
    [KEY_PRIV]: b64encode(privateKey),
    [KEY_PUB]: b64encode(publicKey),
  });
  return { privateKey, publicKey, fingerprint: keyFingerprint(publicKey) };
}

/** Forget the identity AND the pinned host. Any desktop pairing for
 * the old id becomes useless (the desktop keeps it listed until the
 * human revokes it there; a fresh identity must be paired anew). */
export async function resetIdentity(storage: StorageArea): Promise<void> {
  await storage.remove([KEY_PRIV, KEY_PUB, KEY_HOST_PUB, KEY_HOST_FP]);
}

export function pairingPayload(
  extensionId: string,
  identity: PairingIdentity,
  label: string,
): Record<string, unknown> {
  return {
    format: PAIRING_PAYLOAD_FORMAT,
    version: 1,
    extension_id: extensionId,
    label,
    x25519_pub: b64encode(identity.publicKey),
    fingerprint: identity.fingerprint,
  };
}

/** Validate + pin the desktop host payload. The fingerprint is
 * recomputed here — a payload whose stated fingerprint does not
 * match its key is refused, exactly as the desktop refuses ours. */
export async function pinHostPayload(
  storage: StorageArea,
  payload: unknown,
): Promise<{ fingerprint: string }> {
  if (
    typeof payload !== "object" || payload === null ||
    (payload as Record<string, unknown>).format !== HOST_PAYLOAD_FORMAT ||
    (payload as Record<string, unknown>).version !== 1
  ) {
    throw new Error("that is not a MyKey host payload — copy it exactly as the desktop shows it");
  }
  const record = payload as Record<string, unknown>;
  let publicKey: Uint8Array;
  try {
    publicKey = b64decode(String(record.x25519_pub));
  } catch {
    throw new Error("the host payload's key is malformed");
  }
  if (publicKey.length !== 32) {
    throw new Error("the host payload's key has the wrong length");
  }
  const fingerprint = keyFingerprint(publicKey);
  if (record.fingerprint !== fingerprint) {
    throw new Error(
      "the host payload's fingerprint does not match its key — refuse it and do not pair",
    );
  }
  await storage.set({
    [KEY_HOST_PUB]: b64encode(publicKey),
    [KEY_HOST_FP]: fingerprint,
  });
  return { fingerprint };
}

export async function pinnedHost(
  storage: StorageArea,
): Promise<{ publicKey: Uint8Array; fingerprint: string } | null> {
  const stored = await storage.get([KEY_HOST_PUB, KEY_HOST_FP]);
  if (typeof stored[KEY_HOST_PUB] !== "string") return null;
  return {
    publicKey: b64decode(stored[KEY_HOST_PUB] as string),
    fingerprint: String(stored[KEY_HOST_FP] ?? ""),
  };
}
