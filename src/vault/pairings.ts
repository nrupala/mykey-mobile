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

// Key-value pairing + backup codes — the TypeScript mirror of the
// desktop engine's pairings.py and the recovery.py backup-code
// helpers. Byte-for-byte the same shapes, so a payload or package
// made on one side is honoured on the other.
//
// A pairing ties a TARGET ID (key) to a record (value) inside the
// encrypted vault: the target's X25519 public key, what it may do
// (scopes: push / pull / export), an expiry, and an on/off switch.
// Backup packages and cloud sync wrap content keys ONLY to pairings
// that are enabled and unexpired — an unpaired or revoked target
// gets no slot.

import { wordlist } from "@scure/bip39/wordlists/english.js";
import { sha256Bytes } from "./crypto.js";
import { b64decode, b64encode, hexEncode, nowSeconds, randomBytes } from "./encoding.js";

export const BACKUP_CODE_WORDS = 8;
export const PAIRING_PAYLOAD_VERSION = 1;
export const PAIRING_TYPES = ["device", "cloud-folder", "export"] as const;
export type PairingType = (typeof PAIRING_TYPES)[number];
export const PAIRING_SCOPES = ["push", "pull", "export"] as const;
export type PairingScope = (typeof PAIRING_SCOPES)[number];

/** A pairing record as stored in the vault core (mirror of the
 *  desktop registry record; times are epoch seconds). */
export interface PairingRecord {
  target_id: string;
  label: string;
  type: PairingType;
  x25519_pub: string; // base64, 32 bytes
  fingerprint: string;
  scopes: PairingScope[];
  enrolled_at: number;
  expires_at: number | null;
  enabled: boolean;
  revoked_at: number | null;
}

export interface PairingPayload {
  format: string;
  version: number;
  target_id: string;
  label: string;
  type: PairingType;
  x25519_pub: string;
  fingerprint: string;
}

// ---------------------------------------------------------------------
// Fingerprints — grouped hex SHA-256, first 16 bytes, colon groups
// (identical to devices.device_fingerprint / pairings.py).
// ---------------------------------------------------------------------

export function groupedFingerprint(digest: Uint8Array): string {
  const hex = hexEncode(digest);
  const groups: string[] = [];
  for (let i = 0; i < 32; i += 4) groups.push(hex.slice(i, i + 4));
  return groups.join(":");
}

export function pairingFingerprint(x25519Pub: Uint8Array): string {
  return groupedFingerprint(sha256Bytes(x25519Pub));
}

// ---------------------------------------------------------------------
// Backup codes (mirror recovery.generate_backup_code / normalize)
// ---------------------------------------------------------------------

function randomWordIndex(): number {
  // 2048 words = 11 bits; rejection-sample two bytes.
  for (;;) {
    const b = randomBytes(2);
    const v = ((b[0]! << 3) | (b[1]! >> 5)) & 0x7ff;
    if (v < 2048) return v;
  }
}

export function generateBackupCode(): string {
  const words: string[] = [];
  for (let i = 0; i < BACKUP_CODE_WORDS; i++) words.push(wordlist[randomWordIndex()]!);
  return words.join(" ");
}

export function normalizeBackupCode(text: string): string {
  const words = text
    .normalize("NFKD")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter((w) => w.length > 0);
  if (words.length !== BACKUP_CODE_WORDS) {
    throw new Error(
      `a backup code has ${BACKUP_CODE_WORDS} words — this one has ${words.length}`,
    );
  }
  for (const w of words) {
    if (!wordlist.includes(w)) throw new Error(`word not in the word list: '${w}'`);
  }
  return words.join(" ");
}

// ---------------------------------------------------------------------
// Pairing helpers (mirror pairings.py)
// ---------------------------------------------------------------------

export function validateScopes(scopes: readonly string[]): PairingScope[] {
  const out: PairingScope[] = [];
  for (const s of scopes) {
    if (!(PAIRING_SCOPES as readonly string[]).includes(s)) {
      throw new Error(
        `unknown pairing scope '${s}' (allowed: ${PAIRING_SCOPES.join(", ")})`,
      );
    }
    if (!out.includes(s as PairingScope)) out.push(s as PairingScope);
  }
  if (out.length === 0) throw new Error("a pairing needs at least one scope");
  return out.sort();
}

/** Verify a pairing payload (parsed JSON object); returns the
 *  normalized record fields. The fingerprint is always recomputed
 *  from the key, never trusted from the payload. */
export function verifyPairingPayload(payload: Record<string, unknown>): Omit<
  PairingRecord,
  "scopes" | "enrolled_at" | "expires_at" | "enabled" | "revoked_at"
> {
  if (payload?.format !== "MKPAIR" || payload?.version !== PAIRING_PAYLOAD_VERSION) {
    throw new Error("not a pairing payload (format/version not recognized)");
  }
  const targetId = String(payload.target_id ?? "");
  if (targetId.length !== 32 || !/^[0-9a-fA-F]+$/.test(targetId)) {
    throw new Error("pairing payload has a malformed target id");
  }
  const type = payload.type as PairingType;
  if (!PAIRING_TYPES.includes(type)) {
    throw new Error(`pairing payload has an unknown type '${String(payload.type)}'`);
  }
  let pub: Uint8Array;
  try {
    pub = b64decode(String(payload.x25519_pub ?? ""));
  } catch {
    throw new Error("pairing payload key is malformed");
  }
  if (pub.length !== 32) throw new Error("pairing payload key has the wrong length");
  const fingerprint = pairingFingerprint(pub);
  if (payload.fingerprint !== fingerprint) {
    throw new Error("pairing payload fingerprint does not match its key — refuse it");
  }
  return {
    target_id: targetId,
    label: String(payload.label ?? ""),
    type,
    x25519_pub: b64encode(pub),
    fingerprint,
  };
}

/** Enabled, unrevoked, unexpired — the only state that receives new
 *  wraps or sync access (mirror pairings.pairing_active). */
export function pairingActive(
  record: PairingRecord | undefined | null,
  now: number = nowSeconds(),
): boolean {
  if (!record || !record.enabled || record.revoked_at) return false;
  if (record.expires_at && now > record.expires_at) return false;
  return true;
}

/** Plain-language reason a pairing cannot be used for *scope*, or
 *  null when it can (the sync gate's wording). */
export function pairingBlockReason(
  record: PairingRecord | undefined | null,
  scope: PairingScope,
  targetId?: string,
): string | null {
  if (!record) {
    return `This sync folder is tied to pairing ${targetId ?? ""}, which isn't in this vault. Pair it first.`;
  }
  if (record.revoked_at) return "That pairing was revoked. Pair the target again to use it.";
  if (!record.enabled) return "That pairing is turned off. Turn it on in Backup targets & pairing.";
  if (record.expires_at && nowSeconds() > record.expires_at) {
    return "That pairing has expired. Pair the target again to renew it.";
  }
  if (!record.scopes.includes(scope)) {
    return scope === "push"
      ? "That pairing doesn't allow saving to the folder. Pair it again with the save permission."
      : "That pairing doesn't allow loading from the folder. Pair it again with the load permission.";
  }
  return null;
}
