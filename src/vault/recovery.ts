// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** BIP-39 recovery, byte-compatible with recovery.py:
 * seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048) via
 * @scure/bip39; recovery wrapping key = Argon2id(seed, slot salt,
 * 3 / 65536 KiB / 4); backup recipient keypair = X25519 over
 * Argon2id(seed, SHA-256("mkbak-recovery-v1:"+vault_id)[..16]). */

import {
  generateMnemonic,
  mnemonicToSeedSync,
  validateMnemonic,
} from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { ARGON_DEFAULTS, argon2idRaw, sha256Bytes } from "./crypto.js";
import { utf8Encode } from "./encoding.js";

export function newRecoveryPhrase(): string {
  return generateMnemonic(wordlist, 128);
}

export function isValidPhrase(phrase: string): boolean {
  try {
    return validateMnemonic(normalizePhrase(phrase), wordlist);
  } catch {
    return false;
  }
}

export function normalizePhrase(phrase: string): string {
  return phrase.normalize("NFKD").trim().split(/\s+/).join(" ");
}

function seedFromPhrase(phrase: string): Uint8Array {
  const normalized = normalizePhrase(phrase);
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error("recovery phrase is not a valid BIP-39 phrase");
  }
  return mnemonicToSeedSync(normalized, "");
}

/** The 32-byte recovery wrapping key for a vault slot. */
export async function deriveRecoveryKey(
  phrase: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const seed = seedFromPhrase(phrase);
  return argon2idRaw(seed, salt, ARGON_DEFAULTS);
}

/** Deterministic X25519 backup-recipient keypair from the phrase. */
export async function recoveryBackupKeypair(
  phrase: string,
  vaultId: string,
): Promise<{ privateRaw: Uint8Array; publicRaw: Uint8Array }> {
  const seed = seedFromPhrase(phrase);
  const salt = sha256Bytes(utf8Encode(`mkbak-recovery-v1:${vaultId}`)).slice(0, 16);
  const raw = await argon2idRaw(seed, salt, ARGON_DEFAULTS);
  return { privateRaw: raw, publicRaw: x25519.getPublicKey(raw) };
}

export async function recoveryBackupPublic(
  phrase: string,
  vaultId: string,
): Promise<Uint8Array> {
  return (await recoveryBackupKeypair(phrase, vaultId)).publicRaw;
}
