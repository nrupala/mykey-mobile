// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** Cryptographic primitives, matched byte-for-byte to the Python
 * implementation (mykey.py): AES-256-GCM with the ciphertext layout
 * {nonce, ciphertext} (tag appended, as both WebCrypto and Python's
 * AESGCM produce), Argon2id via hash-wasm, PBKDF2-HMAC-SHA256 via
 * WebCrypto, SHA-256 / HMAC / HKDF via @noble/hashes. */

import { argon2id } from "hash-wasm";
import { sha256 } from "@noble/hashes/sha2.js";
import { hmac } from "@noble/hashes/hmac.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { b64decode, b64encode, utf8Encode } from "./encoding.js";

export interface SealedBlob {
  nonce: string;
  ciphertext: string;
}

export async function aesGcmEncrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<SealedBlob> {
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);
  const k = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce as BufferSource, additionalData: aad as BufferSource },
    k,
    plaintext as BufferSource,
  );
  return { nonce: b64encode(nonce), ciphertext: b64encode(new Uint8Array(ct)) };
}

/** Returns null on authentication failure (mirrors Python helpers
 * that translate InvalidTag into a wrong-credential signal). */
export async function aesGcmDecrypt(
  key: Uint8Array,
  blob: SealedBlob,
  aad: Uint8Array,
): Promise<Uint8Array | null> {
  try {
    const k = await crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: b64decode(blob.nonce) as BufferSource,
        additionalData: aad as BufferSource,
      },
      k,
      b64decode(blob.ciphertext) as BufferSource,
    );
    return new Uint8Array(pt);
  } catch {
    return null;
  }
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function sha256Hex(data: Uint8Array): string {
  return [...sha256(data)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export function hkdfSha256(
  ikm: Uint8Array,
  info: Uint8Array,
  length = 32,
  salt?: Uint8Array,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}

export interface ArgonParams {
  time_cost: number;
  memory_cost: number; // KiB, as stored in the vault header
  parallelism: number;
}

export const ARGON_DEFAULTS: ArgonParams = {
  time_cost: 3,
  memory_cost: 65536,
  parallelism: 4,
};

/** Argon2id raw hash, 32 bytes — the Python engine's _derive_*. */
export async function argon2idRaw(
  secret: Uint8Array,
  salt: Uint8Array,
  params: ArgonParams,
): Promise<Uint8Array> {
  return argon2id({
    password: secret,
    salt,
    iterations: params.time_cost,
    memorySize: params.memory_cost,
    parallelism: params.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
}

/** PBKDF2-HMAC-SHA256, 32 bytes (the vault's fallback KDF). */
export async function pbkdf2Sha256(
  secret: Uint8Array,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey("raw", secret as BufferSource, "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    base,
    256,
  );
  return new Uint8Array(bits);
}

/** Derive the wrapping key for a vault slot from a password. */
export async function deriveSlotKey(
  password: string,
  slot: { algo: string; salt: string; time_cost?: number; memory_cost?: number; parallelism?: number; iterations?: number },
): Promise<Uint8Array> {
  const salt = b64decode(slot.salt);
  const secret = utf8Encode(password);
  if (slot.algo === "argon2id") {
    return argon2idRaw(secret, salt, {
      time_cost: slot.time_cost ?? ARGON_DEFAULTS.time_cost,
      memory_cost: slot.memory_cost ?? ARGON_DEFAULTS.memory_cost,
      parallelism: slot.parallelism ?? ARGON_DEFAULTS.parallelism,
    });
  }
  if (slot.algo === "pbkdf2") {
    return pbkdf2Sha256(secret, salt, slot.iterations ?? 600000);
  }
  throw new Error(`unsupported KDF algorithm: ${slot.algo}`);
}
