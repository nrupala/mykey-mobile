// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** Minimal CBOR encoder — only what WebAuthn attestation objects
 * and COSE public keys need: maps with integer or text keys,
 * integers (including negative), byte strings, text strings,
 * arrays, and booleans. Shortest-form length encoding throughout,
 * per RFC 8949. No decoder: nothing in v1 parses untrusted CBOR. */

type CborValue =
  | number
  | string
  | Uint8Array
  | boolean
  | CborValue[]
  | Map<number | string, CborValue>;

function head(major: number, arg: number, out: number[]): void {
  const mt = major << 5;
  if (arg < 24) out.push(mt | arg);
  else if (arg < 0x100) out.push(mt | 24, arg);
  else if (arg < 0x10000) out.push(mt | 25, (arg >> 8) & 0xff, arg & 0xff);
  else if (arg < 0x100000000) {
    out.push(mt | 26, (arg >>> 24) & 0xff, (arg >>> 16) & 0xff, (arg >>> 8) & 0xff, arg & 0xff);
  } else {
    // Values in WebAuthn structures never reach 2^32; refuse rather
    // than emit a lossy 64-bit head through JS number precision.
    throw new Error("CBOR value too large");
  }
}

function encodeInto(value: CborValue, out: number[]): void {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) throw new Error("CBOR: non-integer number");
    if (value >= 0) head(0, value, out);
    else head(1, -1 - value, out);
    return;
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    head(3, bytes.length, out);
    for (const b of bytes) out.push(b);
    return;
  }
  if (value instanceof Uint8Array) {
    head(2, value.length, out);
    for (const b of value) out.push(b);
    return;
  }
  if (typeof value === "boolean") {
    out.push(value ? 0xf5 : 0xf4);
    return;
  }
  if (Array.isArray(value)) {
    head(4, value.length, out);
    for (const v of value) encodeInto(v, out);
    return;
  }
  if (value instanceof Map) {
    head(5, value.size, out);
    for (const [k, v] of value) {
      if (typeof k === "number") {
        if (k >= 0) head(0, k, out);
        else head(1, -1 - k, out);
      } else {
        const bytes = new TextEncoder().encode(k);
        head(3, bytes.length, out);
        for (const b of bytes) out.push(b);
      }
      encodeInto(v, out);
    }
    return;
  }
  throw new Error("CBOR: unsupported value");
}

export function cborEncode(value: CborValue): Uint8Array {
  const out: number[] = [];
  encodeInto(value, out);
  return new Uint8Array(out);
}

export type { CborValue };
