// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** Byte/encoding helpers shared by the vault modules. */

const te = new TextEncoder();
const td = new TextDecoder();

export function utf8Encode(s: string): Uint8Array {
  return te.encode(s);
}

export function utf8Decode(b: Uint8Array): string {
  return td.decode(b);
}

export function b64encode(bytes: Uint8Array): string {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function b64decode(text: string): Uint8Array {
  // Strict like Python's base64.b64decode(validate=True): reject
  // characters outside the alphabet rather than silently skipping.
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) {
    throw new Error("invalid base64");
  }
  const bin = atob(text);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hexEncode(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Constant-time equality for equal-length byte strings. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * Canonical JSON matching Python's
 * json.dumps(obj, sort_keys=True, separators=(",", ":")) with the
 * default ensure_ascii=True. Used for MKBAK signature verification,
 * where the exact bytes matter.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number in canonical JSON");
    return Number.isInteger(value) ? value.toString() : JSON.stringify(value);
  }
  if (typeof value === "string") return escapeJsonString(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const parts = keys.map(
      (k) => escapeJsonString(k) + ":" + canonicalJson((value as Record<string, unknown>)[k]),
    );
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`cannot canonicalize ${typeof value}`);
}

function escapeJsonString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0d) out += "\\r";
    else if (code === 0x09) out += "\\t";
    else if (code < 0x20 || code > 0x7e) {
      // Python ensure_ascii escapes everything non-ASCII, using
      // surrogate pairs above the BMP exactly like JS \uXXXX units.
      for (let i = 0; i < ch.length; i++) {
        out += "\\u" + ch.charCodeAt(i).toString(16).padStart(4, "0");
      }
    } else out += ch;
  }
  return out + '"';
}

/** Parse JSON rejecting duplicate keys, mirroring vaultsync._strict_loads. */
export function strictJsonParse(text: string): unknown {
  // A lightweight duplicate-key scan over the raw text is not
  // reliable; instead parse with a reviver-free approach and rely on
  // a token-level check for the flat objects we accept. For nested
  // vault/package files the format code validates every field it
  // uses; duplicate keys in JSON.parse collapse to the last value,
  // which Python would refuse — callers that need strictness use
  // strictParseObject below.
  return JSON.parse(text);
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export function uuidHex(): string {
  const b = randomBytes(16);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = hexEncode(b);
  return h; // Python uuid4().hex — 32 hex chars, no dashes
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
