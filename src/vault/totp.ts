// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** TOTP (RFC 6238) — identical semantics to totp.py: SHA-1,
 * 30-second period, 6 digits, base32 secret (an otpauth:// URL is
 * accepted and its secret parameter used). */

import { base32 } from "@scure/base";

export function decodeTotpSecret(secret: string): Uint8Array {
  let text = secret.trim();
  if (text.toLowerCase().startsWith("otpauth://")) {
    const url = new URL(text);
    text = url.searchParams.get("secret") ?? "";
  }
  text = text.replace(/ /g, "").toUpperCase();
  const padded = text + "=".repeat((8 - (text.length % 8)) % 8);
  return base32.decode(padded);
}

export async function totpNow(
  secret: string,
  atSeconds?: number,
  period = 30,
  digits = 6,
): Promise<string> {
  const at = atSeconds ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(at / period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter), false);
  const key = await crypto.subtle.importKey(
    "raw",
    decodeTotpSecret(secret) as BufferSource,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg as BufferSource));
  const offset = digest[digest.length - 1]! & 0x0f;
  const code =
    (((digest[offset]! & 0x7f) << 24) |
      (digest[offset + 1]! << 16) |
      (digest[offset + 2]! << 8) |
      digest[offset + 3]!) %
    10 ** digits;
  return code.toString().padStart(digits, "0");
}

/** Seconds remaining in the current TOTP period. */
export function totpSecondsRemaining(period = 30): number {
  return period - (Math.floor(Date.now() / 1000) % period);
}
