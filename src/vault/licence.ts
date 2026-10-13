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

/** Licence keys — the mirror of the desktop engine's licensing.py.
 *
 * The free version holds up to FREE_ENTRY_LIMIT passwords and
 * FREE_MAX_CONNECTIONS connections per vault. A licence — an
 * Ed25519-signed token, prefix MKLIC1 — unlocks unlimited
 * passwords and the connection pool the token itself states.
 * Verification is FULLY OFFLINE against the MyKey Licence
 * Authority public key embedded below; nothing is sent anywhere,
 * and the limits are a fairness limit enforced in the app, never
 * an activation check with a server.
 *
 * Only COUNTS are limited. Security is never gated: encryption,
 * TOTP, sync, two-factor backups, pairing, rotation, skins and
 * export all work identically in the free version. A vault
 * already over a limit opens and works fully — only ADDING
 * pauses (the grandfather rule).
 *
 * Connections counting (per vault): enrolled devices (core
 * registry entries without revoked_at) + enrolled agents +
 * paired browsers (settings.browser_pairings — counted through
 * browserPairingCount() in vault.ts, the seam the browser
 * extension client calls when it registers a pairing). Backup /
 * cloud pairing targets are destinations, NOT connections, and
 * are never counted here.
 *
 * Token format: MKLIC1.<base64url(canonical statement JSON)>.
 * <base64url(Ed25519 signature over those exact bytes)> — the
 * canonical JSON is the shared encoding.ts canonicalJson, byte-
 * identical to the Python side. */

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

import {
  b64decode,
  b64encode,
  canonicalJson,
  hexEncode,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";

export const FREE_ENTRY_LIMIT = 50;
export const FREE_MAX_CONNECTIONS = 4;
export const LICENSED_MAX_CONNECTIONS = 20;

export const PRODUCT = "mykey";
export const EDITION = "unlimited";
export const TOKEN_PREFIX = "MKLIC1";

export const LICENCE_AUTHORITY_FINGERPRINT =
  "EE62F41972E84A9ABDEDF14A565D3A0C9B65B996";
/** Raw 32-byte Ed25519 public key of the licence authority, base64. */
export const LICENCE_PUBLIC_KEY_B64 =
  "t0KP/Om3sbo4nUusE2XP8uAF/MFgTOSIQ6AhbPN/L9E=";

/** The authority's armored OpenPGP public key — the same key as
 * LICENCE_PUBLIC_KEY_B64, for external `gpg --verify` checks of a
 * licence statement (see LICENCE.md). */
export const GPG_PUBLIC_KEY_ASC = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEas5hhBYJKwYBBAHaRw8BAQdAt0KP/Om3sbo4nUusE2XP8uAF/MFgTOSIQ6Ah
bPN/L9G0KU15S2V5IExpY2VuY2UgQXV0aG9yaXR5IDxpbmZvQGFpbWxkcy5vcmc+
iJMEExYKADsWIQTuYvQZcuhKmr3t8UpWXToMm2W5lgUCas5hhAIbAwULCQgHAgIi
AgYVCgkICwIEFgIDAQIeBwIXgAAKCRBWXToMm2W5loz3AP9jBtn8NW/f1EuYYJ8U
2yKVHsROg7dlqzLWJE80/azargD+J6wLD5oCoN6rGIBa70BMckUBbe9EHd+0OHmB
fGTGMQ0=
=HpvB
-----END PGP PUBLIC KEY BLOCK-----`;

export interface LicencePayload {
  licence_id: string;
  licensee: string;
  product: string;
  edition: string;
  issued_at: string;
  payment_date: string;
  serial: string;
  passcode: string;
  max_connections: number;
}

const PAYLOAD_FIELDS = [
  "edition",
  "issued_at",
  "licence_id",
  "licensee",
  "max_connections",
  "passcode",
  "payment_date",
  "product",
  "serial",
] as const;

export class LicenceInvalidError extends Error {}
export class LicenceRequiredError extends Error {}

function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new LicenceInvalidError("the licence key has characters it shouldn't");
  }
  const pad = "=".repeat((4 - (text.length % 4)) % 4);
  return b64decode(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
}

/** People paste keys with spaces and line breaks from the grouped
 * display form. Base64url is case-sensitive, so only whitespace is
 * stripped — never re-case a key. */
export function normalizeToken(text: string): string {
  return (text ?? "").replace(/\s+/g, "");
}

export function canonicalStatement(payload: LicencePayload): Uint8Array {
  return utf8Encode(canonicalJson(payload));
}

export function parseToken(text: string): {
  payload: LicencePayload;
  signature: Uint8Array;
  body: Uint8Array;
} {
  const token = normalizeToken(text);
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) {
    throw new LicenceInvalidError(
      `that does not look like a MyKey licence key (it should start with ${TOKEN_PREFIX}.)`,
    );
  }
  let body: Uint8Array;
  let signature: Uint8Array;
  try {
    body = b64urlDecode(parts[1]);
    signature = b64urlDecode(parts[2]);
  } catch {
    throw new LicenceInvalidError("the licence key is damaged — please paste it again in full");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(utf8Decode(body));
  } catch {
    throw new LicenceInvalidError("the licence key's statement is not readable");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new LicenceInvalidError("the licence key's statement is not readable");
  }
  const keys = Object.keys(parsed as Record<string, unknown>).sort();
  if (
    keys.length !== PAYLOAD_FIELDS.length ||
    !PAYLOAD_FIELDS.every((f, i) => keys[i] === f)
  ) {
    throw new LicenceInvalidError("the licence key's statement has the wrong shape");
  }
  const payload = parsed as unknown as LicencePayload;
  // Refuse non-canonical statements outright, like the Python side.
  if (utf8Decode(canonicalStatement(payload)) !== utf8Decode(body)) {
    throw new LicenceInvalidError("the licence key's statement is not in its signed form");
  }
  return { payload, signature, body };
}

/** Verify a licence key fully offline. Returns the payload, or
 * throws LicenceInvalidError — failing closed on anything
 * unexpected, mirroring licensing.py exactly. */
export function verifyToken(
  text: string,
  publicKeyB64: string = LICENCE_PUBLIC_KEY_B64,
): LicencePayload {
  const { payload, signature, body } = parseToken(text);
  if (payload.product !== PRODUCT) {
    throw new LicenceInvalidError("that licence key is for a different product");
  }
  if (payload.edition !== EDITION) {
    throw new LicenceInvalidError(`that licence key's edition (${payload.edition}) is not recognised here`);
  }
  if (
    typeof payload.max_connections !== "number" ||
    !Number.isInteger(payload.max_connections) ||
    payload.max_connections < 0
  ) {
    throw new LicenceInvalidError("the licence key's connection count is not readable");
  }
  if (signature.length !== 64) {
    throw new LicenceInvalidError("the licence key's signature is damaged");
  }
  let ok = false;
  try {
    ok = ed25519.verify(signature, body, b64decode(publicKeyB64));
  } catch {
    ok = false;
  }
  if (!ok) {
    throw new LicenceInvalidError(
      "that licence key didn't check out — please check you pasted it in full, exactly as it was sent to you",
    );
  }
  return payload;
}

/** Build a token — test/issuer support; the app itself only
 * verifies. `seed` is the authority's raw 32-byte private key. */
export function buildToken(payload: LicencePayload, seed: Uint8Array): string {
  const body = canonicalStatement(payload);
  const signature = ed25519.sign(body, seed);
  return `${TOKEN_PREFIX}.${b64urlEncode(body)}.${b64urlEncode(signature)}`;
}

export function publicKeyB64FromSeed(seed: Uint8Array): string {
  return b64encode(ed25519.getPublicKey(seed));
}

/** The per-licence passcode (licence issuance, Owner Update #1):
 * SHA-256 over email ‖ payment date ‖ DOB ‖ random serial,
 * rendered GPG-fingerprint-style. The three personal inputs
 * IDENTIFY a licence and authorize reissue; they never derive
 * key material — the random serial makes this non-brute-forceable.
 * The DOB is hashed here and never stored anywhere. */
export function computePasscode(
  email: string,
  paymentDate: string,
  dob: string,
  serialHex: string,
): string {
  const digest = sha256(
    utf8Encode(`${email.trim().toLowerCase()}|${paymentDate}|${dob}|${serialHex}`),
  );
  const hex = hexEncode(digest).toUpperCase();
  return (hex.match(/.{4}/g) ?? []).join(" ");
}

/** Plain-words licence state for Settings / About — the same
 * wording family as the desktop status_line. */
export function statusLine(state: {
  licensed: boolean;
  entries: number;
  connections: number;
  connectionLimit: number;
}): string {
  if (state.licensed) {
    return `Licensed · unlimited passwords · ${state.connections} of ${state.connectionLimit} connections`;
  }
  return `Free · ${state.entries} of ${FREE_ENTRY_LIMIT} passwords · ${state.connections} of ${state.connectionLimit} connections`;
}
