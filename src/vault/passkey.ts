// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** WebAuthn authenticator (passkey wave) — a pure TypeScript
 * platform authenticator that operates on an UNLOCKED VaultSession.
 *
 * Faithfulness notes (WebAuthn Level 3 / FIDO2):
 *  - RP ID verification: the requested rpId must equal the origin's
 *    host or be a valid registrable-domain suffix of it (host ends
 *    with "." + rpId). Anything else is refused — this is the
 *    phishing defence. The check here is the suffix rule itself;
 *    determining that the rpId is a *registrable* domain (public
 *    suffix list) is approximated: an rpId that is an IP literal
 *    or contains a port/path is refused outright, and the Android
 *    layer additionally only receives rpIds from the system's
 *    Credential Manager request, which the OS has already scoped
 *    to the calling app / origin.
 *  - User verification: every create and every assertion requires
 *    userVerified === true. The caller obtains that from the vault
 *    unlock (master password or the fingerprint device slot) that
 *    immediately precedes the ceremony — there is no separate PIN.
 *  - Attestation is honestly "none": fmt "none", empty attStmt,
 *    zero AAGUID. MyKey is a software authenticator with no hardware
 *    attestation key, and it does not pretend otherwise.
 *  - Backup flags: BE=1, BS=1 — honest, because the credential
 *    private key is backed up inside the encrypted vault (and its
 *    encrypted backups) by design.
 *  - sign_count starts at 0, increments on every assertion, and
 *    persists in the vault. Because the vault syncs, two devices
 *    restored from the same vault copy can present the same count:
 *    relying parties detect clones by non-increasing counts, and
 *    checkCloneRegression() additionally warns locally when a
 *    record's count has fallen below this device's high-water mark.
 *  - Private keys never leave this module except inside the
 *    encrypted vault record: they are never logged, never copied
 *    to the clipboard, and never returned to callers.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { cborEncode } from "./cbor.js";
import { sha256Bytes } from "./crypto.js";
import { b64decode, b64encode, nowSeconds, randomBytes, utf8Encode } from "./encoding.js";
import type { PasskeyRecord, VaultSession } from "./vault.js";

export class PasskeyError extends Error {}
export class RpIdMismatchError extends PasskeyError {}
export class NoCredentialError extends PasskeyError {}
export class UnsupportedAlgorithmError extends PasskeyError {}
export class UserVerificationRequiredError extends PasskeyError {}
export class CredentialExistsError extends PasskeyError {}
export class MultipleCredentialsError extends PasskeyError {
  candidates: Array<{ credential_id: string; rp_id: string; user_name: string }>;
  constructor(candidates: Array<{ credential_id: string; rp_id: string; user_name: string }>) {
    super("more than one passkey matches — the user must pick one");
    this.candidates = candidates;
  }
}

// ------------------------------------------------------------------
// base64url (WebAuthn JSON serialization form)
// ------------------------------------------------------------------

export function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text: string): Uint8Array {
  const std = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  return b64decode(padded);
}

function b64urlToB64(text: string): string {
  return b64encode(b64urlDecode(text));
}

// ------------------------------------------------------------------
// RP ID verification
// ------------------------------------------------------------------

export function rpIdAllowed(rpId: string, origin: string): boolean {
  if (!rpId || rpId.includes(":") || rpId.includes("/") || rpId.includes("..")) return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(rpId)) return false; // IP literal is not an RP ID
  // Native Android caller: the origin is "android:apk-key-hash:…"
  // and the OS has already bound the rpId to the calling app via
  // its asset-links / privileged-caller checks before the request
  // reached us. The web suffix rule below is the defence for web
  // origins; for an android: origin there is no host to check.
  if (origin.startsWith("android:")) return true;
  let host: string;
  try {
    host = new URL(origin).hostname;
  } catch {
    return false;
  }
  if (!host) return false;
  if (host === rpId) return true;
  // Suffix rule with the dot guard: "login.example.com" is inside
  // rpId "example.com"; "evil-example.com" is NOT.
  return host.endsWith("." + rpId);
}

function requireRpId(rpId: string, origin: string): void {
  if (!rpIdAllowed(rpId, origin)) {
    throw new RpIdMismatchError(
      `relying party id "${rpId}" does not match origin "${origin}" — refused`,
    );
  }
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

function be16(n: number): Uint8Array {
  return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}

function be32(n: number): Uint8Array {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Convert an ECDSA P1363 signature (r‖s, fixed width) to DER. */
export function p1363ToDer(sig: Uint8Array): Uint8Array {
  if (sig.length % 2 !== 0) throw new Error("P1363 signature has odd length");
  const half = sig.length / 2;
  const intDer = (raw: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < raw.length - 1 && raw[i] === 0) i++;
    let v = raw.subarray(i);
    if (v[0]! & 0x80) v = concat(new Uint8Array([0]), v);
    return concat(new Uint8Array([0x02, v.length]), v);
  };
  const body = concat(intDer(sig.subarray(0, half)), intDer(sig.subarray(half)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

let edDsaProbe: Promise<boolean> | null = null;
function edDsaAvailable(): Promise<boolean> {
  if (!edDsaProbe) {
    edDsaProbe = (async () => {
      try {
        await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, false, ["sign", "verify"]);
        return true;
      } catch {
        return false;
      }
    })();
  }
  return edDsaProbe;
}

function parseOptions(optionsJson: string | Record<string, any>): Record<string, any> {
  if (typeof optionsJson === "string") return JSON.parse(optionsJson);
  return optionsJson;
}

function cosePublicKey(alg: number, publicRaw: Uint8Array): Uint8Array {
  if (alg === -7) {
    // EC2 / P-256: {1:2, 3:-7, -1:1, -2:x, -3:y}
    const x = publicRaw.subarray(1, 33);
    const y = publicRaw.subarray(33, 65);
    return cborEncode(new Map<number, any>([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]));
  }
  // OKP / Ed25519: {1:1, 3:-8, -1:6, -2:raw}
  return cborEncode(new Map<number, any>([[1, 1], [3, -8], [-1, 6], [-2, publicRaw]]));
}

// ------------------------------------------------------------------
// Create (registration ceremony)
// ------------------------------------------------------------------

export interface CreateRequest {
  origin: string;
  optionsJson: string | Record<string, any>;
  userVerified: boolean;
}

export async function createCredential(
  session: VaultSession,
  req: CreateRequest,
): Promise<Record<string, any>> {
  if (!req.userVerified) {
    throw new UserVerificationRequiredError("passkey creation requires user verification (vault unlock)");
  }
  const options = parseOptions(req.optionsJson);
  const originHost = (() => { try { return new URL(req.origin).hostname; } catch { return ""; } })();
  const rpId: string = options.rp?.id ?? originHost;
  requireRpId(rpId, req.origin);

  const params: Array<{ type?: string; alg?: number }> = options.pubKeyCredParams ?? [{ type: "public-key", alg: -7 }];
  const offered = params.filter((p) => p.type === undefined || p.type === "public-key").map((p) => p.alg ?? -7);
  let alg: number | null = null;
  for (const a of offered) {
    if (a === -7) { alg = -7; break; }
    if (a === -8 && (await edDsaAvailable())) { alg = -8; break; }
  }
  if (alg === null) {
    throw new UnsupportedAlgorithmError(
      `none of the requested algorithms [${offered.join(", ")}] is supported (ES256 supported; EdDSA only where WebCrypto offers Ed25519)`,
    );
  }

  for (const excl of options.excludeCredentials ?? []) {
    if (excl?.id) {
      const existing = session.findPasskeyByCredentialId(b64urlToB64(String(excl.id)));
      if (existing && existing.passkey?.rp_id === rpId) {
        throw new CredentialExistsError("a passkey for this account already exists in the vault");
      }
    }
  }

  // Key generation.
  let privatePkcs8: Uint8Array;
  let publicRaw: Uint8Array;
  let spki: Uint8Array;
  if (alg === -7) {
    const kp = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    privatePkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
    publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
  } else {
    const kp = (await crypto.subtle.generateKey({ name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"])) as CryptoKeyPair;
    privatePkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
    publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
  }

  const credentialId = randomBytes(32);
  const challenge: string = String(options.challenge ?? "");
  const clientData = utf8Encode(JSON.stringify({
    type: "webauthn.create",
    challenge,
    origin: req.origin,
    crossOrigin: false,
  }));

  const flags = 0x01 | 0x04 | 0x08 | 0x10 | 0x40; // UP|UV|BE|BS|AT
  const authData = concat(
    sha256(utf8Encode(rpId)),
    new Uint8Array([flags]),
    be32(0),
    new Uint8Array(16), // zero AAGUID — honest "none" attestation
    be16(credentialId.length),
    credentialId,
    cosePublicKey(alg, publicRaw),
  );
  const attestationObject = cborEncode(new Map<string, any>([
    ["fmt", "none"],
    ["attStmt", new Map()],
    ["authData", authData],
  ]));

  const user = options.user ?? {};
  const record: PasskeyRecord = {
    rp_id: rpId,
    user_id: user.id ? b64urlToB64(String(user.id)) : "",
    user_name: String(user.name ?? ""),
    user_display_name: String(user.displayName ?? user.name ?? ""),
    credential_id: b64encode(credentialId),
    alg,
    public_key: b64encode(publicRaw),
    private_key: b64encode(privatePkcs8),
    sign_count: 0,
    transports: ["internal"],
    created_at: nowSeconds(),
    aaguid: b64encode(new Uint8Array(16)),
    backup_eligible: true,
    backed_up: true,
  };
  await session.addPasskeyRecord(record);

  return {
    id: b64urlEncode(credentialId),
    rawId: b64urlEncode(credentialId),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: b64urlEncode(clientData),
      attestationObject: b64urlEncode(attestationObject),
      transports: ["internal"],
      publicKey: b64urlEncode(spki),
      publicKeyAlgorithm: alg,
    },
    clientExtensionResults: {},
  };
}

// ------------------------------------------------------------------
// Get (assertion ceremony)
// ------------------------------------------------------------------

export interface GetRequest {
  origin: string;
  optionsJson: string | Record<string, any>;
  userVerified: boolean;
  /** Base64url credential id chosen by the user when several match. */
  selectCredentialId?: string;
}

export async function getAssertion(
  session: VaultSession,
  req: GetRequest,
): Promise<Record<string, any>> {
  if (!req.userVerified) {
    throw new UserVerificationRequiredError("passkey sign-in requires user verification (vault unlock)");
  }
  const options = parseOptions(req.optionsJson);
  const originHost = (() => { try { return new URL(req.origin).hostname; } catch { return ""; } })();
  const rpId: string = options.rpId ?? options.rp?.id ?? originHost;
  requireRpId(rpId, req.origin);

  let candidates = session.listPasskeys().filter((e) => e.passkey?.rp_id === rpId);
  const allow: Array<{ id?: string }> = options.allowCredentials ?? [];
  if (allow.length > 0) {
    const ids = new Set(allow.filter((a) => a.id).map((a) => b64urlToB64(String(a.id))));
    candidates = candidates.filter((e) => ids.has(e.passkey!.credential_id));
  }
  if (candidates.length === 0) {
    throw new NoCredentialError(`no passkey in the vault for ${rpId}`);
  }
  let entry = candidates[0]!;
  const selected = req.selectCredentialId ?? (options.mykey_selected_credential ? String(options.mykey_selected_credential) : undefined);
  if (selected) {
    const wanted = b64urlToB64(selected);
    const picked = candidates.find((e) => e.passkey!.credential_id === wanted);
    if (!picked) throw new NoCredentialError("the selected passkey is not available for this relying party");
    entry = picked;
  } else if (candidates.length > 1) {
    throw new MultipleCredentialsError(
      candidates.map((e) => ({ credential_id: e.passkey!.credential_id, rp_id: rpId, user_name: e.passkey!.user_name })),
    );
  }
  const record = entry.passkey!;

  const challenge: string = String(options.challenge ?? "");
  const clientData = utf8Encode(JSON.stringify({
    type: "webauthn.get",
    challenge,
    origin: req.origin,
    crossOrigin: false,
  }));
  const clientDataHash = sha256(clientData);

  const newCount = record.sign_count + 1;
  const flags = 0x01 | 0x04 | 0x08 | 0x10; // UP|UV|BE|BS (no AT)
  const authData = concat(
    sha256(utf8Encode(rpId)),
    new Uint8Array([flags]),
    be32(newCount),
  );
  // Persist the incremented count BEFORE signing: a burned count is
  // harmless, a reused count is a clone signal.
  session.updatePasskeySignCount(entry.id, newCount);

  const signed = concat(authData, clientDataHash);
  const privateBytes = b64decode(record.private_key);
  let signature: Uint8Array;
  if (record.alg === -8) {
    const key = await crypto.subtle.importKey("pkcs8", privateBytes as BufferSource, { name: "Ed25519" } as AlgorithmIdentifier, false, ["sign"]);
    signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" } as AlgorithmIdentifier, key, signed as BufferSource));
  } else {
    const key = await crypto.subtle.importKey("pkcs8", privateBytes as BufferSource, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const p1363 = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, signed as BufferSource));
    signature = p1363ToDer(p1363);
  }

  const credIdBytes = b64decode(record.credential_id);
  return {
    id: b64urlEncode(credIdBytes),
    rawId: b64urlEncode(credIdBytes),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: b64urlEncode(clientData),
      authenticatorData: b64urlEncode(authData),
      signature: b64urlEncode(signature),
      userHandle: record.user_id ? b64urlEncode(b64decode(record.user_id)) : null,
    },
    clientExtensionResults: {},
  };
}

// ------------------------------------------------------------------
// Clone detection (device-local high-water marks)
// ------------------------------------------------------------------

export type SignCountHighWater = Record<string, number>;

export interface CloneWarning {
  credential_id: string;
  rp_id: string;
  sign_count: number;
  high_water: number;
}

/** Flag records whose sign_count has REGRESSED below the highest
 * count this device has previously seen for that credential. That
 * is the local clone signal: another copy of the vault (an older
 * restore, or a cloned authenticator) has been signing. Restoring
 * an older vault copy legitimately regresses the count — surfacing
 * exactly that is the point of the warning. */
export function checkCloneRegression(
  records: PasskeyRecord[],
  highWater: SignCountHighWater,
): CloneWarning[] {
  const out: CloneWarning[] = [];
  for (const r of records) {
    const hw = highWater[r.credential_id];
    if (hw !== undefined && r.sign_count < hw) {
      out.push({ credential_id: r.credential_id, rp_id: r.rp_id, sign_count: r.sign_count, high_water: hw });
    }
  }
  return out;
}

export function updateHighWater(
  records: PasskeyRecord[],
  highWater: SignCountHighWater,
): SignCountHighWater {
  const out = { ...highWater };
  for (const r of records) {
    out[r.credential_id] = Math.max(out[r.credential_id] ?? 0, r.sign_count);
  }
  return out;
}
