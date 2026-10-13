// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** MKBAK backup packages (backup_pkg.py) — the web client
 * implements the recovery-recipient import path for a FRESH target:
 *
 *   1. the source fingerprint is recomputed from the package's own
 *      source keys and must match the header AND the fingerprint
 *      the user supplies from an independent channel (the desktop
 *      shows it at export time) — a package cannot vouch for itself;
 *   2. the Ed25519 signature over the canonical package JSON must
 *      verify under the source key;
 *   3. the content key is unwrapped with the recovery recipient
 *      keypair re-derived from the user's BIP-39 phrase;
 *   4. the bundled vault must be Vault v3 and belong to the same
 *      vault id.
 *
 * Device-recipient import and package EXPORT are deferred: export
 * requires an enrolled device identity, which the web client does
 * not hold in v1 (see docs/FEATURE_MATRIX.md). Everything the
 * Python importer refuses on this path, this module refuses too.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { aesGcmDecrypt, hkdfSha256, sha256Bytes, type SealedBlob } from "./crypto.js";
import {
  b64decode,
  canonicalJson,
  hexEncode,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";
import { recoveryBackupKeypair } from "./recovery.js";

const WRAP_INFO = utf8Encode("mkbak-wrap-v1");

export class BackupRefusedError extends Error {}

export interface PackageInfo {
  packageId: string;
  createdAt: number;
  vaultId: string;
  sourceDeviceId: string;
  sourceFingerprint: string;
  fingerprintMatchesHeader: boolean;
  signatureValid: boolean;
  recipients: { type: string; deviceId?: string; fingerprint?: string }[];
}

interface PackageFile {
  format: string;
  version: number;
  package_id: string;
  created_at: number;
  source: {
    device_id: string;
    fingerprint: string;
    x25519_pub: string;
    ed25519_pub: string;
    vault_id: string;
  };
  recipients: {
    type: string;
    device_id?: string;
    fingerprint?: string;
    wrapped_key: SealedBlob & { ephemeral: string };
  }[];
  content: SealedBlob;
  signature: string;
  [key: string]: unknown;
}

function groupedFingerprint(digestHex: string): string {
  const groups: string[] = [];
  for (let i = 0; i < 32; i += 4) groups.push(digestHex.slice(i, i + 4));
  return groups.join(":");
}

/** device_fingerprint() in devices.py: SHA-256(x25519 || ed25519). */
export function deviceFingerprint(xPub: Uint8Array, ePub: Uint8Array): string {
  const both = new Uint8Array(xPub.length + ePub.length);
  both.set(xPub);
  both.set(ePub, xPub.length);
  return groupedFingerprint(hexEncode(sha256Bytes(both)));
}

function recoveryFingerprint(pubRaw: Uint8Array): string {
  return groupedFingerprint(hexEncode(sha256Bytes(pubRaw)));
}

function parsePackage(bytes: Uint8Array): PackageFile {
  let pkg: any;
  try {
    pkg = JSON.parse(utf8Decode(bytes));
  } catch {
    throw new BackupRefusedError("package is malformed: not valid JSON");
  }
  if (typeof pkg !== "object" || pkg === null || pkg.format !== "MKBAK") {
    throw new BackupRefusedError("not a backup package (bad format token)");
  }
  if (pkg.version !== 1) {
    throw new BackupRefusedError(
      `unsupported package version ${String(pkg.version)} — refusing a possible downgrade`,
    );
  }
  for (const field of ["package_id", "created_at", "source", "recipients", "content", "signature"]) {
    if (!(field in pkg)) throw new BackupRefusedError(`package is missing '${field}'`);
  }
  return pkg as PackageFile;
}

function verifySignature(pkg: PackageFile): boolean {
  try {
    const { signature, ...rest } = pkg;
    const pub = b64decode(pkg.source.ed25519_pub);
    return ed25519.verify(b64decode(signature), utf8Encode(canonicalJson(rest)), pub);
  } catch {
    return false;
  }
}

export function inspectPackage(bytes: Uint8Array): PackageInfo {
  const pkg = parsePackage(bytes);
  let fingerprint = "";
  try {
    fingerprint = deviceFingerprint(
      b64decode(pkg.source.x25519_pub),
      b64decode(pkg.source.ed25519_pub),
    );
  } catch {
    throw new BackupRefusedError("package source keys are malformed");
  }
  return {
    packageId: pkg.package_id,
    createdAt: pkg.created_at,
    vaultId: pkg.source.vault_id,
    sourceDeviceId: pkg.source.device_id,
    sourceFingerprint: fingerprint,
    fingerprintMatchesHeader: pkg.source.fingerprint === fingerprint,
    signatureValid: verifySignature(pkg),
    recipients: (pkg.recipients ?? []).map((r) => ({
      type: r.type,
      deviceId: r.device_id,
      fingerprint: r.fingerprint,
    })),
  };
}

async function openSealed(
  privRaw: Uint8Array,
  blob: SealedBlob & { ephemeral: string },
  aad: Uint8Array,
): Promise<Uint8Array> {
  const shared = x25519.getSharedSecret(privRaw, b64decode(blob.ephemeral));
  if (shared.every((b) => b === 0)) {
    throw new BackupRefusedError("sealed key produced a null shared secret");
  }
  const key = hkdfSha256(shared, WRAP_INFO, 32, undefined);
  const pt = await aesGcmDecrypt(key, blob, aad);
  if (pt === null) throw new BackupRefusedError("sealed key failed to open");
  return pt;
}

/**
 * Import a package via its recovery recipient. Fresh-target
 * semantics: the caller installs the returned vault bytes as a new
 * vault (the app layer refuses to overwrite an existing different
 * vault, mirroring the Python importer's target checks).
 */
export async function importPackageWithRecovery(
  bytes: Uint8Array,
  recoveryPhrase: string,
  expectFingerprint: string,
): Promise<{ vaultBytes: Uint8Array; vaultId: string; sourceFingerprint: string }> {
  const pkg = parsePackage(bytes);
  const source = pkg.source;
  const fingerprint = deviceFingerprint(
    b64decode(source.x25519_pub),
    b64decode(source.ed25519_pub),
  );
  if (source.fingerprint !== fingerprint) {
    throw new BackupRefusedError("package source fingerprint does not match its keys");
  }
  if (!expectFingerprint) {
    throw new BackupRefusedError(
      "fresh-device import requires the source fingerprint obtained independently of the package",
    );
  }
  if (
    expectFingerprint.replace(/:/g, "").toLowerCase() !==
    fingerprint.replace(/:/g, "").toLowerCase()
  ) {
    throw new BackupRefusedError(
      "source fingerprint does not match the one supplied independently — refusing the package",
    );
  }
  if (!verifySignature(pkg)) {
    throw new BackupRefusedError(
      "package signature does not verify — it was tampered with or re-signed by another key",
    );
  }
  const recipient = (pkg.recipients ?? []).find((r) => r.type === "recovery");
  if (!recipient) {
    throw new BackupRefusedError("package has no recovery recipient");
  }
  const vaultId = source.vault_id;
  const { privateRaw, publicRaw } = await recoveryBackupKeypair(recoveryPhrase, vaultId);
  if (recoveryFingerprint(publicRaw) !== recipient.fingerprint) {
    throw new BackupRefusedError(
      "the recovery phrase does not match this package's recovery recipient",
    );
  }
  const wrapAad = utf8Encode(`mkbak-wrap:v1:${pkg.package_id}:${vaultId}:recovery`);
  const contentKey = await openSealed(privateRaw, recipient.wrapped_key, wrapAad);
  const contentBytes = await aesGcmDecrypt(
    contentKey,
    pkg.content,
    utf8Encode(`mkbak:v1:${vaultId}`),
  );
  if (contentBytes === null) {
    throw new BackupRefusedError("package content failed to decrypt — it was tampered with");
  }
  let content: any;
  try {
    content = JSON.parse(utf8Decode(contentBytes));
  } catch {
    throw new BackupRefusedError("package content is not valid JSON");
  }
  if (content.vault_id !== vaultId) {
    throw new BackupRefusedError("package content names a different vault");
  }
  let vaultBytes: Uint8Array;
  try {
    vaultBytes = b64decode(content.vault as string);
  } catch {
    throw new BackupRefusedError("package vault content is malformed");
  }
  let header: any;
  try {
    header = JSON.parse(utf8Decode(vaultBytes));
  } catch {
    throw new BackupRefusedError("bundled vault is not readable JSON");
  }
  if (header.format !== "MKVLT" || header.version !== 3 || !header.vault_id) {
    throw new BackupRefusedError("bundled vault is not an acceptable Vault v3 file");
  }
  if (header.vault_id !== vaultId) {
    throw new BackupRefusedError("bundled vault belongs to a different vault id");
  }
  return { vaultBytes, vaultId, sourceFingerprint: fingerprint };
}
