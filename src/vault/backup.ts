// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** MKBAK backup packages (backup_pkg.py) — full mirror of the
 * desktop engine: export AND import, all recipient paths.
 *
 * A package carries the whole vault encrypted under a random
 * content key, wrapped for:
 *
 *   * every enrolled, non-revoked DEVICE;
 *   * every active PAIRING holding the "export" scope (v2) — an
 *     unpaired, revoked, disabled or expired target gets NO slot;
 *   * a RECOVERY recipient re-derived from the user's BIP-39
 *     phrase. In v2 packages (the default for new exports) the
 *     recovery slot is TWO-FACTOR: the phrase seal is itself
 *     encrypted under a key derived from a backup code (8 words,
 *     shown once at export, never stored). Phrase alone fails;
 *     code alone fails; a wrong code fails closed. V1 packages are
 *     LEGACY — phrase-only — and are labelled as such.
 *
 * Import is strict and fails closed, mirroring the desktop: the
 * source fingerprint is recomputed from the package's own source
 * keys and must match the header AND the fingerprint the user
 * supplies from an independent channel (a package cannot vouch for
 * itself); the Ed25519 signature over the canonical package JSON
 * must verify; the bundled vault must be Vault v3 of the same id.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  argon2idRaw,
  hkdfSha256,
  sha256Bytes,
  type SealedBlob,
} from "./crypto.js";
import {
  b64decode,
  b64encode,
  canonicalJson,
  hexEncode,
  nowSeconds,
  randomBytes,
  utf8Decode,
  utf8Encode,
  uuidHex,
} from "./encoding.js";
import { recoveryBackupKeypair } from "./recovery.js";
import {
  generateBackupCode,
  normalizeBackupCode,
  pairingActive,
  pairingFingerprint,
  type PairingRecord,
} from "./pairings.js";
import type { DeviceIdentity } from "./device.js";

const SUPPORTED_VERSIONS = [1, 2];
export const PACKAGE_VERSION = 2;
const CODE_KDF_PARAMS = { time_cost: 3, memory_cost: 65536, parallelism: 4 };
const CODE_HKDF_INFO = utf8Encode("mkbak-v2:backup-code");

export class BackupRefusedError extends Error {}

interface WrappedKey extends SealedBlob {
  ephemeral?: string;
}

interface RecipientFile {
  type: string;
  device_id?: string;
  target_id?: string;
  fingerprint?: string;
  version?: number;
  code_kdf?: {
    salt: string;
    time_cost?: number;
    memory_cost?: number;
    parallelism?: number;
  };
  wrapped_key: WrappedKey;
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
  recipients: RecipientFile[];
  content: SealedBlob;
  signature: string;
  [key: string]: unknown;
}

export interface PackageInfo {
  packageId: string;
  version: number;
  /** v1 package: phrase-only recovery — the weaker legacy format. */
  legacy: boolean;
  /** v2 package: recovery needs phrase AND backup code. */
  recoveryTwoFactor: boolean;
  createdAt: number;
  vaultId: string;
  sourceDeviceId: string;
  sourceFingerprint: string;
  fingerprintMatchesHeader: boolean;
  signatureValid: boolean;
  recipients: { type: string; deviceId?: string; targetId?: string; fingerprint?: string }[];
}

export interface ImportResult {
  vaultBytes: Uint8Array;
  vaultId: string;
  sourceFingerprint: string;
  /** device:<id> | pairing:<id> | recovery */
  via: string;
  packageVersion: number;
  legacy: boolean;
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

function wrapInfo(version: number): Uint8Array {
  return utf8Encode(`mkbak-wrap-v${version}`);
}

function wrapAad(packageId: string, vaultId: string, recipientId: string, version: number): Uint8Array {
  return utf8Encode(`mkbak-wrap:v${version}:${packageId}:${vaultId}:${recipientId}`);
}

function contentAad(vaultId: string, version: number): Uint8Array {
  return utf8Encode(`mkbak:v${version}:${vaultId}`);
}

function codeAad(packageId: string, vaultId: string): Uint8Array {
  return utf8Encode(`mkbak-code:v2:${packageId}:${vaultId}`);
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
  if (!SUPPORTED_VERSIONS.includes(pkg.version)) {
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
    version: pkg.version,
    legacy: pkg.version === 1,
    recoveryTwoFactor: pkg.version === 2,
    createdAt: pkg.created_at,
    vaultId: pkg.source.vault_id,
    sourceDeviceId: pkg.source.device_id,
    sourceFingerprint: fingerprint,
    fingerprintMatchesHeader: pkg.source.fingerprint === fingerprint,
    signatureValid: verifySignature(pkg),
    recipients: (pkg.recipients ?? []).map((r) => ({
      type: r.type,
      deviceId: r.device_id,
      targetId: r.target_id,
      fingerprint: r.fingerprint,
    })),
  };
}

// ---------------------------------------------------------------------
// sealing (ephemeral ECDH -> HKDF -> AES-256-GCM), bound by AAD
// ---------------------------------------------------------------------

async function sealToPub(
  pubRaw: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  version: number,
): Promise<WrappedKey> {
  const ephPriv = randomBytes(32);
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, pubRaw);
  if (shared.every((b) => b === 0)) {
    throw new BackupRefusedError("recipient key produced a null shared secret");
  }
  const key = hkdfSha256(shared, wrapInfo(version), 32, undefined);
  const blob = await aesGcmEncrypt(key, plaintext, aad);
  ephPriv.fill(0);
  return { ...blob, ephemeral: b64encode(ephPub) };
}

/** Returns the plaintext, or null when the seal does not open for
 *  this private key (wrong recipient / tampered). */
async function openSealed(
  privRaw: Uint8Array,
  blob: WrappedKey,
  aad: Uint8Array,
  version: number,
): Promise<Uint8Array | null> {
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(privRaw, b64decode(blob.ephemeral ?? ""));
  } catch {
    return null;
  }
  if (shared.every((b) => b === 0)) {
    throw new BackupRefusedError("sealed key produced a null shared secret");
  }
  const key = hkdfSha256(shared, wrapInfo(version), 32, undefined);
  return aesGcmDecrypt(key, blob, aad);
}

async function backupCodeKey(
  code: string,
  salt: Uint8Array,
  params: { time_cost?: number; memory_cost?: number; parallelism?: number },
): Promise<Uint8Array> {
  const raw = await argon2idRaw(utf8Encode(code), salt, {
    time_cost: params.time_cost ?? CODE_KDF_PARAMS.time_cost,
    memory_cost: params.memory_cost ?? CODE_KDF_PARAMS.memory_cost,
    parallelism: params.parallelism ?? CODE_KDF_PARAMS.parallelism,
  });
  return hkdfSha256(raw, CODE_HKDF_INFO, 32, undefined);
}

// ---------------------------------------------------------------------
// import — shared checks and tail
// ---------------------------------------------------------------------

function checkSource(pkg: PackageFile, expectFingerprint: string): string {
  const source = pkg.source;
  let fingerprint: string;
  try {
    fingerprint = deviceFingerprint(
      b64decode(source.x25519_pub),
      b64decode(source.ed25519_pub),
    );
  } catch {
    throw new BackupRefusedError("package source keys are malformed");
  }
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
  return fingerprint;
}

async function finishImport(
  pkg: PackageFile,
  contentKey: Uint8Array,
  via: string,
  sourceFingerprint: string,
): Promise<ImportResult> {
  const vaultId = pkg.source.vault_id;
  const contentBytes = await aesGcmDecrypt(contentKey, pkg.content, contentAad(vaultId, pkg.version));
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
  return {
    vaultBytes,
    vaultId,
    sourceFingerprint,
    via,
    packageVersion: pkg.version,
    legacy: pkg.version === 1,
  };
}

/**
 * Import via the recovery recipient. Fresh-target semantics: the
 * caller installs the returned vault bytes as a new vault. For a
 * v2 package the backup code is REQUIRED alongside the phrase
 * (two-factor); for a legacy v1 package the phrase alone opens it.
 */
export async function importPackageWithRecovery(
  bytes: Uint8Array,
  recoveryPhrase: string,
  expectFingerprint: string,
  backupCode?: string,
): Promise<ImportResult> {
  const pkg = parsePackage(bytes);
  const fingerprint = checkSource(pkg, expectFingerprint);
  const recipient = (pkg.recipients ?? []).find((r) => r.type === "recovery");
  if (!recipient) {
    throw new BackupRefusedError("package has no recovery recipient");
  }
  const vaultId = pkg.source.vault_id;
  const { privateRaw, publicRaw } = await recoveryBackupKeypair(recoveryPhrase, vaultId);
  if (recoveryFingerprint(publicRaw) !== recipient.fingerprint) {
    throw new BackupRefusedError(
      "the recovery phrase does not match this package's recovery recipient",
    );
  }
  let contentKey: Uint8Array | null;
  if (pkg.version === 1) {
    contentKey = await openSealed(
      privateRaw,
      recipient.wrapped_key,
      wrapAad(pkg.package_id, vaultId, "recovery", 1),
      1,
    );
    if (!contentKey) {
      throw new BackupRefusedError("recovery unwrap failed — package is damaged");
    }
  } else {
    if (!backupCode) {
      throw new BackupRefusedError(
        "this backup uses two-factor recovery: it needs the backup code as " +
          "well as the recovery phrase. The code was shown once when the " +
          "backup was made.",
      );
    }
    let code: string;
    try {
      code = normalizeBackupCode(backupCode);
    } catch (err) {
      throw new BackupRefusedError(
        `the backup code is not usable: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
    const kdf = recipient.code_kdf ?? { salt: "" };
    const codeKey = await backupCodeKey(code, b64decode(kdf.salt), kdf);
    const sealedBytes = await aesGcmDecrypt(
      codeKey,
      recipient.wrapped_key,
      codeAad(pkg.package_id, vaultId),
    );
    if (!sealedBytes) {
      throw new BackupRefusedError(
        "the backup code did not open this backup — check the words and try again",
      );
    }
    let sealed: WrappedKey;
    try {
      sealed = JSON.parse(utf8Decode(sealedBytes)) as WrappedKey;
    } catch {
      throw new BackupRefusedError("recovery unwrap failed — package is damaged");
    }
    contentKey = await openSealed(
      privateRaw,
      sealed,
      wrapAad(pkg.package_id, vaultId, "recovery", 2),
      2,
    );
    if (!contentKey) {
      throw new BackupRefusedError("recovery unwrap failed — package is damaged");
    }
  }
  return finishImport(pkg, contentKey, "recovery", fingerprint);
}

/** Import via an enrolled device's own key — inside the trust
 *  boundary: no phrase, no backup code. */
export async function importPackageWithDevice(
  bytes: Uint8Array,
  identity: DeviceIdentity,
  expectFingerprint: string,
): Promise<ImportResult> {
  const pkg = parsePackage(bytes);
  const fingerprint = checkSource(pkg, expectFingerprint);
  const recipient = (pkg.recipients ?? []).find(
    (r) => r.type === "device" && r.device_id === identity.deviceId,
  );
  if (!recipient) {
    throw new BackupRefusedError("this device is not a recipient of this package");
  }
  if (recipient.fingerprint !== identity.fingerprint) {
    throw new BackupRefusedError(
      "the device recipient fingerprint does not match this device — the package was built for another key under this device id",
    );
  }
  const contentKey = await openSealed(
    identity.xPrivateRaw,
    recipient.wrapped_key,
    wrapAad(pkg.package_id, pkg.source.vault_id, identity.deviceId, pkg.version),
    pkg.version,
  );
  if (!contentKey) {
    throw new BackupRefusedError("device unwrap failed — package is damaged");
  }
  return finishImport(pkg, contentKey, `device:${identity.deviceId}`, fingerprint);
}

/** Import via a paired target's key. The caller is responsible for
 *  the registry refusal (a target the destination vault shows as
 *  revoked must not be offered this path), mirroring the desktop's
 *  pairing_registry check. */
export async function importPackageWithPairing(
  bytes: Uint8Array,
  pairingPrivRaw: Uint8Array,
  expectFingerprint: string,
): Promise<ImportResult> {
  const pkg = parsePackage(bytes);
  const fingerprint = checkSource(pkg, expectFingerprint);
  const myFingerprint = pairingFingerprint(x25519.getPublicKey(pairingPrivRaw));
  const recipient = (pkg.recipients ?? []).find(
    (r) => r.type === "pairing" && r.fingerprint === myFingerprint,
  );
  if (!recipient || !recipient.target_id) {
    throw new BackupRefusedError("not a recipient of this package: no pairing slot for this key");
  }
  const contentKey = await openSealed(
    pairingPrivRaw,
    recipient.wrapped_key,
    wrapAad(pkg.package_id, pkg.source.vault_id, recipient.target_id, pkg.version),
    pkg.version,
  );
  if (!contentKey) {
    throw new BackupRefusedError("pairing unwrap failed — package is damaged");
  }
  return finishImport(pkg, contentKey, `pairing:${recipient.target_id}`, fingerprint);
}

// ---------------------------------------------------------------------
// export (MKBAK v2)
// ---------------------------------------------------------------------

export interface ExportPackageInput {
  vaultBytes: Uint8Array;
  vaultId: string;
  /** This client's device identity — signs the package and is its
   *  source. Must itself be enrolled in `devices`. */
  source: DeviceIdentity;
  /** The vault's device registry (core "devices"). */
  devices: Record<string, { x25519_pub: string; fingerprint?: string; revoked_at?: number | null }>;
  /** The vault's pairing registry (core "pairings"). */
  pairings: Record<string, PairingRecord>;
  /** The vault's backup recovery recipient public key, raw bytes
   *  (core "backup_recovery_pub"). */
  backupRecoveryPub: Uint8Array;
}

export interface ExportPackageResult {
  packageBytes: Uint8Array;
  /** Shown to the user ONCE; never stored anywhere. */
  backupCode: string;
  packageId: string;
  recipientLabels: string[];
}

export async function exportPackage(input: ExportPackageInput): Promise<ExportPackageResult> {
  const version = PACKAGE_VERSION;
  const self = input.devices[input.source.deviceId];
  if (!self || self.revoked_at) {
    throw new BackupRefusedError(
      "this device is not enrolled in the vault — enroll it first so your own backups always have a device recipient",
    );
  }
  const packageId = uuidHex();
  const createdAt = nowSeconds();
  const contentKey = randomBytes(32);
  const content = {
    vault_id: input.vaultId,
    exported_at: createdAt,
    vault: b64encode(input.vaultBytes),
    audit: null,
    anchor: null,
  };
  const contentBlob = await aesGcmEncrypt(
    contentKey,
    utf8Encode(canonicalJson(content)),
    contentAad(input.vaultId, version),
  );

  const recipients: RecipientFile[] = [];
  for (const deviceId of Object.keys(input.devices).sort()) {
    const rec = input.devices[deviceId]!;
    if (rec.revoked_at) continue;
    recipients.push({
      type: "device",
      device_id: deviceId,
      fingerprint: rec.fingerprint ?? "",
      wrapped_key: await sealToPub(
        b64decode(rec.x25519_pub),
        contentKey,
        wrapAad(packageId, input.vaultId, deviceId, version),
        version,
      ),
    });
  }
  for (const targetId of Object.keys(input.pairings).sort()) {
    const rec = input.pairings[targetId]!;
    if (!pairingActive(rec) || !rec.scopes.includes("export")) continue;
    recipients.push({
      type: "pairing",
      target_id: targetId,
      fingerprint: rec.fingerprint,
      wrapped_key: await sealToPub(
        b64decode(rec.x25519_pub),
        contentKey,
        wrapAad(packageId, input.vaultId, targetId, version),
        version,
      ),
    });
  }

  // Two-factor recovery slot: seal to the phrase key, then encrypt
  // that seal under the backup-code key.
  const backupCode = generateBackupCode();
  const sealed = await sealToPub(
    input.backupRecoveryPub,
    contentKey,
    wrapAad(packageId, input.vaultId, "recovery", version),
    version,
  );
  const salt = randomBytes(16);
  const codeKey = await backupCodeKey(backupCode, salt, CODE_KDF_PARAMS);
  const wrapped = await aesGcmEncrypt(
    codeKey,
    utf8Encode(canonicalJson(sealed)),
    codeAad(packageId, input.vaultId),
  );
  recipients.push({
    type: "recovery",
    version: 2,
    fingerprint: recoveryFingerprint(input.backupRecoveryPub),
    code_kdf: { salt: b64encode(salt), ...CODE_KDF_PARAMS },
    wrapped_key: { ...wrapped },
  });

  const pkg: PackageFile = {
    format: "MKBAK",
    version,
    package_id: packageId,
    created_at: createdAt,
    source: {
      device_id: input.source.deviceId,
      fingerprint: input.source.fingerprint,
      x25519_pub: b64encode(input.source.xPub),
      ed25519_pub: b64encode(input.source.ePub),
      vault_id: input.vaultId,
    },
    recipients,
    content: contentBlob,
    signature: "",
  };
  const { signature: _drop, ...unsigned } = pkg;
  pkg.signature = b64encode(input.source.sign(utf8Encode(canonicalJson(unsigned))));
  contentKey.fill(0);
  return {
    packageBytes: utf8Encode(JSON.stringify(pkg, null, 1)),
    backupCode,
    packageId,
    recipientLabels: recipients.map((r) =>
      r.type === "device"
        ? `device:${r.device_id}`
        : r.type === "pairing"
          ? `paired:${r.target_id}`
          : "recovery",
    ),
  };
}
