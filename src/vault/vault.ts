// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.
//
// This module is part of the proprietary core (vault format and
// cryptography). It is NOT licensed under Apache 2.0, MIT, or any
// other open licence. No patent licence is granted by this file; all
// patent rights are expressly reserved. See LICENSING.md.

/** Vault v3 engine for the web client — a faithful port of the
 * Python engine's file format (mykey.py):
 *
 *   file  = { format:"MKVLT", version:3, vault_id, inbox_pub,
 *             slots[], verifier, core, entries[], bundles{} }
 *   core  = AES-256-GCM(VK) over the vault core JSON (agent
 *           registry, metadata key, per-entry data keys, audit
 *           seal, device registry) with AAD "core:v3:<vault_id>"
 *   entry = metadata under KMETA, secret fields under a per-entry
 *           DEK_pw, TOTP secret under DEK_totp, each AES-256-GCM
 *           with domain AADs, and a SHA-256 ciphertext hash sealed
 *           in the core that is verified before decryption.
 *
 * Slots wrap the vault key (VK): "master" (password KDF), "recovery"
 * (BIP-39-derived key), agent slots (bundle keys only — never VK),
 * and opaque wrapped slots preserved verbatim. Unknown core fields
 * are preserved verbatim on save, so a file round-tripped through
 * this client keeps every desktop feature intact, including agent
 * bundles, which are rebuilt on every save exactly as the Python
 * engine rebuilds them.
 *
 * Vault v1/v2 files are NOT migrated here: the client refuses them
 * with instructions to open them once in the desktop app, which
 * performs the migration. Nothing is ever half-migrated.
 *
 * Passkey entries (kind "passkey") add a fourth per-entry key
 * class: the WebAuthn record — credential PRIVATE key included —
 * lives in a "passkey" blob under DEK_passkey, sealed by a hash in
 * the core's passkey_hashes map (kept separate from entry_hashes
 * so pre-passkey vaults verify byte-for-byte). DEK_passkey is
 * never placed in an agent bundle and passkey entries are excluded
 * from bundle targets entirely. See docs/PASSKEYS.md.
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  ARGON_DEFAULTS,
  aesGcmDecrypt,
  aesGcmEncrypt,
  argon2idRaw,
  deriveSlotKey,
  hmacSha256,
  type SealedBlob,
} from "./crypto.js";
import {
  b64decode,
  b64encode,
  bytesEqual,
  nowSeconds,
  randomBytes,
  utf8Decode,
  utf8Encode,
  uuidHex,
} from "./encoding.js";
import {
  deriveRecoveryKey,
  isValidPhrase,
  newRecoveryPhrase,
  normalizePhrase,
  recoveryBackupPublic,
} from "./recovery.js";
import {
  classifyImport,
  type ConflictPolicy,
  type ImportRecord,
  type ImportStats,
} from "./csvio.js";
import {
  FREE_ENTRY_LIMIT,
  FREE_MAX_CONNECTIONS,
  LICENCE_PUBLIC_KEY_B64,
  LicenceRequiredError,
  normalizeToken,
  statusLine as licenceStatusLine,
  verifyToken,
  type LicencePayload,
} from "./licence.js";

export const FORMAT_TOKEN = "MKVLT";
export const FORMAT_VERSION = 3;
export const MIN_MASTER_PASSWORD_LENGTH = 12;
export const MIN_GENERATED_PASSWORD_LENGTH = 16;
const VERIFIER_LABEL = "vault-verifier-v3";
const METADATA_FIELDS = ["service", "username", "url", "tags", "favourite", "created", "updated", "kind"] as const;
const ENTRY_FIELDS = ["service", "username", "password", "url", "notes", "totp_secret", "tags", "favourite", "rotate_days"] as const;

/** Vault-wide default password rotation period in days, matching
 * the Python engine (mykey.py DEFAULT_ROTATE_DAYS). The default
 * itself is stored in the encrypted core ("settings"); per-entry
 * rotation fields ride in the entry's secret blob, exactly as the
 * Python engine stores them — never in metadata or a sidecar. */
export const DEFAULT_ROTATE_DAYS = 180;
export class WrongPasswordError extends Error {}
export class VaultCorruptError extends Error {}
export class UnsupportedVaultError extends VaultCorruptError {}

/** The WebAuthn record stored (encrypted) in a passkey entry's
 * passkey blob — field names mirror the Python engine's record
 * contract exactly (PASSKEY_RECORD_FIELDS in mykey.py).
 * private_key is PKCS#8 DER (base64); public_key is the raw
 * uncompressed EC point for ES256 or the raw public key for
 * EdDSA; credential_id / user_id / aaguid are base64. */
export interface PasskeyRecord {
  rp_id: string;
  user_id: string;
  user_name: string;
  user_display_name: string;
  credential_id: string;
  alg: number;
  public_key: string;
  private_key: string;
  sign_count: number;
  transports: string[];
  created_at: number;
  aaguid: string;
  backup_eligible: boolean;
  backed_up: boolean;
}

export interface VaultEntry {
  id: string;
  service: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totp_secret: string;
  tags: string[];
  favourite: boolean;
  kind: "login" | "passkey";
  passkey: PasskeyRecord | null;
  created: number;
  updated: number;
  /** When the password was last set (epoch seconds), or null when
   * no date is recorded (e.g. imported entries). */
  password_set_at: number | null;
  /** Per-entry rotation period in days: null = vault default,
   * 0 = never rotate this entry. */
  rotate_days: number | null;
}

export interface Slot {
  id: string;
  algo: string;
  salt: string;
  nonce: string;
  ciphertext: string;
  time_cost?: number;
  memory_cost?: number;
  parallelism?: number;
  iterations?: number;
  [key: string]: unknown;
}

interface RawEntryObject {
  id: string;
  meta: SealedBlob | null;
  secret: SealedBlob | null;
  totp: SealedBlob | null;
  passkey: SealedBlob | null;
  pending: unknown | null;
  [key: string]: unknown;
}

interface VaultFile {
  format: string;
  version: number;
  vault_id: string;
  inbox_pub: string;
  slots: Slot[];
  verifier: string;
  core: SealedBlob;
  entries: RawEntryObject[];
  bundles: Record<string, SealedBlob>;
}

type CoreObject = Record<string, any>;

function aad(kind: string, ident: string): Uint8Array {
  return utf8Encode(`${kind}:v3:${ident}`);
}

/** The sealed entry-ciphertext hash, exported for the test suite's
 * file surgery (simulating files written by older clients), the
 * same role mykey.py's _entry_hash plays in the Python tests. */
export const computeEntryHash = entryHash;

function entryHash(obj: RawEntryObject): string {
  const h = sha256.create();
  h.update(utf8Encode("entryhash:v3"));
  for (const field of ["meta", "secret", "totp"] as const) {
    const blob = obj[field];
    if (blob == null) h.update(new Uint8Array([0, 110, 111, 110, 101, 0])); // \x00none\x00
    else {
      h.update(b64decode(blob.nonce));
      h.update(b64decode(blob.ciphertext));
    }
  }
  return [...h.digest()].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Normalize a rotation period: null (unset) or a whole number of
 * days >= 0, where 0 means "never". Mirrors the Python engine's
 * _validate_rotate_days — anything else is a caller bug. */
export function validateRotateDays(value: number | null): number | null {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error("rotation period must be a whole number of days or unset");
  }
  return value;
}

/** Hash of one entry's passkey blob, sealed in the core —
 * identical construction to the Python engine's _passkey_hash. */
function passkeyHash(blob: SealedBlob): string {
  const h = sha256.create();
  h.update(utf8Encode("passkeyhash:v3"));
  h.update(b64decode(blob.nonce));
  h.update(b64decode(blob.ciphertext));
  return [...h.digest()].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Validate + normalize a passkey record — mirrors the Python
 * engine's validate_passkey_record. Throws on invalid input. */
export function validatePasskeyRecord(record: any): PasskeyRecord {
  if (typeof record !== "object" || record === null) throw new Error("passkey record must be an object");
  if (typeof record.rp_id !== "string" || !record.rp_id) throw new Error("passkey record needs a non-empty rp_id");
  for (const f of ["credential_id", "public_key", "private_key"] as const) {
    const v = record[f];
    if (typeof v !== "string" || !v) throw new Error(`passkey record needs ${f} (base64)`);
    b64decode(v); // throws on invalid base64
  }
  const out: PasskeyRecord = {
    rp_id: record.rp_id,
    user_id: record.user_id ?? "",
    user_name: record.user_name ?? "",
    user_display_name: record.user_display_name ?? "",
    credential_id: record.credential_id,
    alg: Number(record.alg ?? -7),
    public_key: record.public_key,
    private_key: record.private_key,
    sign_count: Number(record.sign_count ?? 0),
    transports: Array.isArray(record.transports) && record.transports.length ? [...record.transports] : ["internal"],
    created_at: Number(record.created_at ?? nowSeconds()),
    aaguid: record.aaguid ?? b64encode(new Uint8Array(16)),
    backup_eligible: record.backup_eligible !== undefined ? Boolean(record.backup_eligible) : true,
    backed_up: record.backed_up !== undefined ? Boolean(record.backed_up) : true,
  };
  if (!Number.isFinite(out.sign_count) || out.sign_count < 0) throw new Error("passkey sign_count cannot be negative");
  return out;
}

function scopeCoversEntry(scopes: string[], entry: VaultEntry): boolean {
  for (const scope of scopes) {
    if (scope === "get:*") return true;
    if (scope.startsWith("get:tag:")) {
      if (entry.tags.includes(scope.slice("get:tag:".length))) return true;
    } else if (scope.startsWith("get:")) {
      if (scope.slice(4) === entry.service) return true;
    }
  }
  return false;
}

function parseVaultFile(bytes: Uint8Array): VaultFile {
  let data: any;
  try {
    data = JSON.parse(utf8Decode(bytes));
  } catch {
    throw new VaultCorruptError("vault file is not readable JSON");
  }
  if (typeof data !== "object" || data === null || data.format !== FORMAT_TOKEN) {
    throw new VaultCorruptError("not a MyKey vault file (bad format token)");
  }
  if (data.version !== FORMAT_VERSION) {
    throw new UnsupportedVaultError(
      `vault version ${data.version} must be opened once in the desktop app, which migrates it to Vault v3`,
    );
  }
  return data as VaultFile;
}

export class VaultSession {
  private vk: Uint8Array;
  private kmeta: Uint8Array;
  private deks = new Map<string, { pw: Uint8Array; totp: Uint8Array | null; passkey: Uint8Array | null }>();
  private core: CoreObject;
  private slots: Slot[];
  private inboxPubB64: string;
  private entriesList: VaultEntry[] = [];
  private rawPending: RawEntryObject[] = [];
  readonly vaultId: string;
  /** True when the core carries an audit seal the web client cannot
   * verify (the audit log sidecar is a desktop/sync artefact). The
   * seal is preserved verbatim on save; see docs/FEATURE_MATRIX.md. */
  readonly auditSealed: boolean;
  /** Licence authority key this session verifies against. Defaults
   * to the production key; tests substitute a test authority,
   * mirroring the Python engine's seam. */
  licencePublicKeyB64: string = LICENCE_PUBLIC_KEY_B64;
  /** The verified payload from the device-local licence slot, set
   * by the app layer when that slot held a valid key (used when
   * the vault itself carries no key). */
  private deviceLicence: LicencePayload | null = null;

  private constructor(init: {
    vk: Uint8Array;
    kmeta: Uint8Array;
    core: CoreObject;
    slots: Slot[];
    inboxPubB64: string;
    vaultId: string;
  }) {
    this.vk = init.vk;
    this.kmeta = init.kmeta;
    this.core = init.core;
    this.slots = init.slots;
    this.inboxPubB64 = init.inboxPubB64;
    this.vaultId = init.vaultId;
    this.auditSealed = Boolean(init.core.audit_head);
    const coreDeks = (init.core.deks ?? {}) as Record<string, { pw: string; totp: string | null; passkey?: string | null }>;
    for (const [eid, d] of Object.entries(coreDeks)) {
      this.deks.set(eid, {
        pw: b64decode(d.pw),
        totp: d.totp ? b64decode(d.totp) : null,
        passkey: d.passkey ? b64decode(d.passkey) : null,
      });
    }
  }

  // ---------------------------------------------------------------
  // Unlock paths
  // ---------------------------------------------------------------

  private static async fromVaultKey(
    file: VaultFile,
    vk: Uint8Array,
  ): Promise<VaultSession> {
    const coreBytes = await aesGcmDecrypt(vk, file.core, aad("core", file.vault_id));
    if (coreBytes === null) throw new VaultCorruptError("vault core failed to decrypt");
    let core: CoreObject;
    try {
      core = JSON.parse(utf8Decode(coreBytes));
    } catch {
      throw new VaultCorruptError("vault core is not valid JSON");
    }
    if (core.vault_id !== file.vault_id) {
      throw new VaultCorruptError("vault id mismatch between header and core");
    }
    // Inbox binding (desktop design review, finding 3): the header
    // public key must be the core private key's pair.
    const inboxPriv = b64decode(core.inbox_priv as string);
    const derivedPub = x25519.getPublicKey(inboxPriv);
    if (!bytesEqual(derivedPub, b64decode(file.inbox_pub))) {
      throw new VaultCorruptError("vault inbox key does not match its core");
    }
    const session = new VaultSession({
      vk,
      kmeta: b64decode(core.kmeta as string),
      core,
      slots: file.slots,
      inboxPubB64: file.inbox_pub,
      vaultId: file.vault_id,
    });
    const hashes = (core.entry_hashes ?? {}) as Record<string, string>;
    const passkeyHashes = (core.passkey_hashes ?? {}) as Record<string, string>;
    for (const obj of file.entries ?? []) {
      if (obj.pending != null) {
        session.rawPending.push(obj);
        continue;
      }
      const eid = obj.id;
      const expected = hashes[eid];
      if (expected === undefined || expected !== entryHash(obj)) {
        throw new VaultCorruptError(
          `entry ${eid} ciphertext does not match the hash sealed in the vault core`,
        );
      }
      const dek = session.deks.get(eid);
      if (!dek) throw new VaultCorruptError(`entry ${eid} has no data keys in the core`);
      const metaBytes = await aesGcmDecrypt(session.kmeta, obj.meta!, aad("meta", eid));
      const secretBytes = await aesGcmDecrypt(dek.pw, obj.secret!, aad("secret", eid));
      if (metaBytes === null || secretBytes === null) {
        throw new VaultCorruptError(`entry ${eid} failed to decrypt`);
      }
      const meta = JSON.parse(utf8Decode(metaBytes));
      const secret = JSON.parse(utf8Decode(secretBytes));
      let totpSecret = "";
      if (obj.totp != null) {
        if (!dek.totp) throw new VaultCorruptError(`entry ${eid} TOTP key missing`);
        const totpBytes = await aesGcmDecrypt(dek.totp, obj.totp, aad("totp", eid));
        if (totpBytes === null) throw new VaultCorruptError(`entry ${eid} TOTP failed to decrypt`);
        totpSecret = JSON.parse(utf8Decode(totpBytes)).totp_secret ?? "";
      }
      // Rotation fields live in the secret blob. Files written
      // before the feature have neither: the set date falls back
      // to the entry's creation time when the record carries one,
      // else null ("date not recorded") — the Python engine's rule.
      const createdRaw = typeof meta.created === "number" ? meta.created : null;
      let passkey: PasskeyRecord | null = null;
      let kind: "login" | "passkey" = meta.kind === "passkey" ? "passkey" : "login";
      if (obj.passkey != null) {
        const sealed = passkeyHashes[eid];
        if (sealed === undefined || sealed !== passkeyHash(obj.passkey)) {
          throw new VaultCorruptError(
            `entry ${eid} passkey ciphertext does not match the hash sealed in the vault core`,
          );
        }
        if (!dek.passkey) {
          throw new VaultCorruptError(`entry ${eid} has a passkey blob but no passkey data key in the core`);
        }
        const pkBytes = await aesGcmDecrypt(dek.passkey, obj.passkey, aad("passkey", eid));
        if (pkBytes === null) throw new VaultCorruptError(`entry ${eid} passkey failed to decrypt`);
        passkey = validatePasskeyRecord(JSON.parse(utf8Decode(pkBytes)));
        kind = "passkey";
      }
      session.entriesList.push({
        id: eid,
        service: meta.service ?? "",
        username: meta.username ?? "",
        url: meta.url ?? "",
        tags: Array.isArray(meta.tags) ? meta.tags : [],
        favourite: Boolean(meta.favourite),
        created: meta.created ?? 0,
        updated: meta.updated ?? 0,
        password: secret.password ?? "",
        notes: secret.notes ?? "",
        totp_secret: totpSecret,
        password_set_at:
          typeof secret.password_set_at === "number"
            ? secret.password_set_at
            : createdRaw,
        rotate_days:
          typeof secret.rotate_days === "number" ? secret.rotate_days : null,
        kind,
        passkey,
      });
    }
    return session;
  }

  static async openWithPassword(bytes: Uint8Array, password: string): Promise<VaultSession> {
    const file = parseVaultFile(bytes);
    const slot = file.slots.find((s) => s.id === "master");
    if (!slot) throw new VaultCorruptError("vault has no master slot");
    const wrapping = await deriveSlotKey(password, slot);
    const vk = await aesGcmDecrypt(wrapping, slot, utf8Encode("slot:master"));
    if (vk === null) throw new WrongPasswordError("master password does not match this vault");
    return VaultSession.fromVaultKey(file, vk);
  }

  static async openWithPhrase(bytes: Uint8Array, phrase: string): Promise<VaultSession> {
    const file = parseVaultFile(bytes);
    const normalized = normalizePhrase(phrase);
    if (!isValidPhrase(normalized)) {
      throw new WrongPasswordError("recovery phrase is not a valid BIP-39 phrase");
    }
    const slot = file.slots.find((s) => s.id === "recovery");
    if (!slot) throw new WrongPasswordError("this vault has no recovery phrase set up");
    const wrapping = await deriveRecoveryKey(normalized, b64decode(slot.salt));
    const vk = await aesGcmDecrypt(wrapping, slot, utf8Encode("slot:recovery"));
    if (vk === null) throw new WrongPasswordError("recovery phrase does not match this vault");
    const session = await VaultSession.fromVaultKey(file, vk);
    // Backfill the Phase 3A backup recovery recipient for vaults
    // whose phrase predates it (mirrors the Python engine).
    if (session.core.backup_recovery_pub == null) {
      const pub = await recoveryBackupPublic(normalized, session.vaultId);
      session.core.backup_recovery_pub = b64encode(pub);
      session.markDirty();
    }
    return session;
  }

  /** Unlock via an opaque wrapped slot (e.g. the Android device slot
   * whose wrap key is held in the platform Keystore). Possession of
   * the wrap key IS the credential: it unwraps VK directly, exactly
   * like the Python engine's unlock_via_wrapped_key. */
  static async openWithWrapKey(
    bytes: Uint8Array,
    slotId: string,
    wrapKey: Uint8Array,
  ): Promise<VaultSession> {
    const file = parseVaultFile(bytes);
    const slot = file.slots.find((s) => s.id === slotId);
    if (!slot) throw new WrongPasswordError(`no unlock slot: ${slotId}`);
    const vk = await aesGcmDecrypt(wrapKey, slot, utf8Encode(`slot:${slotId}`));
    if (vk === null) throw new WrongPasswordError("credential does not match this vault");
    return VaultSession.fromVaultKey(file, vk);
  }

  // ---------------------------------------------------------------
  // Creation
  // ---------------------------------------------------------------

  static async createNew(masterPassword: string): Promise<VaultSession> {
    if (masterPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
      throw new Error(
        `master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters`,
      );
    }
    const vk = randomBytes(32);
    const kmeta = randomBytes(32);
    const vaultId = uuidHex();
    const inboxPriv = randomBytes(32);
    const inboxPub = x25519.getPublicKey(inboxPriv);
    const core: CoreObject = {
      agents: {},
      audit_head: "",
      kmeta: b64encode(kmeta),
      deks: {},
      origins: {},
      entry_hashes: {},
      passkey_hashes: {},
      inbox_priv: b64encode(inboxPriv),
      vault_id: vaultId,
      anchor_seq: 0,
      retired_audit_keys: {},
      retired_pending_keys: {},
      audit_mac_since: 0,
      devices: {},
      pairings: {},
      backup_recovery_pub: null,
      settings: { default_rotate_days: DEFAULT_ROTATE_DAYS },
    };
    const session = new VaultSession({
      vk,
      kmeta,
      core,
      slots: [],
      inboxPubB64: b64encode(inboxPub),
      vaultId,
    });
    session.slots = [await session.buildMasterSlot(masterPassword)];
    return session;
  }

  private async buildMasterSlot(password: string): Promise<Slot> {
    const salt = randomBytes(16);
    const wrapping = await argon2idRaw(utf8Encode(password), salt, ARGON_DEFAULTS);
    const blob = await aesGcmEncrypt(wrapping, this.vk, utf8Encode("slot:master"));
    return {
      id: "master",
      algo: "argon2id",
      salt: b64encode(salt),
      nonce: blob.nonce,
      ciphertext: blob.ciphertext,
      ...ARGON_DEFAULTS,
    };
  }

  // ---------------------------------------------------------------
  // Persistence
  // ---------------------------------------------------------------

  /** Serialize the current state to Vault v3 file bytes (the
   * equivalent of the Python engine's _persist, minus the desktop
   * audit-anchor sidecar). */
  async serialize(): Promise<Uint8Array> {
    const entryObjects: RawEntryObject[] = [];
    const hashes: Record<string, string> = {};
    const pkHashes: Record<string, string> = { ...(this.core.passkey_hashes ?? {}) };
    for (const entry of this.entriesList) {
      const dek = this.deks.get(entry.id)!;
      const meta: Record<string, unknown> = {};
      for (const f of METADATA_FIELDS) meta[f] = entry[f];
      let passkeyBlob: SealedBlob | null = null;
      if (entry.kind === "passkey" && entry.passkey) {
        if (!dek.passkey) throw new VaultCorruptError(`passkey entry ${entry.id} has no passkey data key`);
        passkeyBlob = await aesGcmEncrypt(
          dek.passkey,
          utf8Encode(JSON.stringify(entry.passkey)),
          aad("passkey", entry.id),
        );
        pkHashes[entry.id] = passkeyHash(passkeyBlob);
      } else {
        delete pkHashes[entry.id];
      }
      const obj: RawEntryObject = {
        id: entry.id,
        meta: await aesGcmEncrypt(this.kmeta, utf8Encode(JSON.stringify(meta)), aad("meta", entry.id)),
        secret: await aesGcmEncrypt(
          dek.pw,
          utf8Encode(JSON.stringify({
            password: entry.password,
            notes: entry.notes,
            password_set_at: entry.password_set_at,
            rotate_days: entry.rotate_days,
          })),
          aad("secret", entry.id),
        ),
        totp: entry.totp_secret
          ? await aesGcmEncrypt(
              dek.totp!,
              utf8Encode(JSON.stringify({ totp_secret: entry.totp_secret })),
              aad("totp", entry.id),
            )
          : null,
        passkey: passkeyBlob,
        pending: null,
      };
      hashes[entry.id] = entryHash(obj);
      entryObjects.push(obj);
    }
    for (const raw of this.rawPending) entryObjects.push(raw);
    // Refresh the core's key tables from live state.
    const deksObj: Record<string, { pw: string; totp: string | null; passkey: string | null }> = {};
    for (const [eid, d] of this.deks) {
      deksObj[eid] = { pw: b64encode(d.pw), totp: d.totp ? b64encode(d.totp) : null, passkey: d.passkey ? b64encode(d.passkey) : null };
    }
    this.core.deks = deksObj;
    this.core.entry_hashes = { ...(this.core.entry_hashes ?? {}), ...hashes };
    for (const eid of Object.keys(this.core.entry_hashes)) {
      if (!this.deks.has(eid) && !this.rawPending.some((r) => r.id === eid)) {
        delete this.core.entry_hashes[eid];
      }
    }
    // Passkey hashes: keep pending entries untouched, drop deleted.
    for (const eid of Object.keys(pkHashes)) {
      if (!this.entriesList.some((e) => e.id === eid) && !this.rawPending.some((r) => r.id === eid)) {
        delete pkHashes[eid];
      }
    }
    this.core.passkey_hashes = pkHashes;
    const coreBlob = await aesGcmEncrypt(
      this.vk,
      utf8Encode(JSON.stringify(this.core)),
      aad("core", this.vaultId),
    );
    const file: VaultFile = {
      format: "MKVLT",
      version: 3,
      vault_id: this.vaultId,
      inbox_pub: this.inboxPubB64,
      slots: this.slots,
      verifier: b64encode(hmacSha256(this.vk, utf8Encode(VERIFIER_LABEL))),
      core: coreBlob,
      entries: entryObjects,
      bundles: await this.buildBundles(),
    };
    return utf8Encode(JSON.stringify(file));
  }

  /** Rebuild agent bundles exactly as the Python engine does on
   * every save, so desktop-enrolled agents keep working on files
   * this client has saved. */
  private async buildBundles(): Promise<Record<string, SealedBlob>> {
    const bundles: Record<string, SealedBlob> = {};
    const agents = (this.core.agents ?? {}) as Record<string, any>;
    const now = nowSeconds();
    for (const [agentId, rec] of Object.entries(agents)) {
      if (!rec?.enabled || !rec?.bundle_key) continue;
      if (rec.expires_at && now > Number(rec.expires_at)) continue;
      const scopes: string[] = Array.isArray(rec.scopes) ? rec.scopes : [];
      const targets: Record<string, unknown> = {};
      const services: Record<string, string> = {};
      for (const entry of this.entriesList) {
        if (entry.kind === "passkey") continue; // passkeys are NEVER agent targets
        if (!scopeCoversEntry(scopes, entry)) continue;
        const meta: Record<string, unknown> = {};
        for (const f of METADATA_FIELDS) meta[f] = entry[f];
        targets[entry.id] = { dek_pw: b64encode(this.deks.get(entry.id)!.pw), meta };
        const key = entry.service.toLowerCase();
        if (!(key in services)) services[key] = entry.id;
      }
      const bundle = {
        agent_id: agentId,
        vault_id: this.vaultId,
        scopes,
        expires_at: rec.expires_at ?? null,
        kmeta: scopes.includes("list") ? b64encode(this.kmeta) : null,
        targets,
        services,
        inbox_pub: this.inboxPubB64,
        pending_mac_key: rec.pending_mac_key,
        audit_mac_key: rec.audit_mac_key,
        audit_head: this.core.audit_head ?? "",
        issued_at: now,
      };
      bundles[agentId] = await aesGcmEncrypt(
        b64decode(rec.bundle_key as string),
        utf8Encode(JSON.stringify(bundle)),
        aad("bundle", agentId),
      );
    }
    return bundles;
  }

  // ---------------------------------------------------------------
  // CRUD
  // ---------------------------------------------------------------

  listEntries(): VaultEntry[] {
    return this.entriesList.map((e) => ({ ...e, tags: [...e.tags] }));
  }

  searchEntries(query: string): VaultEntry[] {
    const q = query.toLowerCase();
    return this.listEntries().filter(
      (e) =>
        e.service.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        e.url.toLowerCase().includes(q) ||
        e.notes.toLowerCase().includes(q) ||
        e.tags.some((t) => t.toLowerCase().includes(q)),
    );
  }

  getEntry(id: string): VaultEntry {
    const entry = this.entriesList.find((e) => e.id === id);
    if (!entry) throw new Error(`no entry: ${id}`);
    return { ...entry, tags: [...entry.tags] };
  }

  async addEntry(
    input: Omit<
      VaultEntry,
      "id" | "created" | "updated" | "password_set_at" | "rotate_days" | "kind" | "passkey"
    > & {
      rotate_days?: number | null;
    },
  ): Promise<VaultEntry> {
    if (!input.service) throw new Error("entry service must be non-empty");
    if (
      this.entriesList.some(
        (e) => e.service === input.service && e.username === input.username,
      )
    ) {
      throw new Error(`entry already exists: ${input.service} (${input.username})`);
    }
    const rotateDays = validateRotateDays(input.rotate_days ?? null);
    // Licensing wave: the free tier caps the entry COUNT (never
    // any security feature). Edits are unaffected — only creating
    // a new entry checks for a free slot.
    if (this.entriesList.length >= this.entryLimit()) {
      throw new LicenceRequiredError(
        `Your vault already holds the free version's ${FREE_ENTRY_LIMIT} passwords. ` +
          "Adding more needs a licence — Settings → Enter a licence key. " +
          "Everything already saved keeps working, and deleting a password frees a place.",
      );
    }

    const ts = nowSeconds();
    const entry: VaultEntry = {
      ...input,
      tags: [...input.tags],
      kind: "login",
      passkey: null,
      id: uuidHex(),
      created: ts,
      updated: ts,
      // A new entry's age clock starts now.
      password_set_at: ts,
      rotate_days: rotateDays,
    };
    this.deks.set(entry.id, {
      pw: randomBytes(32),
      totp: entry.totp_secret ? randomBytes(32) : null,
      passkey: null,
    });
    (this.core.origins as Record<string, string>)[entry.id] = "human";
    this.entriesList.push(entry);
    return { ...entry };
  }

  /** Add a passkey record as a new entry. Human-only by construction
   * (this session is a human unlock). Passkeys count toward the
   * entry cap exactly like logins — they are ordinary entries in
   * listEntries(); any licensing cap applied by the app layer on
   * entry count therefore includes them automatically. */
  async addPasskeyRecord(record: PasskeyRecord, notes = ""): Promise<VaultEntry> {
    const rec = validatePasskeyRecord(record);
    if (
      this.entriesList.some(
        (e) => e.service === rec.rp_id && e.username === rec.user_name,
      )
    ) {
      throw new Error(`entry already exists: ${rec.rp_id} (${rec.user_name})`);
    }
    // Also refuse a duplicate credential_id under a different user.
    if (this.entriesList.some((e) => e.passkey?.credential_id === rec.credential_id)) {
      throw new Error("a passkey with this credential id already exists");
    }
    const entry: VaultEntry = {
      id: uuidHex(),
      service: rec.rp_id,
      username: rec.user_name,
      password: "",
      url: "",
      notes,
      totp_secret: "",
      tags: [],
      favourite: false,
      password_set_at: null,
      rotate_days: null,
      kind: "passkey",
      passkey: rec,
      created: rec.created_at,
      updated: rec.created_at,
    };
    this.deks.set(entry.id, {
      pw: randomBytes(32),
      totp: null,
      passkey: randomBytes(32),
    });
    (this.core.origins as Record<string, string>)[entry.id] = "human";
    this.entriesList.push(entry);
    return { ...entry, passkey: entry.passkey ? { ...entry.passkey } : null };
  }

  listPasskeys(): VaultEntry[] {
    return this.listEntries().filter((e) => e.kind === "passkey");
  }

  findPasskeyByCredentialId(credentialIdB64: string): VaultEntry | null {
    const e = this.entriesList.find((x) => x.kind === "passkey" && x.passkey?.credential_id === credentialIdB64);
    return e ? { ...e, tags: [...e.tags], passkey: e.passkey ? { ...e.passkey } : null } : null;
  }

  /** Advance a passkey's sign_count. Forward only — a regression
   * is refused here; clone detection (comparing against a device
   * high-water mark) lives in passkey.ts. Caller persists. */
  updatePasskeySignCount(entryId: string, count: number): void {
    const entry = this.entriesList.find((e) => e.id === entryId);
    if (!entry || entry.kind !== "passkey" || !entry.passkey) throw new Error(`no passkey entry: ${entryId}`);
    if (count < entry.passkey.sign_count) {
      throw new Error("passkey sign_count cannot move backwards");
    }
    entry.passkey.sign_count = count;
    entry.updated = nowSeconds();
  }

  async updateEntry(id: string, fields: Partial<Omit<VaultEntry, "id" | "created">>): Promise<VaultEntry> {
    const entry = this.entriesList.find((e) => e.id === id);
    if (!entry) throw new Error(`no entry: ${id}`);
    if ("rotate_days" in fields) {
      fields = { ...fields, rotate_days: validateRotateDays(fields.rotate_days ?? null) };
    }
    const oldPassword = entry.password;
    const ts = nowSeconds();
    for (const f of ENTRY_FIELDS) {
      if (f in fields) {
        const v = (fields as Record<string, unknown>)[f];
        (entry as unknown as Record<string, unknown>)[f] = f === "tags" ? [...(v as string[])] : v;
      }
    }
    // The age clock resets only when the password itself changes —
    // editing any other field never touches it (Python parity).
    if ("password" in fields && fields.password !== oldPassword) {
      entry.password_set_at = ts;
    }
    entry.updated = ts;
    const dek = this.deks.get(id)!;
    if (entry.totp_secret && dek.totp === null) dek.totp = randomBytes(32);
    if (!entry.totp_secret) dek.totp = null;
    return { ...entry };
  }

  async deleteEntry(id: string): Promise<VaultEntry> {
    const idx = this.entriesList.findIndex((e) => e.id === id);
    if (idx < 0) throw new Error(`no entry: ${id}`);
    const [removed] = this.entriesList.splice(idx, 1);
    this.deks.delete(id);
    delete (this.core.origins as Record<string, string>)[id];
    if (this.core.passkey_hashes) delete (this.core.passkey_hashes as Record<string, string>)[id];
    return { ...removed! };
  }

  // ---------------------------------------------------------------
  // Password age + rotation (settings live in the encrypted core)
  // ---------------------------------------------------------------

  /** The vault-wide default rotation period in days: null/0 = no
   * rotation by default. Cores written before the feature have no
   * settings block — the shipped default applies. */
  vaultSettings(): { default_rotate_days: number | null } {
    const raw = (this.core.settings ?? {}) as Record<string, unknown>;
    if (!("default_rotate_days" in raw)) {
      return { default_rotate_days: DEFAULT_ROTATE_DAYS };
    }
    const value = raw.default_rotate_days;
    return { default_rotate_days: typeof value === "number" ? value : null };
  }

  /** Set the vault-wide default rotation period (days; null or 0
   * = no rotation by default). Per-entry overrides still win. The
   * caller persists afterwards. */
  setDefaultRotateDays(value: number | null): void {
    const days = validateRotateDays(value);
    this.core.settings = { ...((this.core.settings ?? {}) as object), default_rotate_days: days };
  }

  /** Record that this entry's password was changed today — for
   * passwords rotated on the website itself. Only the clock moves;
   * the stored value is untouched. */
  async markPasswordChanged(id: string, at?: number): Promise<VaultEntry> {
    const entry = this.entriesList.find((e) => e.id === id);
    if (!entry) throw new Error(`no entry: ${id}`);
    const ts = at ?? nowSeconds();
    entry.password_set_at = ts;
    entry.updated = ts;
    return { ...entry };
  }

  // ---------------------------------------------------------------
  // Licensing (mirror of the desktop engine's licensing.py)
  // ---------------------------------------------------------------

  setDeviceLicence(payload: LicencePayload | null): void {
    this.deviceLicence = payload;
  }

  private settings(): Record<string, any> {
    const s = (this.core as Record<string, any>).settings;
    return typeof s === "object" && s !== null ? s : {};
  }

  /** The verified licence stored INSIDE this vault, if any. A
   * stored token that no longer verifies is treated as no licence
   * (fail closed), never as an error at open time. */
  licencePayload(): LicencePayload | null {
    const token = this.licenceKey();
    if (!token) return null;
    try {
      return verifyToken(token, this.licencePublicKeyB64);
    } catch {
      return null;
    }
  }

  /** Licensed via the vault's own key, or via the device slot the
   * app layer verified (either copy alone suffices). */
  isLicensed(): boolean {
    return this.deviceLicence !== null || this.licencePayload() !== null;
  }

  entryLimit(): number {
    return this.isLicensed() ? Number.POSITIVE_INFINITY : FREE_ENTRY_LIMIT;
  }

  /** The raw licence token stored in the vault ("" when none). */
  licenceKey(): string {
    const raw = this.settings().licence_key;
    return typeof raw === "string" ? raw : "";
  }

  /** Verify + store a licence key in the vault's encrypted
   * settings (the caller persists). Throws LicenceInvalidError
   * with a plain message when the key doesn't check out, and
   * leaves any existing key untouched in that case. */
  setLicenceKey(tokenText: string): LicencePayload {
    const payload = verifyToken(tokenText, this.licencePublicKeyB64);
    const settings = { ...this.settings(), licence_key: normalizeToken(tokenText) };
    (this.core as Record<string, any>).settings = settings;
    return payload;
  }

  /** Connections in use on THIS vault: active devices + agents +
   * paired browsers (the extension seam). Blob/export pairing
   * targets are destinations, never connections. */
  connectionCount(): number {
    const devices = (this.core.devices ?? {}) as Record<string, any>;
    const activeDevices = Object.values(devices).filter(
      (d) => d && typeof d === "object" && !d.revoked_at,
    ).length;
    const agents = Object.keys((this.core.agents ?? {}) as Record<string, any>).length;
    return activeDevices + agents + this.browserPairingCount();
  }

  /** Paired browsers live in the vault settings; the browser
   * extension client registers pairings there (the seam the
   * desktop engine exposes as register_browser_pairing). */
  browserPairingCount(): number {
    const list = this.settings().browser_pairings;
    return Array.isArray(list) ? list.length : 0;
  }

  connectionLimit(): number {
    const payload = this.licencePayload() ?? this.deviceLicence;
    return payload ? payload.max_connections : FREE_MAX_CONNECTIONS;
  }

  /** Plain-words licence state for Settings / About. */
  licenceStatusLine(): string {
    return licenceStatusLine({
      licensed: this.isLicensed(),
      entries: this.entriesList.length,
      connections: this.connectionCount(),
      connectionLimit: this.connectionLimit(),
    });
  }


  /** Bulk import — mirrors the desktop engine's import_entries /
   * resolve_import exactly: records key on (service, username),
   * case-insensitive; same password is a duplicate (skipped);
   * a different password is a conflict, settled by the policy
   * the user picked: "skip" keeps the vault's entry, "overwrite"
   * replaces it with the file's, "keep_both" adds a second entry.
   * The caller persists afterwards. */
  async importEntries(
    records: ImportRecord[],
    onConflict: ConflictPolicy = "skip",
  ): Promise<ImportStats> {
    const { fresh, duplicates, conflicts } = classifyImport(records, this.entriesList);
    const stats: ImportStats = {
      added: 0,
      duplicates: duplicates.length,
      conflicts: conflicts.length,
      overwritten: 0,
      keptBoth: 0,
      skippedConflicts: 0,
      heldBack: 0,
    };
    // Licensing wave: an unlicensed vault imports only up to the
    // free entry limit. New entries beyond the allowance are held
    // back and counted, so the caller can report exactly how many
    // and why (enter a licence, import the same file again — the
    // ones already in are skipped as duplicates).
    let allowance = this.entryLimit() - this.entriesList.length;
    const register = (rec: ImportRecord): void => {
      const ts = nowSeconds();
      const entry: VaultEntry = {
        ...rec,
        tags: [...rec.tags],
        kind: "login",
        passkey: null,
        id: uuidHex(),
        created: ts,
        updated: ts,
        // Imported records carry no set date in their source —
        // honestly "not recorded", never the import date.
        password_set_at: null,
        rotate_days: null,
      };
      this.deks.set(entry.id, {
        pw: randomBytes(32),
        totp: entry.totp_secret ? randomBytes(32) : null,
        passkey: null,
      });
      (this.core.origins as Record<string, string>)[entry.id] = "human";
      this.entriesList.push(entry);
    };
    for (const rec of fresh) {
      // A fresh key cannot collide with a passkey (classifyImport
      // already keyed it), but guard anyway: never create a login
      // on top of a passkey's (service, username).
      const clash = this.entriesList.find(
        (e) => e.kind === "passkey" && e.service.toLowerCase() === rec.service.toLowerCase() && e.username.toLowerCase() === rec.username.toLowerCase(),
      );
      if (clash) { stats.skippedConflicts++; continue; }
      if (allowance <= 0) {
        stats.heldBack++;
        continue;
      }
      allowance--;
      register(rec);
      stats.added++;
    }
    for (const rec of conflicts) {
      const existing = this.entriesList.find(
        (e) =>
          e.service.toLowerCase() === rec.service.toLowerCase() &&
          e.username.toLowerCase() === rec.username.toLowerCase(),
      );
      // A passkey entry is NEVER overwritten or merged into by CSV import.
      if (existing?.kind === "passkey") {
        stats.skippedConflicts++;
        continue;
      }
      if (onConflict === "overwrite") {
        if (existing) {
          await this.updateEntry(existing.id, { ...rec });
          // Import overwrite: the replacement password's age is
          // unknown — "not recorded", never the old entry's date
          // and never a pretend "set today" (Python parity).
          existing.password_set_at = null;
          stats.overwritten++;
        } else {
          stats.skippedConflicts++;
        }
      } else if (onConflict === "keep_both") {
        if (allowance <= 0) {
          stats.heldBack++;
        } else {
          allowance--;
          register(rec);
          stats.keptBoth++;
        }
      } else {
        stats.skippedConflicts++;
      }
    }
    return stats;
  }

  // ---------------------------------------------------------------
  // Device + pairing registries (blob wave). Records live in the
  // encrypted core, mirroring the desktop registries; mutations
  // mark the vault dirty so the app layer persists them. The
  // session is the human's unlocked session by construction.
  // ---------------------------------------------------------------

  /** Deep copy of the device registry (core "devices"). */
  devicesRegistry(): Record<string, any> {
    return JSON.parse(JSON.stringify(this.core.devices ?? {}));
  }

  /** Deep copy of the pairing registry (core "pairings"). Vaults
   *  created before the blob wave have no "pairings" field — it
   *  reads as empty and is added on the first enrollment. */
  pairingsRegistry(): Record<string, any> {
    return JSON.parse(JSON.stringify(this.core.pairings ?? {}));
  }

  /** The vault's backup recovery recipient public key, raw bytes,
   *  or null when no recovery phrase is set up. */
  backupRecoveryPub(): Uint8Array | null {
    const raw = this.core.backup_recovery_pub;
    return typeof raw === "string" && raw ? b64decode(raw) : null;
  }

  putDeviceRecord(record: Record<string, any>): void {
    if (!this.core.devices) this.core.devices = {};
    this.core.devices[record.device_id] = record;
    this.markDirty();
  }

  putPairingRecord(record: Record<string, any>): void {
    if (!this.core.pairings) this.core.pairings = {};
    this.core.pairings[record.target_id] = record;
    this.markDirty();
  }

  // ---------------------------------------------------------------
  // Recovery + master + wrapped slots
  // ---------------------------------------------------------------

  hasRecovery(): boolean {
    return this.slots.some((s) => s.id === "recovery");
  }

  /** Create/replace the recovery slot. Returns the phrase (shown once). */
  async setupRecovery(): Promise<string> {
    const phrase = newRecoveryPhrase();
    await this.setRecoveryPhrase(phrase);
    return phrase;
  }

  async setRecoveryPhrase(phrase: string): Promise<void> {
    const normalized = normalizePhrase(phrase);
    const salt = randomBytes(16);
    const wrapping = await deriveRecoveryKey(normalized, salt);
    const blob = await aesGcmEncrypt(wrapping, this.vk, utf8Encode("slot:recovery"));
    const slot: Slot = {
      id: "recovery",
      algo: "argon2id",
      salt: b64encode(salt),
      nonce: blob.nonce,
      ciphertext: blob.ciphertext,
      ...ARGON_DEFAULTS,
    };
    this.slots = [...this.slots.filter((s) => s.id !== "recovery"), slot];
    const pub = await recoveryBackupPublic(normalized, this.vaultId);
    this.core.backup_recovery_pub = b64encode(pub);
  }

  async changeMaster(newPassword: string): Promise<void> {
    if (newPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
      throw new Error(
        `master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters`,
      );
    }
    const slot = await this.buildMasterSlot(newPassword);
    this.slots = [...this.slots.filter((s) => s.id !== "master"), slot];
  }

  hasSlot(slotId: string): boolean {
    return this.slots.some((s) => s.id === slotId);
  }

  /** Add/replace an opaque wrapped slot (e.g. Android device slot). */
  async addWrappedSlot(slotId: string, wrapKey: Uint8Array): Promise<void> {
    const blob = await aesGcmEncrypt(wrapKey, this.vk, utf8Encode(`slot:${slotId}`));
    const slot: Slot = {
      id: slotId,
      algo: "raw-wrap-v1",
      salt: "",
      nonce: blob.nonce,
      ciphertext: blob.ciphertext,
    };
    this.slots = [...this.slots.filter((s) => s.id !== slotId), slot];
  }

  removeSlot(slotId: string): void {
    this.slots = this.slots.filter((s) => s.id !== slotId);
  }

  /** Set when unlock-time maintenance changed core state (e.g. the
   * backup recovery backfill); the app layer re-saves the vault when
   * needsPersist() is true so the change lands on disk. */
  private pendingPersist = false;
  private markDirty(): void {
    this.pendingPersist = true;
  }
  needsPersist(): boolean {
    return this.pendingPersist;
  }

  lock(): void {
    this.vk.fill(0);
    this.kmeta.fill(0);
    for (const d of this.deks.values()) {
      d.pw.fill(0);
      d.totp?.fill(0);
      d.passkey?.fill(0);
    }
    this.deks.clear();
    this.entriesList = [];
    this.rawPending = [];
  }
}

const PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

function randomIndex(max: number): number {
  const limit = Math.floor(256 / max) * max;
  const b = new Uint8Array(1);
  do {
    crypto.getRandomValues(b);
  } while (b[0]! >= limit);
  return b[0]! % max;
}

/** Password generator with the Python engine's alphabet and minimum. */
export function generatePassword(length = 20): string {
  if (length < MIN_GENERATED_PASSWORD_LENGTH) {
    throw new Error(
      `generated passwords must be at least ${MIN_GENERATED_PASSWORD_LENGTH} characters`,
    );
  }
  const alphabet =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + PUNCTUATION;
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[randomIndex(alphabet.length)];
  return out;
}
