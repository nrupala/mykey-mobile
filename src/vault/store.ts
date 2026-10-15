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

/** Local storage. Vault material stored here is the encrypted
 * Vault v3 file bytes themselves (IndexedDB). No plaintext vault
 * data, no passwords — and nothing in localStorage. The blob wave
 * adds two identity items, both stated plainly: this device's
 * MKDEVKEYS identity JSON and pairing-target key JSON (private keys
 * in local app storage, the desktop's 0600-file discipline carried
 * to the web sandbox — local storage protection, not an OS
 * keystore claim). */

import {
  CLIPBOARD_CLEAR_DEFAULT_SECONDS,
  clampClipboardClearSeconds,
} from "../platform/clipboard.js";
import {
  defaultMirrorBook,
  defaultMirrorConfig,
  type MirrorBook,
  type MirrorConfig,
} from "./homecopy.js";

const DB_NAME = "mykey-web";
const STORE = "kv";

export interface AppSettings {
  autoLockMinutes: number; // 0 = never (not recommended)
  lockOnHide: boolean;
  clipboardClearSeconds: number;
  deviceSlotEnabled: boolean;
}

export const DEFAULT_SETTINGS: AppSettings = {
  autoLockMinutes: 5,
  lockOnHide: true,
  // Leakage rule: 1 minute by default; the bounds live in
  // platform/clipboard.ts and nowhere else.
  clipboardClearSeconds: CLIPBOARD_CLEAR_DEFAULT_SECONDS,
  deviceSlotEnabled: false,
};

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  try {
    return await new Promise<T | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(key);
      req.onsuccess = () => resolve(req.result as T | undefined);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

async function idbSet(key: string, value: unknown): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

async function idbDelete(key: string): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export const store = {
  getVaultBytes: () => idbGet<Uint8Array>("vault"),
  setVaultBytes: (bytes: Uint8Array) => idbSet("vault", bytes),
  clearVault: () => idbDelete("vault"),
  getLastBackupAt: () => idbGet<number>("lastBackupAt"),
  setLastBackupAt: (ts: number) => idbSet("lastBackupAt", ts),
  clearLastBackupAt: () => idbDelete("lastBackupAt"),
  async getSettings(): Promise<AppSettings> {
    const raw = await idbGet<Partial<AppSettings>>("settings");
    const merged = { ...DEFAULT_SETTINGS, ...(raw ?? {}) };
    // Single validation point: any stored delay (including values
    // saved before the 60–300s bounds existed) is clamped on load.
    merged.clipboardClearSeconds = clampClipboardClearSeconds(
      merged.clipboardClearSeconds,
    );
    return merged;
  },
  setSettings: (s: AppSettings) => idbSet("settings", s),
  // Passkey clone detection: device-local sign_count high-water
  // marks (credential_id -> highest count seen on THIS device).
  // Counts only — no key material, no record contents.
  getPasskeyHighWater: () => idbGet<Record<string, number>>("passkeyHighWater"),
  setPasskeyHighWater: (hw: Record<string, number>) => idbSet("passkeyHighWater", hw),
  getSyncDirHandle: () => idbGet<FileSystemDirectoryHandle>("syncDirHandle"),
  setSyncDirHandle: (h: FileSystemDirectoryHandle) => idbSet("syncDirHandle", h),
  clearSyncDirHandle: () => idbDelete("syncDirHandle"),
  // Blob wave: this client's device identity (MKDEVKEYS JSON) and
  // the pairing target this device's sync folder is tied to.
  getDeviceIdentity: () => idbGet<string>("deviceIdentity"),
  setDeviceIdentity: (json: string) => idbSet("deviceIdentity", json),
  clearDeviceIdentity: () => idbDelete("deviceIdentity"),
  getSyncTargetId: () => idbGet<string>("syncTargetId"),
  setSyncTargetId: (id: string) => idbSet("syncTargetId", id),
  clearSyncTargetId: () => idbDelete("syncTargetId"),
  // Pairing-target key files (MKPAIRKEYS JSON) for targets set up
  // on this device, keyed by target id.
  getPairingTargetKeys: () => idbGet<Record<string, string>>("pairingTargetKeys"),
  async setPairingTargetKeys(id: string, json: string): Promise<void> {
    const all = (await idbGet<Record<string, string>>("pairingTargetKeys")) ?? {};
    all[id] = json;
    await idbSet("pairingTargetKeys", all);
  },
  async deletePairingTargetKeys(id: string): Promise<void> {
    const all = (await idbGet<Record<string, string>>("pairingTargetKeys")) ?? {};
    delete all[id];
    await idbSet("pairingTargetKeys", all);
  },
  /** Device-local licence slot (licensing wave). The stored value
   * is the signed licence token itself — signed, not secret, so
   * it is safe to keep here; it lets a NEW vault created on this
   * device start licensed, mirroring the desktop device slot. */
  getLicenceKey: () => idbGet<string>("licence"),
  setLicenceKey: (token: string) => idbSet("licence", token),
  clearLicenceKey: () => idbDelete("licence"),
  // Vault home (homecopy wave): the user's home-folder choice and
  // the reconciliation bookkeeping. Digests and timestamps only —
  // the folder grant itself lives on the native side, and no
  // vault content is ever stored here beyond the vault bytes
  // under "vault" above.
  async getMirrorConfig(): Promise<MirrorConfig> {
    const raw = await idbGet<Partial<MirrorConfig>>("mirrorConfig");
    return { ...defaultMirrorConfig(), ...(raw ?? {}) };
  },
  setMirrorConfig: (c: MirrorConfig) => idbSet("mirrorConfig", c),
  clearMirrorConfig: () => idbDelete("mirrorConfig"),
  async getMirrorBook(): Promise<MirrorBook> {
    const raw = await idbGet<Partial<MirrorBook>>("mirrorBook");
    return { ...defaultMirrorBook(), ...(raw ?? {}) };
  },
  setMirrorBook: (b: MirrorBook) => idbSet("mirrorBook", b),
  clearMirrorBook: () => idbDelete("mirrorBook"),

};
