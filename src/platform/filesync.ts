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

/** File flows, honest about what each platform can really do:
 *
 * - Sync folder: the File System Access API (desktop Chromium)
 *   lets the user pick a folder — e.g. inside their own cloud
 *   drive's local folder — and the app reads/writes "vault.mykey"
 *   there. The handle is user-granted and revocable; permission is
 *   re-checked on every use. The Android app has no directory
 *   picker (the WebView does not provide one), so there sync is
 *   the explicit file flow: save the vault file into your cloud
 *   app, open the newer file on the other device. The app labels
 *   each platform's flow in plain words and never pretends.
 *   There is no background sync and no server: the vault file is
 *   ciphertext everywhere it goes, matching the desktop's
 *   zero-knowledge sync design.
 * - Export on the Android app writes the file to the app cache and
 *   opens the system share sheet; on the web it downloads.
 */

import { Capacitor } from "@capacitor/core";
import { Directory, Filesystem } from "@capacitor/filesystem";
import { Share } from "@capacitor/share";
import { VAULT_FILENAME } from "../brand.js";
import { b64encode, utf8Decode } from "../vault/encoding.js";

/** What this runtime can actually do, detected — never assumed.
 *
 * Folder sync needs the File System Access directory picker. That
 * API exists in desktop Chromium browsers; the Android WebView
 * that hosts the Capacitor app does not provide it (checked here
 * at runtime, and the native platform is excluded regardless, so
 * the app can never offer a folder it cannot write to). Where
 * folder sync is unavailable the honest flow is explicit file
 * save/open through the system share sheet and file pickers. */
export interface FileAccessCaps {
  native: boolean;
  directoryPicker: boolean;
}

export function detectFileAccessCaps(): FileAccessCaps {
  return {
    native: Capacitor.isNativePlatform(),
    directoryPicker:
      typeof window !== "undefined" &&
      typeof (window as any).showDirectoryPicker === "function",
  };
}

/** Pure decision, unit-tested: folder sync is offered only where
 * the directory picker genuinely exists, and never in the app. */
export function folderSyncOffered(caps: FileAccessCaps): boolean {
  return !caps.native && caps.directoryPicker;
}

export function syncFolderSupported(): boolean {
  return folderSyncOffered(detectFileAccessCaps());
}

export async function chooseSyncFolder(): Promise<FileSystemDirectoryHandle | null> {
  try {
    return await (window as any).showDirectoryPicker({ id: "mykey-sync" });
  } catch {
    return null; // user cancelled
  }
}

async function ensurePermission(
  handle: FileSystemDirectoryHandle,
  mode: "read" | "readwrite",
): Promise<boolean> {
  const anyHandle = handle as any;
  if (typeof anyHandle.queryPermission !== "function") return true;
  const opts = { mode };
  if ((await anyHandle.queryPermission(opts)) === "granted") return true;
  return (await anyHandle.requestPermission(opts)) === "granted";
}

export async function syncFolderPush(
  handle: FileSystemDirectoryHandle,
  bytes: Uint8Array,
): Promise<boolean> {
  if (!(await ensurePermission(handle, "readwrite"))) return false;
  const fileHandle = await handle.getFileHandle(VAULT_FILENAME, { create: true });
  const writable = await (fileHandle as any).createWritable();
  await writable.write(bytes as BufferSource);
  await writable.close();
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const snap = await handle.getFileHandle(`vault-backup-${stamp}.mykey`, { create: true });
  const snapWritable = await (snap as any).createWritable();
  await snapWritable.write(bytes as BufferSource);
  await snapWritable.close();
  return true;
}

export async function syncFolderPull(
  handle: FileSystemDirectoryHandle,
): Promise<Uint8Array | null> {
  if (!(await ensurePermission(handle, "read"))) return null;
  try {
    const fileHandle = await handle.getFileHandle(VAULT_FILENAME);
    const file = await fileHandle.getFile();
    return new Uint8Array(await file.arrayBuffer());
  } catch {
    return null; // no vault file in the folder yet
  }
}

/** Save bytes somewhere the user controls: share sheet on native,
 * download on web. Returns false when the user cancels the share. */
export async function exportFile(
  filename: string,
  bytes: Uint8Array,
  mime = "application/octet-stream",
): Promise<boolean> {
  if (Capacitor.isNativePlatform()) {
    const written = await Filesystem.writeFile({
      path: filename,
      directory: Directory.Cache,
      data: b64encode(bytes),
    });
    try {
      await Share.share({
        title: filename,
        text: "MyKey encrypted vault file — it is useless without your master password.",
        files: [written.uri],
        dialogTitle: "Save your vault file",
      });
      return true;
    } catch {
      return false;
    }
  }
  const blob = new Blob([bytes as BlobPart], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
  return true;
}

/** Read a file the user picks (any platform). */
export function pickFile(
  accept = ".mykey,.mykeybak,application/json",
): Promise<{ name: string; bytes: Uint8Array } | null> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = accept;
    input.addEventListener("change", async () => {
      const file = input.files?.[0];
      if (!file) return resolve(null);
      resolve({ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
    });
    input.addEventListener("cancel", () => resolve(null));
    input.click();
  });
}

export function looksLikeJson(bytes: Uint8Array): boolean {
  try {
    JSON.parse(utf8Decode(bytes));
    return true;
  } catch {
    return false;
  }
}
