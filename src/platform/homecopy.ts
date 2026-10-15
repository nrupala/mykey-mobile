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

/** Android bridge for the vault's home (see src/vault/homecopy.ts
 * for the model). The native VaultMirror plugin wraps the Storage
 * Access Framework: the user picks a folder once, the grant is
 * persisted by Android, and the plugin reads/writes
 * MyKey/vault.mykey under it. Only encrypted vault bytes ever
 * cross this bridge — the same ciphertext the app stores inside
 * itself.
 *
 * Web/PWA: there is no adapter. Browser storage rules give a web
 * page no durable user-chosen folder for this (the sync folder is
 * a separate, per-session grant), so the home copy is an
 * Android-app feature and the web UI never offers it. */

import { Capacitor, registerPlugin } from "@capacitor/core";
import { isNativeApp } from "./biometric.js";
import { b64decode, b64encode } from "../vault/encoding.js";
import type { HomeCopyAdapter, HomeFolderInfo } from "../vault/homecopy.js";

interface VaultMirrorPlugin {
  pickFolder(): Promise<{ cancelled?: boolean; folderName?: string }>;
  folderInfo(): Promise<{
    configured: boolean;
    folderName: string | null;
    hasFile: boolean;
    modifiedAt: number | null;
    size: number | null;
  }>;
  readVaultFile(): Promise<{ data: string }>;
  writeVaultFile(opts: { data: string }): Promise<{ modifiedAt: number }>;
  writePreservedFile(opts: { data: string; name: string }): Promise<void>;
  forgetFolder(): Promise<void>;
}

const plugin = registerPlugin<VaultMirrorPlugin>("VaultMirror");

export function homeCopyAvailable(): boolean {
  return (
    isNativeApp() &&
    Capacitor.getPlatform() === "android" &&
    Capacitor.isPluginAvailable("VaultMirror")
  );
}

class NativeHomeCopyAdapter implements HomeCopyAdapter {
  async pickFolder(): Promise<{ folderName: string } | null> {
    const res = await plugin.pickFolder();
    if (res.cancelled || !res.folderName) return null;
    return { folderName: res.folderName };
  }

  async folderInfo(): Promise<HomeFolderInfo | null> {
    const info = await plugin.folderInfo();
    if (!info.configured) return null;
    return {
      folderName: info.folderName ?? "your folder",
      hasFile: info.hasFile,
      modifiedAt: info.modifiedAt,
      size: info.size,
    };
  }

  async readHomeFile(): Promise<Uint8Array | null> {
    try {
      const { data } = await plugin.readVaultFile();
      return b64decode(data);
    } catch {
      return null;
    }
  }

  async writeHomeFile(bytes: Uint8Array): Promise<void> {
    await plugin.writeVaultFile({ data: b64encode(bytes) });
  }

  async writePreservedFile(bytes: Uint8Array, name: string): Promise<void> {
    await plugin.writePreservedFile({ data: b64encode(bytes), name });
  }

  async forgetFolder(): Promise<void> {
    await plugin.forgetFolder();
  }
}

let cached: HomeCopyAdapter | null | undefined;

/** The adapter for this runtime, or null where the home copy
 * cannot exist (web). Constructed once. */
export function getHomeCopyAdapter(): HomeCopyAdapter | null {
  if (cached === undefined) {
    cached = homeCopyAvailable() ? new NativeHomeCopyAdapter() : null;
  }
  return cached;
}
