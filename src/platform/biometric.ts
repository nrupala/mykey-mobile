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

/** Biometric device unlock — Android app only.
 *
 * Security model (see docs/FEATURE_MATRIX.md): the vault gains one
 * extra unlock slot ("pwa-device") whose wrapping key is a random
 * 32-byte value generated on the device. That wrap key — never the
 * vault key, never a password — is stored through the biometric
 * plugin's secure credentials, which on Android sit under an
 * Android Keystore key guarded by BiometricPrompt with
 * BIOMETRY_ANY access control: every read requires a fresh
 * biometric (or device credential) authentication. The wrap key
 * unwraps the slot to the vault key via the vault's own
 * cryptographic unlock path; biometrics never touch plaintext and
 * disabling this feature deletes the slot and the stored key.
 *
 * The pure web PWA does NOT offer this: a wrap key kept in web
 * storage would be readable by any script that runs, which would
 * quietly turn it into a plaintext-equivalent backdoor.
 */

import { Capacitor } from "@capacitor/core";
import { AccessControl, NativeBiometric } from "@capgo/capacitor-native-biometric";
import { BRAND, DEVICE_SLOT_ID } from "../brand.js";

/** The plugin keys secure credentials by server; one credential per
 * server, so the device slot gets its own server string. */
const CREDENTIAL_SERVER = `${BRAND.appId}.device-slot`;

export function isNativeApp(): boolean {
  return Capacitor.isNativePlatform();
}

export async function biometricAvailable(): Promise<boolean> {
  if (!isNativeApp()) return false;
  try {
    const r = await NativeBiometric.isAvailable({ useFallback: true });
    return r.isAvailable;
  } catch {
    return false;
  }
}

export async function storeDeviceWrapKey(wrapKeyBase64: string): Promise<void> {
  await NativeBiometric.setCredentials({
    server: CREDENTIAL_SERVER,
    username: DEVICE_SLOT_ID,
    password: wrapKeyBase64,
    accessControl: AccessControl.BIOMETRY_ANY,
  });
}

/** Returns the wrap key after a biometric prompt, or null when the
 * user cancels / no credential is stored. Reading the credential is
 * itself the biometric gate: the Keystore key is created with
 * per-use authentication, so the plugin raises BiometricPrompt. */
export async function fetchDeviceWrapKey(): Promise<string | null> {
  if (!isNativeApp()) return null;
  try {
    const creds = await NativeBiometric.getSecureCredentials({
      server: CREDENTIAL_SERVER,
    });
    return creds?.password ?? null;
  } catch {
    return null;
  }
}

export async function removeDeviceWrapKey(): Promise<void> {
  try {
    await NativeBiometric.deleteCredentials({
      server: CREDENTIAL_SERVER,
    });
  } catch {
    /* already gone */
  }
}
