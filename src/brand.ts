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

/** Brand strings — the ONLY place brand identity lives in the web
 * client, mirroring brand.py in the desktop engine. Rename the
 * product here (and in the package/brand files that consume it)
 * without touching the vault core: the engine is brand-neutral. */

export const BRAND = {
  productName: "MyKey",
  tagline: "Zero-Trust Password Manager",
  domain: "usemykey.com",
  supportEmail: "info@aimlds.org",
  appId: "com.usemykey.mykey",
  vendor: "2351485 ALBERTA INC.",
  attribution: "Owned by Nrupal Akolkar · Built with Muse by Meta",
} as const;

export const VAULT_FILENAME = "vault.mykey";
export const DEVICE_SLOT_ID = "pwa-device";
