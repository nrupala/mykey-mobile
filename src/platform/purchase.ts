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

/** The purchase seam (licensing wave).
 *
 * Google Play policy: an app distributed through Play must not
 * link out to a web checkout for a digital unlock — the unlock is
 * sold through Play Billing. So the Android build's Buy action
 * NEVER opens the website checkout. Today (pre-Play, direct APK)
 * it explains, in plain words, that the licence is bought on the
 * website from another device and pasted in here. When the Play
 * listing exists, Play Billing plugs into buyLicence() at exactly
 * this seam; the licence-key paste path already works in every
 * build and stays.
 *
 * The web/PWA build has no such restriction: Buy and Tip jar open
 * the brand-configured pages on usemykey.com. */

import { BRAND } from "../brand.js";
import { isNativeApp } from "./biometric.js";

export function buyLicence(statusEl: HTMLElement): void {
  if (isNativeApp()) {
    statusEl.textContent =
      `Licences are bought on our website — open ${BRAND.domain} in a browser ` +
      "on any device, buy there, then come back and tap \u201CEnter a licence key\u201D " +
      "to paste your key. (Buying inside the app arrives when MyKey is listed on Google Play.)";
    return;
  }
  window.open(BRAND.licenceBuyUrl, "_blank", "noopener");
}

export function tipJar(statusEl: HTMLElement): void {
  if (isNativeApp()) {
    statusEl.textContent =
      `Thank you! Tips live on our website too — open ${BRAND.domain} in a browser ` +
      "on any device. A tip is a thank-you only; it never unlocks anything, and nothing is held back without one.";
    return;
  }
  window.open(BRAND.tipUrl, "_blank", "noopener");
}
