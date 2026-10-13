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

/** In-app Help + About data (owner directive, 2026-10-13).

 * The help text is NOT written here. The canonical text lives in
 * the desktop repo as HELP.md / FAQ.md; src/content/ carries a
 * byte-for-byte mirror, and CI fails if the two drift (see the
 * "Help text matches" step in .github/workflows/pwa.yml). The
 * text renders fully offline — it ships inside the app bundle. */

import { BRAND } from "../brand.js";
import helpMarkdown from "../content/HELP.md?raw";
import faqMarkdown from "../content/FAQ.md?raw";

export const HELP_MARKDOWN: string = helpMarkdown;
export const FAQ_MARKDOWN: string = faqMarkdown;

export interface AboutInfo {
  productName: string;
  tagline: string;
  version: string;
  vaultFormat: string;
  vendor: string;
  domain: string;
  supportEmail: string;
  ownerName: string;
  ownerUrl: string;
  builderName: string;
  builderUrl: string;
  referralCode: string;
  referralLine: string;
  licenceSummary: string;
  termsPointer: string;
  whatsNewPointer: string;
}

export function aboutInfo(): AboutInfo {
  return {
    productName: BRAND.productName,
    tagline: BRAND.tagline,
    version: __APP_VERSION__,
    vaultFormat: "Vault v3",
    vendor: BRAND.vendor,
    domain: BRAND.domain,
    supportEmail: BRAND.supportEmail,
    ownerName: "Nrupal Akolkar",
    ownerUrl: "https://nrupalakolkar.com",
    builderName: "Muse by Meta",
    builderUrl: "https://muse.ai/join",
    referralCode: "101EEK",
    referralLine:
      "join Muse, then redeem code 101EEK in Settings within 48 hours " +
      "of joining and we both earn tokens.",
    licenceSummary:
      "The MyKey core is proprietary software of 2351485 ALBERTA INC.; " +
      "the interface layer is Apache 2.0.",
    termsPointer: "The full terms are in TERMS, in the app and the repo.",
    whatsNewPointer:
      "What is in this version: see CHANGELOG where you got the app.",
  };
}

/** Licence / tip-jar block for the About screen.
 *
 * The free-tier ruling landed with the licensing wave (client
 * 1.3.0), so the slot carries the plain-words summary. The caller
 * passes the open vault's live status line when there is one
 * (About is also reachable from the locked screen, where only
 * the standing summary shows). Buying and key entry themselves
 * live in Settings — About informs, Settings acts. */
export function licenceSlotLines(statusLine?: string): string[] {
  const lines = [
    "Free version: up to 50 passwords and 4 connections (devices, " +
      "agents and paired browsers in one shared pool). A one-time " +
      "licence unlocks unlimited passwords and 20 connections. Only " +
      "the counts are limited — every security feature is free, and " +
      "a vault already over the limit still opens and works fully.",
    "To buy a licence or paste a licence key, open Settings. " +
      "The tip jar is there too — tips are thanks only and unlock nothing.",
  ];
  return statusLine ? [statusLine, ...lines] : lines;
}
