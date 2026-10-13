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

/** Options page: the pairing ceremony, in plain words. Shows this
 * browser's pairing payload + fingerprint for the desktop step,
 * and pins the desktop host's key after verifying its fingerprint
 * against the key itself. */

import { extApi } from "./api.js";
import {
  loadOrCreateIdentity,
  pairingPayload,
  pinHostPayload,
  pinnedHost,
  resetIdentity,
} from "./keys.js";

const api = extApi();
const LABEL_KEY = "mkext.label";

const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;

async function render(): Promise<void> {
  const identity = await loadOrCreateIdentity(api.storage.local);
  const stored = await api.storage.local.get([LABEL_KEY]);
  const label =
    typeof stored[LABEL_KEY] === "string" ? (stored[LABEL_KEY] as string) : "";
  ($("ext-label") as unknown as HTMLInputElement).value = label;
  $("ext-fingerprint").textContent = identity.fingerprint;
  const payload = pairingPayload(api.runtime.id, identity, label);
  ($("payload") as unknown as HTMLTextAreaElement).value = JSON.stringify(
    payload,
    null,
    1,
  );
  const host = await pinnedHost(api.storage.local);
  $("host-state").textContent = host
    ? `Desktop host pinned. Its fingerprint: ${host.fingerprint} — it must match what "mykey ext-host-payload" shows on the desktop.`
    : "No desktop host pinned yet.";
}

$("ext-label").addEventListener("change", async () => {
  const label = ($("ext-label") as unknown as HTMLInputElement).value;
  await api.storage.local.set({ [LABEL_KEY]: label });
  await render();
});

$("copy-payload").addEventListener("click", async () => {
  const area = $("payload") as unknown as HTMLTextAreaElement;
  await navigator.clipboard.writeText(area.value);
});

/** The desktop prints the host payload as JSON followed by a
 * human hint line ("Host fingerprint ..."), and users paste the
 * whole thing. Extract the first balanced JSON object instead of
 * failing on the trailing words. */
function extractJsonObject(text: string): string {
  const clean = text.replace(/^\uFEFF/, "");
  const start = clean.indexOf("{");
  if (start < 0) throw new Error("no payload found — paste the host payload");
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < clean.length; i += 1) {
    const ch = clean[i] as string;
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
    } else if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return clean.slice(start, i + 1);
    }
  }
  throw new Error("the pasted payload looks incomplete");
}

$("pin-host").addEventListener("click", async () => {
  const raw = ($("host-payload") as unknown as HTMLTextAreaElement).value;
  try {
    const parsed: unknown = JSON.parse(extractJsonObject(raw));
    const { fingerprint } = await pinHostPayload(api.storage.local, parsed);
    $("host-state").textContent =
      `Pinned. Host fingerprint: ${fingerprint}. ` +
      "Now approve the pairing on the desktop (step 1) if you have not yet.";
    ($("host-payload") as unknown as HTMLTextAreaElement).value = "";
  } catch (err) {
    $("host-state").textContent =
      err instanceof Error ? err.message : String(err);
    $("host-state").classList.add("error");
  }
  await render();
});

$("reset-identity").addEventListener("click", async () => {
  if (
    !window.confirm(
      "Reset this browser's pairing identity? Existing pairings for the old key stop working, and the desktop pairing must be done again.",
    )
  ) {
    return;
  }
  await resetIdentity(api.storage.local);
  await loadOrCreateIdentity(api.storage.local);
  await render();
});

void render();
