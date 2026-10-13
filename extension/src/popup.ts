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

/** Popup: one obvious next action per state — pair, connect,
 * unlock, or pick the login to fill. All secret text is rendered
 * with textContent, and copied secrets go through the clipboard
 * rule (copySecretWithClear) with the desktop's chosen delay. */

import { extApi } from "./api.js";
import {
  CLIPBOARD_ALARM,
  copySecretWithClear,
  type ClipboardDeps,
} from "./clipboard.js";
import type { MatchMeta } from "./background.js";

const api = extApi();

interface StatusResult {
  paired: boolean;
  connected: boolean;
  unlocked: boolean;
  scopes: string[];
  clipboardSeconds: number;
  pendingSave: { origin: string; username: string; mode: "new" | "update" } | null;
}

interface Envelope {
  ok: boolean;
  result?: unknown;
  error?: string;
  code?: string;
}

async function call(type: string, fields: Record<string, unknown> = {}): Promise<never> {
  const envelope = (await api.runtime.sendMessage({ type, ...fields })) as Envelope;
  if (!envelope?.ok) {
    throw new Error(envelope?.error ?? "the extension hit a problem");
  }
  return envelope.result as never;
}

const $ = <T extends HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const statusLine = $("status-line");
let clipboardSeconds = 60;

function say(text: string, isError = false): void {
  statusLine.textContent = text;
  statusLine.classList.toggle("error", isError);
}

function show(id: string, visible: boolean): void {
  $(id).hidden = !visible;
}

const popupClipboard: ClipboardDeps = {
  writeText: (text) => navigator.clipboard.writeText(text),
  readText: async () => {
    try {
      return await navigator.clipboard.readText();
    } catch {
      return null;
    }
  },
  session: api.storage.session,
  setAlarm: (when) => api.alarms.create(CLIPBOARD_ALARM, { when }),
  now: () => Date.now(),
};

async function copySecret(text: string): Promise<void> {
  await copySecretWithClear(popupClipboard, text, clipboardSeconds);
  say(`Copied — it clears itself in ${clipboardSeconds} seconds.`);
}

async function refresh(): Promise<void> {
  let status: StatusResult;
  try {
    status = await call("mk-status");
    if (status.paired && !status.connected) {
      // First open after the browser starts always begins
      // disconnected — that is normal, not a failure. Try the
      // (local, instant) connect before showing the "could not
      // reach the desktop" panel; that panel is only for a
      // connect that actually failed.
      try {
        status = await call("mk-connect");
      } catch {
        status = await call("mk-status");
      }
    }
  } catch (err) {
    say(err instanceof Error ? err.message : String(err), true);
    return;
  }
  clipboardSeconds = status.clipboardSeconds;
  show("unpaired", !status.paired);
  show("connect", status.paired && !status.connected);
  show("unlock", status.paired && status.connected && !status.unlocked);
  show("lock-btn", status.unlocked);
  const ready = status.paired && status.connected && status.unlocked;
  show("matches", ready);
  show("generate", ready);

  const pending = status.pendingSave;
  show("pending-save", Boolean(pending));
  if (pending) {
    $("pending-save-text").textContent =
      pending.mode === "new"
        ? `Save the login for ${pending.username} on ${pending.origin}?`
        : `Update the saved password for ${pending.username} on ${pending.origin}?`;
  }
  if (ready) {
    await call("mk-arm-active-tab").catch(() => undefined);
    await loadMatches();
  }
}

async function loadMatches(): Promise<void> {
  try {
    const { origin, matches } = (await call("mk-matches")) as {
      origin: string | null;
      matches: MatchMeta[];
    };
    const list = $("match-list");
    list.replaceChildren();
    $("no-matches").hidden = matches.length > 0;
    if (origin) {
      $("matches-heading").textContent = `On this site (${origin})`;
    }
    for (const match of matches) {
      list.append(matchItem(match));
    }
  } catch (err) {
    say(err instanceof Error ? err.message : String(err), true);
  }
}

function matchItem(match: MatchMeta): HTMLLIElement {
  const li = document.createElement("li");
  li.className = "match";
  const who = document.createElement("span");
  who.className = "who";
  who.textContent = `${match.service} — ${match.username}`;
  const actions = document.createElement("div");
  actions.className = "actions";

  const fill = document.createElement("button");
  fill.textContent = "Fill";
  fill.addEventListener("click", async () => {
    try {
      await call("mk-fill", { entryId: match.id });
      window.close();
    } catch (err) {
      say(err instanceof Error ? err.message : String(err), true);
    }
  });
  actions.append(fill);

  if (match.has_totp) {
    const code = document.createElement("button");
    code.className = "small ghost";
    code.textContent = "Fill code";
    code.addEventListener("click", async () => {
      try {
        const res = (await call("mk-totp", { entryId: match.id })) as {
          code: string;
          filled: boolean;
        };
        if (res.filled) {
          window.close();
        } else {
          await copySecret(res.code);
        }
      } catch (err) {
        say(err instanceof Error ? err.message : String(err), true);
      }
    });
    actions.append(code);
  }

  const copy = document.createElement("button");
  copy.className = "small ghost";
  copy.textContent = "Copy password";
  copy.addEventListener("click", async () => {
    try {
      const creds = (await call("mk-copy", { entryId: match.id })) as {
        username: string;
        password: string;
      };
      await copySecret(creds.password);
    } catch (err) {
      say(err instanceof Error ? err.message : String(err), true);
    }
  });
  actions.append(copy);

  const subLabel = document.createElement("label");
  subLabel.className = "sub";
  const subBox = document.createElement("input");
  subBox.type = "checkbox";
  subBox.checked = match.fill_subdomains;
  subBox.addEventListener("change", async () => {
    try {
      await call("mk-set-subdomains", {
        entryId: match.id,
        value: subBox.checked,
      });
      say(
        subBox.checked
          ? "This login may now fill on subdomains of its site."
          : "This login now fills only on its exact site.",
      );
    } catch (err) {
      subBox.checked = !subBox.checked;
      say(err instanceof Error ? err.message : String(err), true);
    }
  });
  subLabel.append(subBox, document.createTextNode(" Also fill on subdomains"));
  li.append(who, actions, subLabel);
  return li;
}

$("open-options").addEventListener("click", () => {
  void api.runtime.openOptionsPage();
});

$("connect-btn").addEventListener("click", async () => {
  try {
    await call("mk-connect");
    say("");
  } catch (err) {
    say(err instanceof Error ? err.message : String(err), true);
  }
  await refresh();
});

$("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const master = $("master") as unknown as HTMLInputElement;
  try {
    await call("mk-unlock", { password: master.value });
    master.value = "";
    say("Unlocked. Your logins for this site are below.");
  } catch (err) {
    say(err instanceof Error ? err.message : String(err), true);
  }
  await refresh();
});

$("lock-btn").addEventListener("click", async () => {
  await call("mk-lock").catch(() => undefined);
  window.close();
});

$("pending-save-yes").addEventListener("click", async () => {
  try {
    const res = (await call("mk-pending-save-action", { accepted: true })) as {
      saved: boolean;
    };
    say(res.saved ? "Saved to MyKey." : "Nothing was saved.");
  } catch (err) {
    say(err instanceof Error ? err.message : String(err), true);
  }
  await refresh();
});

$("pending-save-no").addEventListener("click", async () => {
  await call("mk-pending-save-action", { accepted: false }).catch(
    () => undefined,
  );
  await refresh();
});

$("gen-btn").addEventListener("click", async () => {
  const length = Number(
    ($("gen-length") as unknown as HTMLInputElement).value || 20,
  );
  try {
    const res = (await call("mk-generate", { length })) as {
      password: string;
    };
    $("gen-output").textContent = res.password;
    $("gen-copy").hidden = false;
    $("gen-copy").dataset.secret = res.password;
  } catch (err) {
    say(err instanceof Error ? err.message : String(err), true);
  }
});

$("gen-copy").addEventListener("click", async () => {
  const secret = $("gen-copy").dataset.secret;
  if (secret) await copySecret(secret);
});

void refresh();
