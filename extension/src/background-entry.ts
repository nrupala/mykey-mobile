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

/** Background entry: wires BackgroundCore to the real extension
 * runtime. All logic lives in background.ts (injectable, tested);
 * this file only translates runtime messages. */

import { extApi } from "./api.js";
import { BackgroundCore } from "./background.js";
import { CLIPBOARD_ALARM, type ClipboardDeps } from "./clipboard.js";
import type { ExtTab } from "./webext.js";

const api = extApi();

function backgroundClipboardDeps(): ClipboardDeps | undefined {
  // Firefox event pages have a DOM and can honour the clipboard
  // rule directly. Chromium service workers cannot — the alarm
  // handler delegates to the offscreen document there.
  if (typeof navigator === "undefined" || !navigator.clipboard) {
    return undefined;
  }
  return {
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
}

const core = new BackgroundCore({
  api,
  clipboardDeps: backgroundClipboardDeps(),
});

async function activeTab(): Promise<ExtTab> {
  const tabs = await api.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab) throw new Error("no active tab");
  return tab;
}

type Handler = (
  message: Record<string, unknown>,
  senderTabId?: number,
) => Promise<unknown>;

const handlers: Record<string, Handler> = {
  "mk-status": async () => core.status(),
  "mk-connect": async () => {
    await core.connect();
    return core.status();
  },
  "mk-unlock": async (m) => {
    const res = await core.unlock(String(m.password ?? ""));
    return { ...res, ...(await core.status()) };
  },
  "mk-lock": async () => {
    await core.lock();
    return core.status();
  },
  "mk-arm-active-tab": async () => {
    const tab = await activeTab();
    if (tab.id !== undefined) await core.armTab(tab.id);
    return { armed: true };
  },
  "mk-matches": async () => core.matches(await activeTab()),
  "mk-fill": async (m) => {
    const tab = await activeTab();
    return core.fill(tab, String(m.entryId ?? ""));
  },
  "mk-totp": async (m) => {
    const tab = await activeTab();
    return core.totp(tab, String(m.entryId ?? ""));
  },
  "mk-copy": async (m) => {
    const tab = await activeTab();
    return core.copyCredentials(tab, String(m.entryId ?? ""));
  },
  "mk-set-subdomains": async (m) => {
    const tab = await activeTab();
    return core.setSubdomains(
      tab,
      String(m.entryId ?? ""),
      Boolean(m.value),
    );
  },
  "mk-generate": async (m) => ({
    password: core.generate(Number(m.length ?? 20)),
  }),
  "mk-pending-save-action": async (m) =>
    core.pendingSaveAction(Boolean(m.accepted)),
  "mk-save-choice": async (m) =>
    core.saveChoice(String(m.token ?? ""), Boolean(m.accepted)),
  "mk-captured": async (m, senderTabId?: number) => {
    if (senderTabId !== undefined) {
      await core.onCaptured(senderTabId, {
        origin: String(m.origin ?? ""),
        username: String(m.username ?? ""),
        password: String(m.password ?? ""),
      });
    }
    return { received: true };
  },
};

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const record = message as Record<string, unknown>;
  const handler = handlers[String(record.type ?? "")];
  if (!handler) return false;
  handler(record, sender.tab?.id)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((err: unknown) =>
      sendResponse({
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        code:
          err instanceof Error && "code" in err
            ? String((err as { code: unknown }).code)
            : undefined,
      }),
    );
  return true; // async response
});

api.tabs.onUpdated.addListener((tabId, changeInfo) => {
  void core.onTabUpdated(tabId, changeInfo.status);
});

api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === CLIPBOARD_ALARM) {
    void core.onClipboardAlarm();
  }
});
