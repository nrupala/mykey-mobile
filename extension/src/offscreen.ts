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

/** Offscreen document (Chromium only): exists for exactly one job —
 * running the clipboard clear pass, which a service worker cannot
 * do (no DOM, no clipboard). It uses the classic execCommand path on
 * a scratch textarea, the documented offscreen clipboard pattern.
 * Firefox has no offscreen API; its background page runs the same
 * pass directly.
 */

import { extApi } from "./api.js";
import {
  CLIPBOARD_ALARM,
  runClipboardClear,
  type ClipboardDeps,
} from "./clipboard.js";

const api = extApi();

function scratchArea(): HTMLTextAreaElement {
  let area = document.querySelector("textarea");
  if (!area) {
    area = document.createElement("textarea");
    document.body.append(area);
  }
  return area;
}

const deps: ClipboardDeps = {
  writeText: async (text) => {
    const area = scratchArea();
    area.value = text;
    area.select();
    document.execCommand("copy");
  },
  readText: async () => {
    const area = scratchArea();
    area.value = "";
    area.select();
    if (!document.execCommand("paste")) return null;
    return area.value;
  },
  session: api.storage.session,
  setAlarm: (when) => api.alarms.create(CLIPBOARD_ALARM, { when }),
  now: () => Date.now(),
};

api.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const record = message as Record<string, unknown>;
  if (record.type === "mk-clipboard-clear-pass") {
    runClipboardClear(deps)
      .then((outcome) => sendResponse({ ok: true, outcome }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
  return false;
});
