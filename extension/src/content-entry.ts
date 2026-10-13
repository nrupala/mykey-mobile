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

/** Content-script entry: installed into a page ONLY by an explicit
 * injection from the background (activeTab + scripting — this file
 * is never declared as a static content script). Installing arms
 * the save-capture watcher for this page: injection itself is the
 * user's act (they opened the popup or pressed Fill on this tab),
 * and the watcher still only REPORTS a candidate — the human
 * clicks Save before anything is stored. */

import { extApi } from "./api.js";
import {
  armCapture,
  dismissSavePrompt,
  fillCredentials,
  fillTotp,
  showSavePrompt,
  type SavePromptSpec,
} from "./content.js";

export interface MkContentApi {
  fill: (username: string, password: string) => { username: boolean; password: boolean };
  fillTotp: (code: string) => boolean;
  showSavePrompt: (token: string, spec: SavePromptSpec) => void;
  dismissSavePrompt: () => void;
}

declare global {
  interface Window {
    __mkContent?: MkContentApi;
  }
}

const api = extApi();

if (!window.__mkContent) {
  window.__mkContent = {
    fill: (username, password) => fillCredentials(document, username, password),
    fillTotp: (code) => fillTotp(document, code),
    showSavePrompt: (token, spec) =>
      showSavePrompt(document, spec, (accepted) => {
        void api.runtime.sendMessage({
          type: "mk-save-choice",
          token,
          accepted,
        });
      }),
    dismissSavePrompt: () => dismissSavePrompt(document),
  };
  armCapture(window, (captured) => {
    void api.runtime.sendMessage({ type: "mk-captured", ...captured });
  });
}
