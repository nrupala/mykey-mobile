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

/** Minimal ambient WebExtension API surface — ONLY the APIs this
 * extension calls. Declaring them by hand (instead of pulling a
 * catch-all types package) keeps the extension's true capability
 * surface visible in one file for review. Both Chrome MV3 and
 * Firefox MV3 expose these; `browser` is the Firefox namespace,
 * `chrome` the Chromium one, with identical promise behaviour for
 * the calls used here. */

export interface ExtPort {
  name: string;
  postMessage(message: unknown): void;
  disconnect(): void;
  onMessage: { addListener(cb: (message: unknown) => void): void };
  onDisconnect: { addListener(cb: () => void): void };
}

export interface ExtTab {
  id?: number;
  url?: string;
  active?: boolean;
  windowId?: number;
}

export interface StorageArea {
  get(keys?: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
  clear(): Promise<void>;
}

export interface WebExtApi {
  runtime: {
    id: string;
    lastError?: { message?: string };
    connectNative(application: string): ExtPort;
    getURL(path: string): string;
    onMessage: {
      addListener(
        cb: (
          message: unknown,
          sender: { tab?: ExtTab; frameId?: number },
          sendResponse: (response?: unknown) => void,
        ) => boolean | void,
      ): void;
    };
    sendMessage(message: unknown): Promise<unknown>;
    openOptionsPage(): Promise<void>;
  };
  storage: {
    local: StorageArea;
    session: StorageArea;
  };
  tabs: {
    query(query: { active?: boolean; currentWindow?: boolean }): Promise<ExtTab[]>;
    onUpdated: {
      addListener(
        cb: (tabId: number, changeInfo: { status?: string }, tab: ExtTab) => void,
      ): void;
    };
  };
  scripting: {
    executeScript(injection: {
      target: { tabId: number; frameIds?: number[] };
      files?: string[];
      func?: (...args: never[]) => unknown;
      args?: unknown[];
      world?: "ISOLATED" | "MAIN";
    }): Promise<Array<{ result?: unknown }>>;
  };
  action: {
    setBadgeText(details: { text: string; tabId?: number }): Promise<void>;
    setBadgeBackgroundColor(details: { color: string }): Promise<void>;
  };
  alarms: {
    create(name: string, info: { when?: number; delayInMinutes?: number }): void;
    onAlarm: { addListener(cb: (alarm: { name: string }) => void): void };
  };
  offscreen?: {
    createDocument(details: {
      url: string;
      reasons: string[];
      justification: string;
    }): Promise<void>;
    closeDocument(): Promise<void>;
    hasDocument(): Promise<boolean>;
    Reason: { CLIPBOARD: string };
  };
}

declare global {
  const chrome: WebExtApi;
  const browser: WebExtApi | undefined;
}
