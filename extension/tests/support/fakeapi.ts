// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// An in-memory WebExtension API double for tests. Storage areas are
// plain maps the tests can dump (leak gate 4/5 grep them).
// executeScript records every call (leak gate 3 asserts frameIds)
// and runs injected funcs against the test's jsdom window.

import type {
  ExtPort,
  StorageArea,
  WebExtApi,
} from "../../src/webext.js";

export class FakeStorageArea implements StorageArea {
  data = new Map<string, unknown>();

  async get(keys?: string | string[] | null): Promise<Record<string, unknown>> {
    if (keys == null) return Object.fromEntries(this.data);
    const list = Array.isArray(keys) ? keys : [keys];
    const out: Record<string, unknown> = {};
    for (const key of list) {
      if (this.data.has(key)) out[key] = this.data.get(key);
    }
    return out;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    for (const [k, v] of Object.entries(items)) this.data.set(k, v);
  }

  async remove(keys: string | string[]): Promise<void> {
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      this.data.delete(key);
    }
  }

  async clear(): Promise<void> {
    this.data.clear();
  }

  dump(): string {
    return JSON.stringify(Object.fromEntries(this.data));
  }
}

export interface ScriptCall {
  target: { tabId: number; frameIds?: number[] };
  files?: string[];
  hasFunc: boolean;
  args?: unknown[];
}

export class FakeApi implements WebExtApi {
  local = new FakeStorageArea();
  session = new FakeStorageArea();
  storage = { local: this.local, session: this.session };
  messageLog: unknown[] = [];
  onSendMessage: ((message: unknown) => Promise<unknown>) | undefined;
  runtime = {
    id: "abcdefghijklmnopabcdefghijklmnop",
    lastError: undefined,
    connectNative: (_name: string): ExtPort => {
      throw new Error("tests inject transports directly");
    },
    sendMessage: async (message: unknown): Promise<unknown> => {
      this.messageLog.push(message);
      if (this.onSendMessage) return this.onSendMessage(message);
      return {};
    },
    onMessage: { addListener: (_cb: never) => undefined },
    openOptionsPage: async () => undefined,
    getURL: (path: string) => `chrome-extension://fake/${path}`,
  };
  tabsState = {
    active: { id: 7, url: "https://github.com/login" },
  };
  tabs = {
    query: async (_q: { active?: boolean; currentWindow?: boolean }) => [
      { ...this.tabsState.active },
    ],
    onUpdated: { addListener: (_cb: never) => undefined },
  };
  scriptCalls: ScriptCall[] = [];
  createdDocuments: { reasons: string[] }[] = [];
  scripting = {
    executeScript: async (injection: {
      target: { tabId: number; frameIds?: number[] };
      files?: string[];
      func?: (...args: never[]) => unknown;
      args?: unknown[];
    }): Promise<{ result?: unknown }[]> => {
      this.scriptCalls.push({
        target: injection.target,
        files: injection.files,
        hasFunc: Boolean(injection.func),
        args: injection.args,
      });
      if (injection.func) {
        const result = (injection.func as (...a: unknown[]) => unknown)(
          ...(injection.args ?? []),
        );
        return [{ result }];
      }
      return [{}];
    },
  };
  alarmsState = new Map<string, number>();
  alarms = {
    create: (name: string, info: { when?: number; delayInMinutes?: number }) => {
      this.alarmsState.set(name, info.when ?? Date.now());
    },
    onAlarm: { addListener: (_cb: never) => undefined },
  };
  action = {
    setBadgeText: async (_d: { text: string; tabId?: number }) => undefined,
    setBadgeBackgroundColor: async (_d: { color: string }) => undefined,
  };
  offscreen = {
    hasDocument: async () => this.createdDocuments.length > 0,
    createDocument: async (opts: {
      url: string;
      reasons: string[];
      justification: string;
    }) => {
      this.createdDocuments.push({ reasons: opts.reasons });
    },
    closeDocument: async () => {
      this.createdDocuments.pop();
    },
    Reason: { CLIPBOARD: "CLIPBOARD" },
  };
}
