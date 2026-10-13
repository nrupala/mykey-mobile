// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// One-call test world: FakeApi + FakeHost + BackgroundCore wired
// together with a paired identity and a pinned host key.

import { BackgroundCore } from "../../src/background.js";
import { keyFingerprint } from "../../src/channel.js";
import type { ClipboardDeps } from "../../src/clipboard.js";
import { loadOrCreateIdentity, pinHostPayload } from "../../src/keys.js";
import { b64encode } from "../../../src/vault/encoding.js";
import { FakeApi } from "./fakeapi.js";
import { FakeHost } from "./fakehost.js";

export interface FakeClipboard extends ClipboardDeps {
  current: string;
  writes: string[];
  alarms: number[];
}

export function makeFakeClipboard(session: FakeApi["session"]): FakeClipboard {
  const clip: FakeClipboard = {
    current: "",
    writes: [],
    alarms: [],
    writeText: async (text) => {
      clip.current = text;
      clip.writes.push(text);
    },
    readText: async () => clip.current,
    session,
    setAlarm: (when) => clip.alarms.push(when),
    now: () => Date.now(),
  };
  return clip;
}

export interface World {
  api: FakeApi;
  host: FakeHost;
  core: BackgroundCore;
  clipboard: FakeClipboard;
}

export async function makeWorld(): Promise<World> {
  const api = new FakeApi();
  const host = new FakeHost();
  await loadOrCreateIdentity(api.storage.local);
  await pinHostPayload(api.storage.local, {
    format: "MKHOST",
    version: 1,
    x25519_pub: b64encode(host.hostPub),
    fingerprint: keyFingerprint(host.hostPub),
  });
  const clipboard = makeFakeClipboard(api.session);
  const core = new BackgroundCore({
    api,
    clipboardDeps: clipboard,
    createTransport: (extApi) => host.transportFor(extApi.runtime.id),
  });
  return { api, host, core, clipboard };
}
