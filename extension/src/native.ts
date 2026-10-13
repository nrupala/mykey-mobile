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

import { NATIVE_HOST_NAME, type FrameTransport } from "./channel.js";
import type { ExtPort, WebExtApi } from "./webext.js";

/** FrameTransport over a browser native-messaging port. The browser
 * itself frames the pipe (length-prefixed); this wrapper only moves
 * JSON objects. */
export class NativeTransport implements FrameTransport {
  private port: ExtPort;
  private frameCbs: Array<(frame: Record<string, unknown>) => void> = [];
  private closeCbs: Array<() => void> = [];

  constructor(api: WebExtApi) {
    this.port = api.runtime.connectNative(NATIVE_HOST_NAME);
    this.port.onMessage.addListener((message) => {
      const frame = message as Record<string, unknown>;
      for (const cb of this.frameCbs) cb(frame);
    });
    this.port.onDisconnect.addListener(() => {
      for (const cb of this.closeCbs) cb();
    });
  }

  post(frame: Record<string, unknown>): void {
    this.port.postMessage(frame);
  }

  onFrame(cb: (frame: Record<string, unknown>) => void): void {
    this.frameCbs.push(cb);
  }

  onClose(cb: () => void): void {
    this.closeCbs.push(cb);
  }

  close(): void {
    try {
      this.port.disconnect();
    } catch {
      /* already gone */
    }
  }
}
