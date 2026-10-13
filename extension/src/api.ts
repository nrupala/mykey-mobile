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

import type { WebExtApi } from "./webext.js";

/** The API object for whichever browser we run in: Firefox exposes
 * `browser`, Chromium exposes `chrome`; the calls used here behave
 * identically (promises) in both. */
export function extApi(): WebExtApi {
  const g = globalThis as { browser?: WebExtApi; chrome?: WebExtApi };
  if (typeof g.browser !== "undefined" && g.browser) return g.browser;
  return g.chrome as WebExtApi;
}
