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

/** Page-origin helpers. The DESKTOP host is the matching authority;
 * these functions only compute the origin string the extension
 * reports (and use it to bind a fill to the tab it was matched on).
 * The string form mirrors native_host.parse_origin: scheme://host
 * with the port present only when it is not the scheme's default. */

const DEFAULT_PORTS: Record<string, number> = { https: 443, http: 80 };

export function originOfUrl(urlString: string): string | null {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return null;
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  if (!(scheme in DEFAULT_PORTS)) return null;
  if (url.username || url.password) return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return null;
  const port = url.port ? Number(url.port) : DEFAULT_PORTS[scheme];
  if (!Number.isInteger(port) || port === undefined) return null;
  return port === DEFAULT_PORTS[scheme]
    ? `${scheme}://${host}`
    : `${scheme}://${host}:${port}`;
}

export function isWebUrl(urlString: string): boolean {
  return originOfUrl(urlString) !== null;
}
