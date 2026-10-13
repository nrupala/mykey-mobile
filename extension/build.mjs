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

/** Build the store-ready extension packages:
 *   dist/chromium/ + dist/mykey-extension-chromium.zip
 *   dist/firefox/  + dist/mykey-extension-firefox.zip
 * One TypeScript source, two manifests. Bundles are single files
 * (content scripts cannot be ES modules; the service worker and
 * pages use module bundles). */

import { build } from "esbuild";
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");

const common = {
  bundle: true,
  platform: "browser",
  target: "es2022",
  sourcemap: false,
  logLevel: "info",
};

async function bundleAll(outdir, { offscreen }) {
  await build({
    ...common,
    entryPoints: [join(root, "src/background-entry.ts")],
    outfile: join(outdir, "background.js"),
    format: "esm",
  });
  await build({
    ...common,
    entryPoints: [join(root, "src/content-entry.ts")],
    outfile: join(outdir, "content.js"),
    format: "iife",
  });
  await build({
    ...common,
    entryPoints: [join(root, "src/popup.ts"), join(root, "src/options.ts")],
    outdir,
    format: "esm",
  });
  if (offscreen) {
    await build({
      ...common,
      entryPoints: [join(root, "src/offscreen.ts")],
      outfile: join(outdir, "offscreen.js"),
      format: "esm",
    });
  }
}

function assemble(browser, { offscreen }) {
  const outdir = join(dist, browser);
  mkdirSync(outdir, { recursive: true });
  cpSync(join(root, "src/popup.html"), join(outdir, "popup.html"));
  cpSync(join(root, "src/options.html"), join(outdir, "options.html"));
  cpSync(join(root, "src/styles.css"), join(outdir, "styles.css"));
  if (offscreen) {
    cpSync(join(root, "src/offscreen.html"), join(outdir, "offscreen.html"));
  }
  cpSync(join(root, "icons"), join(outdir, "icons"), { recursive: true });
  cpSync(
    join(root, `manifest.${browser}.json`),
    join(outdir, "manifest.json"),
  );
  return outdir;
}

function zip(outdir, zipName) {
  const zipPath = join(dist, zipName);
  rmSync(zipPath, { force: true });
  execFileSync("zip", ["-r", "-q", zipPath, "."], { cwd: outdir });
  return zipPath;
}

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

for (const [browser, opts] of [
  ["chromium", { offscreen: true }],
  ["firefox", { offscreen: false }],
]) {
  const outdir = assemble(browser, opts);
  await bundleAll(outdir, opts);
  const zipPath = zip(outdir, `mykey-extension-${browser}.zip`);
  console.log(`built ${zipPath}`);
}
