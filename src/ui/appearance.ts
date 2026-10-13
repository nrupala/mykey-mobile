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

/** Appearance: which skin the user picked, applied to the page.
 *
 * The choice is a non-secret UI preference, so it lives in
 * localStorage — that also lets main.ts apply it synchronously,
 * before first paint, so the app never flashes the wrong colours.
 * Nothing secret ever touches this module.
 *
 * Default behaviour is "device": the app follows the operating
 * system's light/dark setting and reacts live when it changes.
 * Picking a skin overrides the device until the user picks
 * "Use device settings" again. */

import {
  isThemeChoice,
  resolveTheme,
  type ThemeChoice,
  type ThemeDef,
} from "./themes.js";

const STORAGE_KEY = "mykey.appearance.theme";

let current: ThemeChoice = "device";
let media: MediaQueryList | null = null;
let listening = false;

export function loadThemeChoice(): ThemeChoice {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (isThemeChoice(raw)) current = raw;
  } catch {
    /* storage unavailable (private mode etc.) — fall back to device */
  }
  return current;
}

export function saveThemeChoice(choice: ThemeChoice): void {
  current = choice;
  try {
    window.localStorage.setItem(STORAGE_KEY, choice);
  } catch {
    /* preference lasts for this session only */
  }
}

export function currentThemeChoice(): ThemeChoice {
  return current;
}

function osPrefersDark(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

const TOKEN_VARS: ReadonlyArray<readonly [keyof ThemeDef["tokens"], string]> = [
  ["paper", "--paper"], ["surface", "--surface"], ["ink", "--ink"],
  ["muted", "--muted"], ["brand", "--brand"], ["brandInk", "--brand-ink"],
  ["brandSoft", "--brand-soft"], ["accent", "--accent"],
  ["caution", "--caution"], ["danger", "--danger"],
  ["dangerSoft", "--danger-soft"], ["dangerSoftInk", "--danger-soft-ink"],
  ["infoSoft", "--info-soft"], ["infoSoftInk", "--info-soft-ink"],
  ["line", "--line"], ["focus", "--focus"],
];

/** Apply a theme definition to the document root as CSS variables. */
export function paintTheme(def: ThemeDef, choice: ThemeChoice): void {
  const root = document.documentElement;
  for (const [key, cssVar] of TOKEN_VARS) {
    root.style.setProperty(cssVar, def.tokens[key]);
  }
  def.meter.forEach((colour, i) => {
    root.style.setProperty(`--meter-${i + 1}`, colour);
  });
  root.style.setProperty("color-scheme", def.scheme);
  root.dataset.theme = def.id;
  root.dataset.themeChoice = choice;
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", def.tokens.brand);
}

/** Resolve and paint the active choice; in "device" mode this also
 * keeps a live listener on the OS setting. */
export function applyTheme(choice: ThemeChoice): void {
  current = choice;
  paintTheme(resolveTheme(choice, osPrefersDark()), choice);
  if (!listening && typeof window !== "undefined" &&
      typeof window.matchMedia === "function") {
    media = window.matchMedia("(prefers-color-scheme: dark)");
    media.addEventListener("change", () => {
      if (current === "device") {
        paintTheme(resolveTheme("device", osPrefersDark()), "device");
      }
    });
    listening = true;
  }
}

/** Pick a skin: persist + paint immediately (the picker previews
 * live because the settings screen itself restyles). */
export function chooseTheme(choice: ThemeChoice): void {
  saveThemeChoice(choice);
  applyTheme(choice);
}
