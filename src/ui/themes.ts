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

/** Skin system: every colour in the client comes from a theme's
 * token set — components never hard-code a colour. A theme is a
 * complete, coherent palette plus a five-step strength-meter ramp.
 *
 * Design intent (also written up in docs/DESIGN.md): blue and teal
 * hues carry the primary actions because they read as calm and
 * trustworthy; surfaces stay low-saturation so the app feels quiet;
 * warm amber appears only for caution; red is reserved for real
 * danger; dark skins are deep blue/indigo rather than pure black so
 * text does not smear at night. The Chakra skin uses the
 * seven-chakra spectrum (root red through crown violet) for its
 * meter ramp and highlights. These are design choices about mood
 * and legibility — the app makes no medical or healing claims.
 *
 * Accessibility is a build gate, not a hope: tests/themes.test.ts
 * computes WCAG contrast for every text and component token pair in
 * every skin and fails the build on any violation. */

export interface ThemeTokens {
  paper: string;
  surface: string;
  ink: string;
  muted: string;
  brand: string;
  brandInk: string;
  brandSoft: string;
  accent: string;
  caution: string;
  danger: string;
  dangerSoft: string;
  dangerSoftInk: string;
  infoSoft: string;
  infoSoftInk: string;
  line: string;
  focus: string;
}

export interface ThemeDef {
  id: string;
  /** Plain name shown in the picker. */
  name: string;
  /** One plain line describing the feel. */
  blurb: string;
  scheme: "light" | "dark";
  tokens: ThemeTokens;
  /** Strength-meter segment colours, weakest → strongest. */
  meter: [string, string, string, string, string];
}

const LIGHT_METER: [string, string, string, string, string] = [
  "#c62828", "#e07b00", "#c9a100", "#5f9e2f", "#0a6b2d",
];
const DARK_METER: [string, string, string, string, string] = [
  "#ff7a72", "#ffa040", "#ffd83d", "#8fd14f", "#4ade80",
];

export const THEMES: Record<string, ThemeDef> = {
  daylight: {
    id: "daylight",
    name: "Daylight",
    blurb: "Bright and clear, like a well-lit desk.",
    scheme: "light",
    tokens: {
      paper: "#ffffff", surface: "#f4f8fa", ink: "#10222e", muted: "#41586b",
      brand: "#0b3d5c", brandInk: "#ffffff", brandSoft: "#e3eff6",
      accent: "#0a6b2d", caution: "#8a5a00", danger: "#a01717",
      dangerSoft: "#fdecec", dangerSoftInk: "#5f0d0d",
      infoSoft: "#e9f3fa", infoSoftInk: "#0d3049",
      line: "#6e8b9c", focus: "#c07f10",
    },
    meter: LIGHT_METER,
  },
  midnight: {
    id: "midnight",
    name: "Midnight",
    blurb: "Deep blue-dark, easy on the eyes at night.",
    scheme: "dark",
    tokens: {
      paper: "#0c141d", surface: "#14222f", ink: "#e9f1f6", muted: "#a7bccb",
      brand: "#58a6cf", brandInk: "#071a26", brandSoft: "#17364a",
      accent: "#4cc38a", caution: "#f0b43c", danger: "#ff9d97",
      dangerSoft: "#3a1d1d", dangerSoftInk: "#ffb4ab",
      infoSoft: "#12303f", infoSoftInk: "#bfe3f5",
      line: "#5b7d92", focus: "#f5c15c",
    },
    meter: DARK_METER,
  },
  ocean: {
    id: "ocean",
    name: "Ocean",
    blurb: "Deep blue and teal — calm water, steady trust.",
    scheme: "dark",
    tokens: {
      paper: "#04222e", surface: "#07303f", ink: "#e8f4f2", muted: "#a3c6bf",
      brand: "#2fa8a0", brandInk: "#03222b", brandSoft: "#0b3d47",
      accent: "#4ade80", caution: "#f2b33d", danger: "#ff9d94",
      dangerSoft: "#40201d", dangerSoftInk: "#ffc9c2",
      infoSoft: "#0a3644", infoSoftInk: "#bfe9f2",
      line: "#5b8b9a", focus: "#ffd166",
    },
    meter: DARK_METER,
  },
  forest: {
    id: "forest",
    name: "Forest",
    blurb: "Soft green light, quiet as trees.",
    scheme: "light",
    tokens: {
      paper: "#f7faf4", surface: "#eef5e9", ink: "#14231a", muted: "#40584a",
      brand: "#1d5c38", brandInk: "#ffffff", brandSoft: "#dcefe0",
      accent: "#177245", caution: "#8a5a00", danger: "#a01717",
      dangerSoft: "#fdecec", dangerSoftInk: "#5f0d0d",
      infoSoft: "#e6f2e4", infoSoftInk: "#173d24",
      line: "#6f8f74", focus: "#b06a00",
    },
    meter: LIGHT_METER,
  },
  dune: {
    id: "dune",
    name: "Dune",
    blurb: "Warm sand and amber, soft on the eyes.",
    scheme: "light",
    tokens: {
      paper: "#fbf6ec", surface: "#f5ecd9", ink: "#2b2118", muted: "#6b5844",
      brand: "#845007", brandInk: "#ffffff", brandSoft: "#f3e3c2",
      accent: "#0a6b2d", caution: "#96590a", danger: "#9e1b1b",
      dangerSoft: "#fbe9e4", dangerSoftInk: "#5f0d0d",
      infoSoft: "#f0e7d3", infoSoftInk: "#4a3517",
      line: "#94805f", focus: "#b97c0f",
    },
    meter: LIGHT_METER,
  },
  chakra: {
    id: "chakra",
    name: "Chakra",
    blurb: "Deep indigo with the seven-chakra spectrum as its accent.",
    scheme: "dark",
    tokens: {
      paper: "#16102e", surface: "#1f1842", ink: "#f0edff", muted: "#bcb2e6",
      brand: "#9d8cff", brandInk: "#1b1040", brandSoft: "#2c2360",
      accent: "#4ade80", caution: "#ffb020", danger: "#ff7a72",
      dangerSoft: "#3a1e2e", dangerSoftInk: "#ffb3c1",
      infoSoft: "#241b52", infoSoftInk: "#d6ccff",
      line: "#6f61ad", focus: "#ffd83d",
    },
    // Root red → sacral orange → solar yellow → heart green →
    // crown violet: the spectrum, weakest to strongest.
    meter: ["#ef5350", "#ff9800", "#fdd835", "#66bb6a", "#ab7be8"],
  },
  contrast: {
    id: "contrast",
    name: "High Contrast",
    blurb: "Black on white, the sharpest text we can offer.",
    scheme: "light",
    tokens: {
      paper: "#ffffff", surface: "#ffffff", ink: "#000000", muted: "#2b2b2b",
      brand: "#0033cc", brandInk: "#ffffff", brandSoft: "#dbe4ff",
      accent: "#00640d", caution: "#7a4d00", danger: "#b00000",
      dangerSoft: "#ffe1e1", dangerSoftInk: "#660000",
      infoSoft: "#dbeafe", infoSoftInk: "#00215e",
      line: "#000000", focus: "#000000",
    },
    meter: LIGHT_METER,
  },
};

/** Picker order. "device" is the automatic choice, listed first. */
export const THEME_ORDER = [
  "daylight", "midnight", "ocean", "forest", "dune", "chakra", "contrast",
] as const;

/** The "device" choice follows the operating system: Daylight in
 * light mode, Midnight in dark mode. */
export const DEVICE_LIGHT = "daylight";
export const DEVICE_DARK = "midnight";

/** The seven-chakra spectrum, root → crown, used for the Chakra
 * skin's picker swatch band (its meter ramp uses five of these). */
export const CHAKRA_SPECTRUM = [
  "#ef5350", "#ff9800", "#fdd835", "#66bb6a",
  "#42a5f5", "#3949ab", "#ab7be8",
] as const;

/** A stored choice: "device" (follow the OS) or a theme id. */
export type ThemeChoice = "device" | string;

export function isThemeChoice(value: unknown): value is ThemeChoice {
  return value === "device" ||
    (typeof value === "string" && value in THEMES);
}

export function resolveTheme(choice: ThemeChoice, osDark: boolean): ThemeDef {
  if (choice === "device") {
    return THEMES[osDark ? DEVICE_DARK : DEVICE_LIGHT]!;
  }
  return THEMES[choice] ?? THEMES[DEVICE_LIGHT]!;
}

// ------------------------------------------------------------------
// Colour math — the accessibility gate lives here so the tests use
// exactly the code the palette was tuned with.
// ------------------------------------------------------------------

export function relativeLuminance(hex: string): number {
  const h = hex.replace("#", "");
  const channel = (i: number) => {
    const c = parseInt(h.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4);
}

export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  const hi = Math.max(la, lb);
  const lo = Math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}

/** Token pairs that must read as body text (WCAG AA: 4.5:1). */
export const TEXT_CONTRAST_PAIRS: ReadonlyArray<
  readonly [keyof ThemeTokens, keyof ThemeTokens]
> = [
  ["ink", "paper"], ["ink", "surface"], ["ink", "brandSoft"],
  ["muted", "paper"], ["muted", "surface"], ["muted", "brandSoft"],
  ["brand", "paper"], ["brand", "surface"],
  ["brandInk", "brand"],
  ["accent", "paper"], ["accent", "surface"],
  ["caution", "paper"], ["caution", "surface"],
  ["danger", "paper"], ["danger", "surface"],
  ["dangerSoftInk", "dangerSoft"],
  ["infoSoftInk", "infoSoft"],
];

/** Token pairs that are component boundaries / focus indicators
 * (WCAG non-text contrast: 3:1). */
export const UI_CONTRAST_PAIRS: ReadonlyArray<
  readonly [keyof ThemeTokens, keyof ThemeTokens]
> = [
  ["focus", "paper"], ["focus", "surface"],
  ["line", "paper"], ["line", "surface"],
  ["brand", "paper"],
];
