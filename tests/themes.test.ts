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

// THE ACCESSIBILITY GATE for the skin system. Every skin —
// including both halves of the automatic "device" choice — must
// pass WCAG AA contrast for every text pair (4.5:1) and component
// pair (3:1) the stylesheet actually renders. A failure here fails
// CI: no skin ships below the line, ever.

import { describe, expect, it } from "vitest";
import {
  DEVICE_DARK,
  DEVICE_LIGHT,
  TEXT_CONTRAST_PAIRS,
  THEMES,
  UI_CONTRAST_PAIRS,
  contrastRatio,
  isThemeChoice,
  resolveTheme,
} from "../src/ui/themes.js";

const ALL_IDS = Object.keys(THEMES);

describe("skin catalogue", () => {
  it("ships the agreed set of skins", () => {
    expect(ALL_IDS.sort()).toEqual(
      ["chakra", "contrast", "daylight", "dune", "forest", "midnight", "ocean"],
    );
  });

  it("every skin defines every token and a five-step meter", () => {
    const tokenKeys = Object.keys(THEMES[DEVICE_LIGHT]!.tokens).sort();
    for (const id of ALL_IDS) {
      const def = THEMES[id]!;
      expect(Object.keys(def.tokens).sort(), id).toEqual(tokenKeys);
      expect(def.meter, id).toHaveLength(5);
      for (const value of [...Object.values(def.tokens), ...def.meter]) {
        expect(value, `${id}: ${value}`).toMatch(/^#[0-9a-f]{6}$/i);
      }
      expect(def.name.length, id).toBeGreaterThan(0);
      expect(def.blurb.length, id).toBeGreaterThan(0);
    }
  });

  it("the device choice resolves to Daylight/Midnight", () => {
    expect(resolveTheme("device", false).id).toBe(DEVICE_LIGHT);
    expect(resolveTheme("device", true).id).toBe(DEVICE_DARK);
    expect(resolveTheme("ocean", false).id).toBe("ocean");
    expect(isThemeChoice("device")).toBe(true);
    expect(isThemeChoice("midnight")).toBe(true);
    expect(isThemeChoice("neon")).toBe(false);
    expect(isThemeChoice(null)).toBe(false);
  });
});

describe("WCAG contrast gate", () => {
  for (const id of ALL_IDS) {
    const def = THEMES[id]!;
    it(`${def.name}: every text pair ≥ 4.5:1`, () => {
      for (const [fg, bg] of TEXT_CONTRAST_PAIRS) {
        const ratio = contrastRatio(def.tokens[fg], def.tokens[bg]);
        expect(ratio, `${id}: ${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5);
      }
    });
    it(`${def.name}: every component pair ≥ 3:1`, () => {
      for (const [fg, bg] of UI_CONTRAST_PAIRS) {
        const ratio = contrastRatio(def.tokens[fg], def.tokens[bg]);
        expect(ratio, `${id}: ${fg} on ${bg}`).toBeGreaterThanOrEqual(3.0);
      }
    });
  }

  it("contrast math is sane (black on white is 21:1)", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 0);
    expect(contrastRatio("#ffffff", "#ffffff")).toBeCloseTo(1, 5);
  });
});
