// @vitest-environment jsdom
// Licensed under the Apache License, Version 2.0 — see LICENSING.md.
// Copyright (c) 2026 2351485 ALBERTA INC.

// Appearance behaviour: the device default, persistence of a skin
// choice, instant repaint, and live reaction to the OS flipping
// between light and dark while the choice is "device".

import { beforeAll, describe, expect, it } from "vitest";
import { THEMES } from "../src/ui/themes.js";

let appearance: typeof import("../src/ui/appearance.js");
let setOsDark: (dark: boolean) => void = () => {};

beforeAll(async () => {
  let matches = false;
  const listeners = new Set<(e: { matches: boolean }) => void>();
  setOsDark = (dark: boolean) => {
    matches = dark;
    listeners.forEach((fn) => fn({ matches: dark }));
  };
  window.matchMedia = ((query: string) => ({
    get matches() {
      return matches;
    },
    media: query,
    addEventListener: (_t: string, fn: (e: { matches: boolean }) => void) =>
      listeners.add(fn),
    removeEventListener: (_t: string, fn: (e: { matches: boolean }) => void) =>
      listeners.delete(fn),
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
  const meta = document.createElement("meta");
  meta.setAttribute("name", "theme-color");
  document.head.append(meta);
  appearance = await import("../src/ui/appearance.js");
});

describe("appearance", () => {
  it("defaults to the device choice; device + light OS paints Daylight", () => {
    window.localStorage.clear();
    expect(appearance.loadThemeChoice()).toBe("device");
    appearance.applyTheme("device");
    expect(document.documentElement.dataset.theme).toBe("daylight");
    expect(document.documentElement.style.getPropertyValue("--brand").trim())
      .toBe(THEMES.daylight!.tokens.brand);
    expect(document.documentElement.style.getPropertyValue("color-scheme"))
      .toContain("light");
  });

  it("a skin choice paints instantly and persists", () => {
    appearance.chooseTheme("midnight");
    expect(document.documentElement.dataset.theme).toBe("midnight");
    expect(document.documentElement.style.getPropertyValue("--paper").trim())
      .toBe(THEMES.midnight!.tokens.paper);
    expect(window.localStorage.getItem("mykey.appearance.theme")).toBe("midnight");
    expect(appearance.loadThemeChoice()).toBe("midnight");
    const meta = document.querySelector('meta[name="theme-color"]');
    expect(meta?.getAttribute("content")).toBe(THEMES.midnight!.tokens.brand);
  });

  it("in device mode the app follows the OS when it flips", () => {
    appearance.chooseTheme("device");
    expect(document.documentElement.dataset.theme).toBe("daylight");
    setOsDark(true);
    expect(document.documentElement.dataset.theme).toBe("midnight");
    setOsDark(false);
    expect(document.documentElement.dataset.theme).toBe("daylight");
  });

  it("an explicit skin ignores OS flips", () => {
    appearance.chooseTheme("ocean");
    setOsDark(true);
    expect(document.documentElement.dataset.theme).toBe("ocean");
    setOsDark(false);
    expect(document.documentElement.dataset.theme).toBe("ocean");
  });

  it("a stored value that is not a skin is never honoured", () => {
    window.localStorage.setItem("mykey.appearance.theme", "neon");
    expect(appearance.loadThemeChoice()).not.toBe("neon");
  });
});
