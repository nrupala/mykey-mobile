// Guards the one deliberate duplication in the project: the
// Capacitor CLI loads capacitor.config.ts standalone, so the app
// identity is written there literally and must match src/brand.ts.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { BRAND, VAULT_FILENAME } from "../src/brand.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("brand identity consistency", () => {
  it("capacitor config uses the brand app id and name", () => {
    const text = readFileSync(join(root, "capacitor.config.ts"), "utf8");
    expect(text).toContain(`appId: "${BRAND.appId}"`);
    expect(text).toContain(`appName: "${BRAND.productName}"`);
  });

  it("manifest uses the brand name and vault file name is stable", () => {
    const manifest = JSON.parse(
      readFileSync(join(root, "public", "manifest.webmanifest"), "utf8"),
    );
    expect(manifest.short_name).toBe(BRAND.productName);
    expect(VAULT_FILENAME).toBe("vault.mykey"); // must match the desktop default
  });
});
