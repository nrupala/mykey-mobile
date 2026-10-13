import type { CapacitorConfig } from "@capacitor/cli";

/** The Android app wraps the SAME built web client (dist/) as the
 * PWA — one source of truth, two surfaces. App identity mirrors
 * src/brand.ts (the Capacitor CLI loads this file standalone and
 * cannot import the app sources; tests/config.test.ts asserts the
 * two stay in step). */
const config: CapacitorConfig = {
  appId: "com.usemykey.mykey", // BRAND.appId in src/brand.ts
  appName: "MyKey", // BRAND.productName in src/brand.ts
  webDir: "dist",
  server: {
    // No remote content, ever: the app ships its whole UI and makes
    // no network calls (the CSP in index.html also enforces it).
    androidScheme: "https",
    cleartext: false,
  },
};

export default config;
