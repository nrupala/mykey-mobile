// Licensed under the Apache License, Version 2.0 — see LICENSING.md.
// Copyright (c) 2026 2351485 ALBERTA INC.

// The folder-sync decision is capability-driven, and the Android
// app must NEVER be offered folder sync: the WebView provides no
// directory picker. These cases pin that decision so a future
// refactor cannot quietly start promising folders on Android.

import { describe, expect, it } from "vitest";
import { folderSyncOffered } from "../src/platform/filesync.js";

describe("folderSyncOffered", () => {
  it("desktop browser with the directory picker: offered", () => {
    expect(folderSyncOffered({ native: false, directoryPicker: true })).toBe(true);
  });
  it("browser without the picker (Firefox/Safari): not offered", () => {
    expect(folderSyncOffered({ native: false, directoryPicker: false })).toBe(false);
  });
  it("Android app: never offered, picker or not", () => {
    expect(folderSyncOffered({ native: true, directoryPicker: true })).toBe(false);
    expect(folderSyncOffered({ native: true, directoryPicker: false })).toBe(false);
  });
});
