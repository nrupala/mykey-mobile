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

// End-to-end smoke for the built PWA (run against `vite preview`):
// first visit installs the offline shell, a vault is created, a
// password added, the vault locked/unlocked, and everything must
// still work after a reload with the network OFF. A second test
// unlocks the PYTHON-generated fixture vault file through the real
// file-picker flow.

import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "..", "tests", "fixtures", "fixture.mykey");
const CHROMIUM_CSV = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "chromium.csv");
const MASTER = "E2e-Master-Password-1";

async function createVaultAndEnter(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome to MyKey" })).toBeVisible();
  await page.getByRole("button", { name: "Create a new vault" }).click();
  const fields = page.locator("form.form input[type='password']");
  await fields.nth(0).fill(MASTER);
  await fields.nth(1).fill(MASTER);
  await page.getByRole("button", { name: "Create vault", exact: true }).click();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: /open my vault/ }).click();
  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();
}

test("create, add, lock, unlock, offline reload", async ({ page, context }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome to MyKey" })).toBeVisible();

  // Create a vault.
  await page.getByRole("button", { name: "Create a new vault" }).click();
  const fields = page.locator("form.form input[type='password']");
  await fields.nth(0).fill(MASTER);
  await fields.nth(1).fill(MASTER);
  await page.getByRole("button", { name: "Create vault", exact: true }).click();

  // Recovery phrase screen: 12 words, confirm, enter.
  await expect(page.getByRole("heading", { name: "Save your recovery phrase" })).toBeVisible();
  const words = await page.locator(".phrase-grid li").allTextContents();
  expect(words).toHaveLength(12);
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: /open my vault/ }).click();

  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();

  // Add an entry.
  await page.getByRole("button", { name: "Add a password" }).click();
  await page.getByLabel("Service or app name").fill("github");
  await page.getByLabel("Username or email").fill("octocat");
  await page.getByLabel("Password", { exact: true }).fill("e2e-secret-123");
  await page.getByRole("button", { name: "Save password" }).click();
  await expect(page.getByRole("button", { name: /github/ })).toBeVisible();

  // Lock and unlock.
  await page.getByRole("button", { name: "Lock now" }).click();
  await expect(page.getByRole("heading", { name: "Your vault is locked" })).toBeVisible();
  await page.getByLabel("Master password", { exact: true }).fill(MASTER);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();
  await expect(page.getByRole("button", { name: /github/ })).toBeVisible();

  // Wait for the service worker to control the page, then go offline.
  await page.waitForFunction(() => !!navigator.serviceWorker?.controller, null, {
    timeout: 30_000,
  });
  await context.setOffline(true);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Your vault is locked" })).toBeVisible();
  await page.getByLabel("Master password", { exact: true }).fill(MASTER);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();
  await expect(page.getByRole("button", { name: /github/ })).toBeVisible();
  await context.setOffline(false);
});

test("opens the Python fixture vault through the file picker", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome to MyKey" })).toBeVisible();
  await page.getByRole("button", { name: "Open a vault file" }).click();

  const chooserPromise = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: "Choose vault file" }).click();
  const chooser = await chooserPromise;
  await chooser.setFiles(FIXTURE);

  await page.getByLabel("Master password", { exact: true }).fill("Correct-Horse-2026!");
  await page.getByRole("button", { name: "Open this vault" }).click();
  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();
  const entryList = page.locator(".entry-list");
  await expect(entryList.getByRole("button", { name: /github/ })).toBeVisible();
  await expect(entryList.getByRole("button", { name: /bank/ })).toBeVisible();

  // The fixture's dated passwords (set Nov 2023) are long past due
  // at any real "today", so the unlock note counts both (rotation
  // wave); the never-rotate entry stays out.
  await expect(page.getByText("2 passwords are due for a change")).toBeVisible();

  // The github entry shows a live TOTP code (fixture carries TOTP).
  await entryList.getByRole("button", { name: /github/ }).click();
  await expect(page.locator(".entry-totp, .kv-value.code").first()).toContainText(/\d{6}/);
});

test("device default follows a dark OS setting", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Welcome to MyKey" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "midnight");
});

test("skin choice persists across lock, reload, and offline", async ({ page, context }) => {
  await createVaultAndEnter(page);
  // Light OS + no choice yet = the device default (Daylight).
  await expect(page.locator("html")).toHaveAttribute("data-theme", "daylight");

  await page.getByRole("button", { name: /Appearance/ }).click();
  await expect(page.getByRole("heading", { name: "Appearance" })).toBeVisible();
  await page.getByRole("button", { name: /Midnight/ }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "midnight");
  await page.getByRole("button", { name: "Back", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();

  // Lock + unlock keeps the skin.
  await page.getByRole("button", { name: "Lock now" }).click();
  await page.getByLabel("Master password", { exact: true }).fill(MASTER);
  await page.getByRole("button", { name: "Unlock", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "midnight");

  // Offline reload keeps it too.
  await page.waitForFunction(() => !!navigator.serviceWorker?.controller, null, {
    timeout: 30_000,
  });
  await context.setOffline(true);
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "midnight");
  await expect(page.getByRole("heading", { name: "Your vault is locked" })).toBeVisible();
  await context.setOffline(false);
});

test("imports a Chrome CSV export into the vault", async ({ page }) => {
  await createVaultAndEnter(page);
  await page.getByRole("button", { name: /Import passwords/ }).click();
  await expect(page.getByRole("heading", { name: "Import passwords" })).toBeVisible();

  const chooserPromise = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: "Choose the exported file" }).click();
  const chooser = await chooserPromise;
  await chooser.setFiles(CHROMIUM_CSV);

  await expect(page.getByText(/are new to your vault/)).toBeVisible();
  await page.getByRole("button", { name: "Add them to my vault" }).click();
  await expect(page.getByRole("heading", { name: "Import finished" })).toBeVisible();
  await expect(page.getByText(/Added 2 new passwords/)).toBeVisible();

  await page.getByRole("button", { name: "See my passwords" }).click();
  const listAfterImport = page.locator(".entry-list");
  await expect(listAfterImport.getByRole("button", { name: /github/ })).toBeVisible();
  await expect(listAfterImport.getByRole("button", { name: /Example Bank/ })).toBeVisible();
});

test("CSV export stays blocked until the warning is confirmed", async ({ page }) => {
  await createVaultAndEnter(page);
  await page.getByRole("button", { name: "Add a password" }).click();
  await page.getByLabel("Service or app name").fill("github");
  await page.getByLabel("Username or email").fill("octocat");
  await page.getByLabel("Password", { exact: true }).fill("e2e-secret-123");
  await page.getByRole("button", { name: "Save password" }).click();
  await expect(page.getByRole("button", { name: /github/ })).toBeVisible();

  await page.getByRole("button", { name: /Export passwords/ }).click();
  await expect(
    page.getByRole("heading", { name: "Export passwords as a readable file" }),
  ).toBeVisible();
  await expect(page.getByText(/NOT encrypted/)).toBeVisible();

  const exportBtn = page.getByRole("button", { name: "Export the readable file" });
  await expect(exportBtn).toBeDisabled();
  await page.getByRole("checkbox").check();
  await expect(exportBtn).toBeEnabled();

  const downloadPromise = page.waitForEvent("download");
  await exportBtn.click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("mykey_export.csv");
  const path = await download.path();
  const content = readFileSync(path!, "utf8");
  expect(content).toContain("Service,Username,Password,URL,Notes");
  expect(content).toContain("github,octocat,e2e-secret-123");
});

test("lock on hide: hidden tab locks the vault", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Create a new vault" }).click();
  const fields = page.locator("form.form input[type='password']");
  await fields.nth(0).fill(MASTER);
  await fields.nth(1).fill(MASTER);
  await page.getByRole("button", { name: "Create vault", exact: true }).click();
  await page.getByRole("checkbox").check();
  await page.getByRole("button", { name: /open my vault/ }).click();
  await expect(page.getByRole("heading", { name: "Your passwords" })).toBeVisible();
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      get: () => "hidden",
    });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(page.getByRole("heading", { name: "Your vault is locked" })).toBeVisible();
});
