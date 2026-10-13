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

import { expect, test } from "@playwright/test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), "..", "tests", "fixtures", "fixture.mykey");
const MASTER = "E2e-Master-Password-1";

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
  await expect(page.getByRole("button", { name: /github/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /bank/ })).toBeVisible();

  // The github entry shows a live TOTP code (fixture carries TOTP).
  await page.getByRole("button", { name: /github/ }).click();
  await expect(page.locator(".entry-totp, .kv-value.code").first()).toContainText(/\d{6}/);
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
