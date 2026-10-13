// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Copyright (c) 2026 2351485 ALBERTA INC.
//
// jsdom page helpers: install a page as the test globals and load
// the REAL content entry into it (the same module the browser
// injects), so content behaviour is tested as shipped.

import { JSDOM } from "jsdom";
import { vi } from "vitest";
import type { FakeApi } from "./fakeapi.js";

export function installPage(html: string, url: string): JSDOM {
  const dom = new JSDOM(html, { url });
  const g = globalThis as unknown as Record<string, unknown>;
  g.window = dom.window;
  g.document = dom.window.document;
  return dom;
}

export const LOGIN_PAGE = `<!doctype html><html><body>
  <form id="login" action="/session" method="post">
    <label>Email <input id="u" type="text" name="username" autocomplete="username"></label>
    <label>Password <input id="p" type="password" name="password" autocomplete="current-password"></label>
    <button type="submit">Sign in</button>
  </form>
</body></html>`;

export const OTP_PAGE = `<!doctype html><html><body>
  <form id="otp" action="/verify" method="post">
    <input class="code" inputmode="numeric" autocomplete="one-time-code" maxlength="1">
    <input class="code" inputmode="numeric" maxlength="1">
    <input class="code" inputmode="numeric" maxlength="1">
    <input class="code" inputmode="numeric" maxlength="1">
    <input class="code" inputmode="numeric" maxlength="1">
    <input class="code" inputmode="numeric" maxlength="1">
  </form>
</body></html>`;

export const PAYMENT_PAGE = `<!doctype html><html><body>
  <form id="pay" action="/pay" method="post">
    <input type="text" name="cardnumber" autocomplete="cc-number">
    <input type="text" name="ccname" autocomplete="cc-name">
    <input type="text" name="cvc" autocomplete="cc-csc">
    <input type="password" name="pin" autocomplete="off">
    <button type="submit">Pay</button>
  </form>
</body></html>`;

export const CHANGE_PW_PAGE = `<!doctype html><html><body>
  <form id="change" action="/settings/password" method="post">
    <input type="password" name="current" autocomplete="current-password">
    <input type="password" name="new1" autocomplete="new-password">
    <input type="password" name="new2" autocomplete="new-password">
    <button type="submit">Change password</button>
  </form>
</body></html>`;

/** Load src/content-entry.ts fresh against the current globals, so
 * window.__mkContent is the real shipped content API. The FakeApi
 * must already be installed as globalThis.chrome. */
export async function loadContentEntry(api: FakeApi): Promise<void> {
  const g = globalThis as unknown as Record<string, unknown>;
  g.chrome = api;
  vi.resetModules();
  await import("../../src/content-entry.js");
}
