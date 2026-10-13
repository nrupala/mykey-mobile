# MyKey browser extension

Fill logins from your desktop MyKey vault, in your browser.

The extension never holds a copy of your vault. It talks to the
MyKey app on your own computer over a private, encrypted channel
(see "How it works" below). Nothing is sent over the internet —
the extension makes **zero network requests**, which its test
suite proves.

**Browsers:** Chrome, Edge, Brave and the other Chromium browsers,
plus Firefox. Safari is not supported in this version.

## Install

You need two parts: the desktop MyKey app, and this extension.

### 1. On the desktop (once)

1. Install MyKey (the desktop app) if you have not already.
2. Tell the host which vault to serve:
   `mykey ext-set-vault <path to your vault.mykey>`
3. Let your browser start the host when needed:
   `mykey ext-host-install`
   (add `--browser edge` / `--browser firefox` etc. if you like;
   plain `ext-host-install` covers all installed browsers it can)

### 2. In the browser

- **Chromium browsers:** open `chrome://extensions`, turn on
  *Developer mode*, choose *Load unpacked*, and pick the
  `chromium` folder from the release zip. (Store listing follows;
  the zip is the v1 install path.)
- **Firefox:** open `about:debugging`, choose *This Firefox* →
  *Load Temporary Add-on*, and pick the `manifest.json` inside the
  `firefox` folder of the release zip.

### 3. Pair the browser with the desktop (once per browser)

Pairing is how the extension proves it is *your* browser and not
some other program on the machine. You approve it on the desktop.

1. Click the MyKey icon, then open the pairing options (the popup
   offers the button when you are not paired yet).
2. The options page shows this browser's **fingerprint** and a
   **pairing payload**. On the desktop, save the payload to a file
   and run:
   `mykey ext-enroll --payload payload.json --scopes fill,save`
3. The desktop shows the same fingerprint. **Compare the two
   fingerprints.** If they match, confirm on the desktop.
4. On the desktop run `mykey ext-host-payload` and paste its output
   into the options page ("Step 2 — pin the desktop's host key").
   The extension checks that the fingerprint in the payload matches
   the key itself. A payload that lies is refused.
5. Done. The popup now connects to your desktop vault.

To end a pairing: `mykey ext-revoke` on the desktop. A revoked
browser key can never be approved again — if you revoke by
mistake, use "Reset identity" on the options page and pair afresh.
Pairings can also carry an expiry (`--expires-days` at enroll
time) and can be paused with `mykey ext-disable`.

## Daily use

- Click the MyKey icon (or press **Ctrl+Shift+Y**) on a site. If
  the vault is locked, type your master password. It goes only to
  your own desktop app, inside the encrypted channel. It is never
  stored by the extension.
- Pick the login and choose **Fill**. Filling is always your click
  — nothing is filled just because a page loaded, and MyKey never
  submits a form for you.
- **Fill code** fills a sign-in (TOTP) code, as its own separate
  click.
- **Copy password** copies it; the copy clears itself after the
  time set on the desktop (`mykey ext-set --clipboard-seconds N`,
  60–300 seconds, default 60), and only if the clipboard still
  holds what MyKey put there. Locking clears it right away.
- After you sign in somewhere new, MyKey offers to save the login
  (a small prompt in the page, or the popup if you moved tabs).
  Nothing is saved unless you click Save. If the password changed,
  the offer says so.
- **Also fill on subdomains** (per login, off by default): lets
  that one login fill on subdomains of its own site. The choice is
  stored on the desktop, and the desktop makes the final call on
  every fill.

## What MyKey will never do

- Fill on a lookalike site. Matching is exact — scheme, host and
  port must all match the saved website. `example.com.evil.com`
  and `evil-example.com` get nothing, ever.
- Fill inside iframes, or fill a form it did not match.
- Fill payment-card forms, or save card details. Card fields are
  recognised and left completely alone in this version.
- Auto-fill on page load, or auto-submit any form.

## How it works (one layer down)

- The extension and the desktop talk through the browser's
  **native messaging** — a local pipe the browser starts on
  demand. No ports, no servers, no internet.
- Even though the pipe is local, every message after pairing is
  **encrypted in transit**: an X25519 key agreement from the
  pairing keys, a fresh session key per connection (HKDF-SHA256),
  AES-256-GCM per message, with counters that reject replays.
  A recording of the pipe shows only ciphertext — the leak test
  suite proves this with fixture secrets.
- The desktop stays the authority: it matches origins, holds the
  vault, enforces pairing scopes (`fill`, `save`), expiries and
  revocation, and auto-locks on the timer set with
  `mykey ext-set --auto-lock-seconds N` (default 300). The moment
  the desktop locks, the extension's cached matches are wiped and
  fills stop.

## Permissions, and why each one exists

| Permission | Why |
|---|---|
| `nativeMessaging` | Talk to the desktop MyKey app. The only way this extension communicates with anything. |
| `activeTab` | See the current tab's address (to match logins) and act on it — only after you open the popup or press the shortcut. |
| `scripting` | Put the fill into the page's fields, and show the save prompt — into the top frame only, and only on tabs you armed. |
| `storage` | Keep this browser's own pairing key and settings. Vault secrets are never stored. |
| `alarms` | Run the "clear the copied password" timer even when the popup is closed. |
| `clipboardWrite` / `clipboardRead` | Copy a password, then later check that the clipboard still holds *that* copy before clearing it (the house clipboard rule). |
| `offscreen` (Chromium only) | A tiny hidden page that runs the clipboard clear — Chromium background workers cannot touch the clipboard themselves. |

There are **no host permissions** (`<all_urls>` and friends) and
no always-on content scripts. The extension cannot read a page
until you open it on that tab.

## The leak test suite

This extension passed a named leak-test gate before release —
`tests/leak.test.ts` plus the desktop suite. It proves, with tests
that fail on a naive build:

1. A recording of the desktop channel contains no plaintext
   username, password or sign-in code.
2. Wrong-origin pages (lookalikes, subdomains without permission,
   http/https or port mismatches) get nothing.
3. Iframes cannot trigger or receive fills; fills go only to the
   top frame's matched fields.
4. No secret appears in console output, extension storage, page
   DOM outside the target fields, message traffic, or errors.
5. Locking the desktop (or its auto-lock) ends filling at once;
   no cached plaintext remains.
6. Revoked, expired or disabled pairings are refused.
7. Save-capture never fires on payment or other non-login forms.
8. Zero network requests; manifest permissions stay minimal.

Run it yourself: `npm test` in this folder (the host-integration
suite also runs when a desktop checkout is available via
`MYKEY_DESKTOP_DIR`).

## Known limits in this version

- No icon inside login fields — open the popup or use the
  shortcut.
- Change-password forms are detected but not captured yet; change
  the password in the desktop app for now.
- Safari is not supported.
- The pairing screens on the desktop are command-line in this
  version (`ext-enroll`, `ext-pairings`, `ext-revoke`).

## Support

2351485 ALBERTA INC. · Support: info@aimlds.org
