# Changelog

All notable changes to the MyKey web client + Android app.
Versions follow the client's own line; the vault format it speaks
is Vault v3 (desktop engine 2.2.0).

## [Unreleased]

- **Your vault has a home outside the app (Android).** Your vault is
  a file; MyKey is its opener. On Android you can now give the vault
  a home: pick a folder once (for example in your cloud drive) and
  MyKey keeps the vault file there — `MyKey/vault.mykey`, encrypted
  as always — updated on every save. The copy inside the app is a
  working copy, so the app still opens when the folder can't be
  reached; on open, the newer copy wins, and if both copies changed
  you are asked at unlock, with the other copy preserved in the
  folder as a dated file — nothing is ever overwritten on a guess
  or deleted. Uninstalling the app can no longer take your vault
  with it: reinstall, and MyKey offers to open the vault found in
  its folder. Turning the home off in Settings leaves the outside
  file where it is (deleting it is yours to do, in your file
  manager). A failed home update is shown in Settings and as a
  one-line notice at the next unlock — never silent, never blocking
  your save. The web app has no home copy (browser storage rules)
  and does not offer one. Client 1.4.0.

- **Permanent release signing — in-place updates from now on.**
  Android builds shipped so far were debug builds, each signed by
  the CI machine's throwaway key, so Android refused every update
  and the app had to be uninstalled and reinstalled (losing the
  on-device vault copy unless it was exported first). The release
  APK is now signed in CI with one permanent release key held by
  2351485 ALBERTA INC. (provided to CI as Actions secrets; the
  keystore is never in this repository). The release AAB stays
  unsigned here because Play App Signing signs the store build.
  One consequence, stated plainly: an install signed with an old
  debug key cannot be updated over — one final fresh install of a
  release-signed build is needed; every update after that installs
  in place. Also fixed: the Android version now comes from
  package.json (versionName verbatim; versionCode derived as
  major*10000 + minor*100 + patch) instead of a frozen 1.0.0 / 1.

- **New app logo — the refined key.** The placeholder key is replaced
  by the product mark (owner pick, 2026-10-14): a two-tone gold key
  with a double-ring bow on deep navy (#111D54), drawn as clean
  vector masters (`public/brand/logo-tile.svg`, `logo-key.svg`) and
  rendered into every icon slot — PWA icons (incl. maskable),
  apple-touch, the extension icons, the Android adaptive foreground
  (navy background colour updated to match), and the legacy mipmaps.
  The web manifest theme/background colours move to the same navy.

- **Help on the locked screen, above the fold.** The "Help and
  questions" button on the locked screen moved from the very bottom
  to directly under the unlock controls, before the secondary
  actions — on a phone it previously fell below the fold and a
  locked-out user never saw it.

Android autofill wave.

- **Autofill service (Android).** MyKey can now fill passwords in
  other apps and browsers. A native AutofillService answers with
  a single no-value dataset; tapping it opens MyKey, and the
  chosen entry's values cross back only after unlock + an
  explicit tap — never automatically, never with auto-submit.
  Inline (keyboard) presentation plus the dropdown dataset.
- **Matching with a hard identity check.** Browsers match by web
  domain (subdomains of a saved site included; lookalikes
  refused). Apps match by a binding stored on the entry: package
  name + the SHA-256 of the app's signing certificate. A
  re-signed or cloned app never matches silently — it is flagged
  and needs a fresh one-time confirm. First use asks to link;
  unlinking lives in the entry details.
- **Save to MyKey.** Android's save prompt routes new logins to
  an in-app confirm screen; nothing is stored before the tap.
  New entries pass the same free entry cap as every other add
  path — the licensing wave's limit, enforced in the vault
  itself (50 entries free, unlimited with a licence).
- **Hardening.** Locked vault ⇒ the dataset shows only "Unlock
  MyKey" (no entry names, no usernames). FLAG_SECURE on the app
  and the autofill auth screen (no screenshots/recents). The
  autofill module has zero logging — enforced by a CI grep — and
  release rules strip Log calls if minification is ever enabled.
  Auto-lock expiry revokes fill ability.
- **Entry field `android_app`** (encrypted metadata) round-trips
  through both clients; the desktop engine carries it and shows
  it read-only. Interop fixtures gained a bound entry proving
  both directions, including through a Python save.
- Settings gains an "Autofill in other apps" section with an
  honest on/off status and a deep link to Android's picker.
- Device verification is the owner's step (CI has no emulator):
  docs/DEVICE_TEST_AUTOFILL.md.

### Fixed — Android autofill bindings survive a save in this client
- Entries can carry an `android_app` binding (package name +
  signing-certificate hash) written by the desktop engine / the
  Android autofill flow. This client's metadata field list did
  not include it, so opening such a vault here and saving
  anything silently dropped every binding. The field is now
  carried verbatim through load and save (validated with the
  desktop's rules; malformed bindings load as none), with a
  round-trip test standing guard.

## [1.3.0] — 2026-10-13

Licensing wave — the free tier and the signed licence key, in
lockstep with the desktop engine.

- **Free tier, counted fairly.** Up to 50 passwords and 4
  connections (devices + agents + paired browsers, one pool per
  vault). Only the counts are limited; every security feature
  stays free. Settings shows the state in plain words ("Free ·
  37 of 50 passwords · 3 of 4 connections").
- **Licence keys.** Settings → "Enter a licence key": an
  Ed25519-signed `MKLIC1.` token verified fully offline. The key
  is stored inside the vault (travels with it) and in a device
  slot (new vaults start licensed). Licence statement format,
  passcode recovery and the grandfather rule are shared with the
  desktop — see LICENCE.md.
- **Grandfather rule + honest imports.** Over-limit vaults open
  and work fully; only adding pauses. Imports fill to the limit
  and report exactly how many were held back and why.
- **About screen slot filled.** The help wave's marked licence / tip slot in About now carries the plain-words licence summary (and the live status line when a vault is open).
- **Buy / tip jar, Play-safe.** Buy and Tip jar live in Settings.
  The Android build never links out to a web checkout for the
  unlock (Play policy): it points to the website on another
  device, with Play Billing seamed in for the future listing.

## [Unreleased]

- **Password age + rotation.** The app notes the day each password
  was set — inside the encrypted vault, next to the password
  itself. Changing a password restarts its clock automatically;
  "Mark as changed today" covers passwords changed on the website.
  Passwords are due for a change after 180 days by default; the
  vault default is changeable in Settings (including Never), and
  each entry can carry its own period or opt out. Due states are
  calm: a small badge in the list, a count at unlock, and a
  Password rotation section listing what needs attention. No
  notifications and no new permissions in this version (planned
  as future work). Vaults written before this feature open
  normally — the set date falls back to the entry's creation date,
  or reads "date not recorded". Same semantics, file fields and
  fixture gate as the desktop engine.

- **Built-in help, fully offline.** "How MyKey works" and
  "Common questions" ship inside the app (no network, no web
  view). The text is the canonical copy from the desktop repo,
  mirrored byte-for-byte; the PWA CI fails if the copies drift.
  Help is reachable from the locked screen — a locked-out user
  is who needs the recovery answers — and from Settings.
- **About screen.** App name and version, seller 2351485
  ALBERTA INC., support address, the linked attribution line
  with the Muse referral code, a licence summary, and a
  changelog pointer. A marked slot waits for the licence / tip
  block if the free-tier ruling lands.

## [1.2.0] — 2026-10-13

The blob wave: backup packages round-trip through this client.

- MKBAK v2 export and import, byte-compatible with the desktop
  engine (2.2.0) — fixtures regenerate from the Python repo and
  the Python cross-check opens this client's packages, so the
  formats cannot drift.
- Two-factor recovery: newer backup packages open outside the app
  only with the recovery phrase AND an 8-word backup code
  together. The code is generated at export, shown once, and
  never stored. Legacy v1 packages still restore phrase-only and
  are labelled LEGACY.
- This client holds its own device identity, enrolls in the
  vault, and restores its own packages directly (no phrase, no
  code).
- Key-value pairing: pair devices, cloud folders, and backup
  targets by payload + fingerprint confirmation; the registry
  lives in the encrypted vault. Exports wrap only to active
  pairings with the export scope; a sync folder tied to a pairing
  saves/loads only while that pairing is active with the matching
  permission. Revoke/disable/expire from the pairing screen.

## [Unreleased]

### Changed — clipboard self-clear rule (owner directive, 2026-10-13)
- Copied secrets (passwords, TOTP codes, recovery material) now
  clear through one guard (`src/platform/clipboard.ts`): 1 minute
  by default, user-settable from 1 to 5 minutes in Settings with
  hard bounds of 60–300 seconds enforced at a single validation
  point (older stored values are clamped on load). The clipboard
  is cleared only if it still holds exactly what MyKey put there;
  locking the vault clears a pending copied secret immediately;
  a new copy restarts the timer. On Android, copies are marked
  sensitive (EXTRA_IS_SENSITIVE) via a small native plugin; the
  previous fixed 30-second setting is superseded.
Passkey wave (2026-10-13).

- **Passkey storage.** Vault entries of kind "passkey" hold a
  WebAuthn record (credential private key included) in its own
  blob under a new per-entry key class (DEK_passkey), sealed by
  a core hash — same discipline as passwords and TOTP, separate
  key. Interop-proven both directions; the Python cross-check
  verifies a TS-produced assertion signature.
- **Passkey use on Android.** The app is a Credential Manager
  provider (API 34+): "create a passkey" and "sign in with a
  passkey" run through a TypeScript WebAuthn authenticator on the
  unlocked vault — RP ID mismatch always refused, unlock is the
  user verification, attestation honestly "none", sign_count
  monotonic with a device-local clone warning. Provider flows
  are compile-verified in CI; the device test script is
  docs/DEVICE_TEST_PASSKEYS.md. Design + limits:
  docs/PASSKEYS.md.
- **Never to agents, never to CSV.** Passkey entries are excluded
  from agent bundles in both engines; CSV export skips them and
  CSV import never overwrites one.

## [1.1.0] — 2026-10-13

Polish wave, driven by the first device test of 1.0.0.

- **Skins.** Settings → Appearance offers Device (auto), Daylight,
  Midnight, Ocean, Forest, Dune, Chakra, and High Contrast. All
  colours are theme tokens now; a skin applies instantly and
  persists on-device. Every skin passes a WCAG AA contrast gate
  in CI. Rationale in docs/DESIGN.md.
- **Device-first display defaults.** First run follows the OS
  light/dark setting (live), the OS font size, and reduced-motion;
  "Use device settings" restores automatic behaviour at any time.
- **Password strength meter** in the editor: five segments plus a
  word, in the active skin's ramp.
- **Browser CSV import.** Chrome-family and Firefox exports are
  recognised automatically; other files get a by-hand column
  mapping. Desktop-identical duplicate/conflict handling with a
  plain-language choice. Files are parsed locally, never uploaded.
- **CSV export, deliberately gated.** Desktop-identical columns,
  behind a plain-language unencrypted-file warning and an explicit
  confirmation — no one-tap path.
- **Android sync, honestly labelled.** The app has no folder
  picker (WebView), so sync in the app is the explicit file flow
  through the user's cloud app, labelled as such in Settings.
- Support address is now info@aimlds.org (brand, footer, terms,
  README), following the product-support decision.

## [1.0.0] — 2026-10-13

First release.

- One TypeScript client for both surfaces: installable offline
  PWA + Capacitor Android app (`com.usemykey.mykey`).
- Vault v3 engine ported from the Python implementation:
  create/open by master password or BIP-39 recovery phrase,
  Argon2id/PBKDF2 slots, per-entry data keys, entry-hash seal,
  agent bundle rebuild on save, unknown core fields preserved.
- Records: list/search/view/copy, add/edit/delete, favourites and
  tags, password generator, live TOTP codes.
- Portability: encrypted vault file export/import; MKBAK backup
  restore via the recovery recipient with the desktop's
  fingerprint + signature checks; folder sync through the File
  System Access API where the browser genuinely supports it, with
  explicit download/upload elsewhere.
- Security: ciphertext-only local storage (IndexedDB), auto-lock
  (quiet timer + hidden), clipboard auto-clear, strict CSP with
  `connect-src 'none'`, pinned dependencies, no INTERNET
  permission in the Android app, OS cloud backup of app data off.
- Android fingerprint unlock as a Keystore-backed wrapped slot
  (opt-in), never a plaintext path.
- Interoperability gate: Python-generated fixtures + a reverse
  cross-check (Python opens TS-written files) run in CI.
