# Changelog

All notable changes to the MyKey web client + Android app.
Versions follow the client's own line; the vault format it speaks
is Vault v3 (desktop engine 2.2.0).

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

- **Browser extension + autofill** (new sibling package,
  `extension/`). For Chromium browsers (Chrome/Edge/Brave/…)
  and Firefox; Safari is out of scope for v1. The extension
  holds no vault copy: it talks to the desktop app over native
  messaging, paired by the house key-value pattern (extension
  id → X25519 public key + scopes + expiry + enabled, approved
  by a human on the desktop with a fingerprint ceremony).
  Session traffic is encrypted in transit (X25519 + HKDF,
  AES-256-GCM per message, replay counters) — a frame capture
  shows only ciphertext.
- **Autofill behaviour.** Exact origin matching (scheme + host
  + port), per-entry "also fill on subdomains" toggle (default
  off, stored on the desktop), lookalikes never match. Fill is
  click-only — never on page load, never auto-submit. TOTP fill
  is a separate explicit action. Save-on-login capture prompts
  in-page and saves only on a click; payment forms are
  recognised and never harvested. Clipboard copies follow the
  house rule (clear after 60–300s, default 60, only if the
  clipboard still holds the copy; immediate clear on lock).
- **Leak test gate.** A named suite (`extension/tests/`,
  including `leak.test.ts` and a real-host integration suite)
  proves: no plaintext in recorded channel frames, wrong
  origins get nothing, iframes get nothing, no secrets in
  console/storage/DOM/message traffic/errors, lock wipes fill
  ability and caches, revoked/expired pairings are refused,
  non-login forms are never captured, and the extension makes
  zero network requests with a minimal permission manifest.
  Store-ready zips build as CI artifacts
  (`.github/workflows/extension.yml`).
- Known v1 limits: no in-field icon, change-password capture
  not offered yet, desktop pairing screens are CLI-only.

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
