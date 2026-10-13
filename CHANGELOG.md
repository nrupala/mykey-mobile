# Changelog

All notable changes to the MyKey web client + Android app.
Versions follow the client's own line; the vault format it speaks
is Vault v3 (desktop engine 2.1.0).

## [Unreleased]

Help + FAQ + About wave (desktop repo: MyKey Help wave PR).

- **Built-in help, fully offline.** "How MyKey works" and
  "Common questions" render in-app from text bundled with the
  client — no web view, no network. The canonical text lives in
  the desktop repo (HELP.md / FAQ.md); this repo mirrors it
  byte-for-byte in `src/content/`, and CI now fails if the two
  drift apart.
- **Help is reachable while locked out.** A "Help and questions"
  button sits on the locked and welcome screens, not just in
  Settings — a forgotten password is when the FAQ matters most.
- **About screen.** Settings → About MyKey: name, version,
  seller, support address, the linked attribution line with the
  Muse referral code, a licence summary pointing at TERMS, and
  a changelog pointer.

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
