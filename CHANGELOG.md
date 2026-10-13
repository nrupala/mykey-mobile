# Changelog

All notable changes to the MyKey web client + Android app.
Versions follow the client's own line; the vault format it speaks
is Vault v3 (desktop engine 2.1.0).

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
