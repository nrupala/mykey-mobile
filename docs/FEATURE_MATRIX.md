# Feature matrix — MyKey web client (PWA) + Android app

Exact status of every feature, as of the 1.1.0 polish wave
(2026-10-13). "Deferred" means deliberately not built yet, not
broken. "Platform-blocked" means the platform cannot genuinely do
it, the app says so in plain words, and a working fallback is
offered instead.

## Vault

| Feature | Status | Notes |
|---|---|---|
| Create a new Vault v3 vault | Implemented | Same format, KDF defaults and limits as the desktop engine. Master password ≥ 12 characters. |
| Open Vault v3 by master password | Implemented | Proven against Python-generated fixtures (interop gate). |
| Open by recovery phrase (BIP-39) | Implemented | 12/24 words, checksum-validated; includes the desktop's backup-recipient backfill on unlock. |
| Set up / replace recovery phrase | Implemented | Phrase shown once, behind a written-down confirmation. |
| Change master password | Implemented | Re-wraps the master slot; recovery phrase unaffected. |
| Vault v1 / v2 files | Deferred (by design) | The client refuses them with instructions to open once in the desktop app, which performs the migration. Nothing is half-migrated on a phone browser. |
| Audit-sealed desktop vaults | Implemented with a stated limit | Vaults whose core carries a desktop audit seal open normally and stay byte-compatible; the app shows a notice that it cannot verify the audit log (a sidecar file the web client does not carry). The seal itself is preserved verbatim on every save. |
| Agent bundles | Maintained silently | Desktop-enrolled agents keep working on files this client saves: bundles are rebuilt on every save exactly as the desktop engine rebuilds them (proven by the Python cross-check — scope is still enforced after a TS save). Agent management UI is deferred. |
| Agent-submitted "pending" entries | Preserved, not shown | Pending objects round-trip verbatim. Approving them is a desktop task in v1. |

## Records

| Feature | Status | Notes |
|---|---|---|
| List, search | Implemented | Search covers service, username, website, notes, tags. |
| View / copy (username, password, TOTP) | Implemented | Passwords masked until "Show"; clipboard auto-clears. |
| Add / edit / delete | Implemented | Delete asks for a second tap — no silent destructive action. Duplicate (service, username) refused, like the desktop. |
| Password generator | Implemented | ≥ 16 characters (default 20), unbiased random selection, desktop's alphabet. |
| TOTP sign-in codes | Implemented | Live code + countdown, RFC 6238, accepts raw secrets and otpauth:// values. |
| Favourites, tags | Implemented | Favourites pin to the top; tags are plain text, comma-separated. |
| Import from browsers (CSV) | Implemented | Chromium family (Chrome/Edge/Brave/Opera/Vivaldi/Arc/Google Password Manager) and Firefox exports are recognised by header signature; anything else gets a by-hand column mapping. Mirrors the desktop importer: (service, username) keys, same-password = duplicate (skipped), different password = conflict with a plain-language choice (keep mine / use the file's / keep both). The file is parsed locally and never uploaded; imported entries land encrypted in the vault. Other managers' formats (Bitwarden, 1Password, …) arrive through the generic mapping in this client; their dedicated parsers remain desktop-only for now. |
| Export to CSV (readable file) | Implemented, deliberately gated | Same columns as the desktop exporter (Service, Username, Password, URL, Notes). There is no one-tap path: a warning screen states in plain words that the file is unencrypted and readable by anyone, and the export button stays disabled until the user ticks the understanding checkbox. An empty vault exports nothing. |

## Portability & sync

| Feature | Status | Notes |
|---|---|---|
| Export the encrypted vault file | Implemented | Download on web, system share sheet on Android. |
| Import a vault file | Implemented | Replaces the device copy only after explicit confirmation when it is a different vault. |
| MKBAK backup — restore (recovery recipient) | Implemented | Full Python-path checks: source fingerprint recomputed + must match one the user supplies independently, Ed25519 signature verified, downgrade refused, older-than-last-restored warns. |
| MKBAK backup — create a package | Deferred | Export requires an enrolled device identity, which the web client does not hold in v1; desktop creates packages. |
| MKBAK backup — device-recipient restore | Deferred | Needs the receiving device's private key; the recovery path covers fresh-device restore in v1. |
| Sync via a folder (your own cloud drive) | Implemented (desktop Chromium) | File System Access API: pick a folder, the app reads/writes `vault.mykey` + timestamped snapshots. Permission is re-checked every use; nothing runs in the background. |
| Sync on Firefox / Safari | Platform-blocked, fallback offered | No File System Access API: use Download + Open-file. The app says this plainly and never pretends to folder-sync. |
| Sync in the Android app | Implemented as an explicit file flow (verified behaviour) | The Android WebView provides no directory picker, so folder sync is never offered there — the capability is detected at runtime and the decision is unit-tested (`folderSyncOffered`: native ⇒ never). Instead, Settings labels the real flow in plain words: "Download my vault file" saves the encrypted vault into the user's cloud app via the share sheet; "Load a vault file from my cloud app" brings a newer copy back (different-vault loads ask first, then the app locks and the user unlocks the loaded copy). The app cannot silently sync on Android and does not claim to. |
| WebDAV sync | Deferred | The desktop covers WebDAV; the web client ships folder flows only in v1. |
| Any server, account, telemetry | Never | There is no MyKey server. CSP `connect-src 'none'` makes the client incapable of network calls. |

## Platform

| Feature | Status | Notes |
|---|---|---|
| Installable PWA, full offline after first visit | Implemented | Service-worker precache of the whole client; e2e-proven offline. |
| Android app (Capacitor, same build) | Implemented | Debug APK + unsigned release AAB from CI (see README — signing section). No INTERNET permission; Android cloud backup of app data disabled. |
| Fingerprint / face unlock (Android) | Implemented | Opt-in wrapped slot: a random wrap key lives in Android Keystore-backed, biometric-gated storage and unwraps the vault through its normal cryptographic path. Not a plaintext backdoor; turning it off deletes slot + key. Verify on a real device: CI cannot exercise biometrics. |
| Biometric unlock in the pure web PWA | Not offered (security decision) | A wrap key in web storage would be script-readable — a quiet backdoor. Password/phrase only on the web. |
| iOS app | Deferred | The PWA works in Safari (with the download/upload flows); a Capacitor iOS build is a later wave. |
| Auto-lock (quiet timer + when hidden) | Implemented | Defaults: 5 minutes, and lock when hidden — both changeable. |
| Accessibility | Implemented | Labels, focus management, aria-live status, contrast-checked palette, large targets, reduced-motion support. |
| Device display defaults | Implemented | First run follows the device: OS light/dark (reacts live to OS changes), OS font scaling (all sizes relative; the Android shell sets no WebView text-zoom override, so the system font scale applies), reduced-motion honoured. Any skin choice overrides until "Use device settings" is picked again. |
| Skins (themes) | Implemented | Settings → Appearance: Device (auto), Daylight, Midnight, Ocean, Forest, Dune, Chakra, High Contrast. Token-based — every colour comes from the active palette; picking applies instantly (the picker is its own live preview) and persists on-device. Every skin passes the WCAG AA contrast gate in CI (tests/themes.test.ts). Palette rationale: docs/DESIGN.md. |
| Password strength meter | Implemented | Five segments in the theme's meter ramp plus a word (Very weak → Excellent) — never colour alone. The Chakra skin's ramp follows the seven-chakra spectrum. |

## Help & About

| Feature | Status | Notes |
|---|---|---|
| Built-in help ("How MyKey works") | Implemented | The canonical HELP.md from the desktop repo, mirrored byte-for-byte in `src/content/` and rendered in-app from the bundle — fully offline, no web view. CI compares the mirror against the desktop repo on every run (`cmp` step in pwa.yml), so the apps cannot drift. |
| FAQ ("Common questions") | Implemented | Same canonical-text arrangement as the help file (FAQ.md). Reachable from the locked screen as well as from inside the vault — a locked-out user is exactly who needs it. |
| About screen | Implemented | Settings → About MyKey (and from Help): name, version, seller (2351485 ALBERTA INC.), support (info@aimlds.org), linked attribution with the Muse referral code, licence summary pointing at TERMS, changelog pointer. A marked code slot waits for the licence / tip block if the free-tier ruling lands — no purchase content ships before that ruling. |
