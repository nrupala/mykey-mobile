# Feature matrix — MyKey web client (PWA) + Android app

Exact status of every feature, as of the 1.3.0 licensing
and passkey waves and the Android autofill wave
(2026-10-13), following the blob and
password-rotation waves. "Deferred" means deliberately not built yet, not

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
| View / copy (username, password, TOTP) | Implemented | Passwords masked until "Show". Copied secrets clear themselves after 1 minute by default (Settings: 1–5 minutes, hard bounds 60–300s), only if the clipboard still holds what MyKey put there; locking clears at once. Android marks clips sensitive (EXTRA_IS_SENSITIVE); on the web a browser may block the timed clear without focus — stated, never faked. |
| Add / edit / delete | Implemented | Delete asks for a second tap — no silent destructive action. Duplicate (service, username) refused, like the desktop. |
| Password generator | Implemented | ≥ 16 characters (default 20), unbiased random selection, desktop's alphabet. |
| TOTP sign-in codes | Implemented | Live code + countdown, RFC 6238, accepts raw secrets and otpauth:// values. |
| Favourites, tags | Implemented | Favourites pin to the top; tags are plain text, comma-separated. |
| Android app binding on an entry | Implemented | An entry can be linked to one Android app (package name + SHA-256 of its signing certificate), stored in the encrypted metadata like every other field and carried by both clients; the desktop shows it read-only. Set from the Android autofill chooser after an explicit confirm; unlink in the entry's details. |
| Password age + rotation | Implemented | The day each password was set is stored inside the encrypted secret blob (never in plaintext, never in agent-visible listings) and shown in plain words ("Password set 13 Oct 2026 · change by 11 Apr 2027"). Changing the password restarts the clock; other edits never touch it; "Mark as changed today" covers website-side changes. Due after 180 days by default; Settings changes the vault default (or Never); the edit form sets a per-entry period or Never. Calm surfacing only: list badge, a count at unlock, and a Password rotation section. No notifications in this version (future work; no new permissions). Pre-feature vaults open with the creation date as the set date, else "date not recorded". Desktop-identical semantics, proven both directions through the fixture gate. |
| Notifications for due passwords | Deferred (future work) | Deliberately not in this wave: reminders are in-app only, and the app holds no notification permission. |
| Import from browsers (CSV) | Implemented | Chromium family (Chrome/Edge/Brave/Opera/Vivaldi/Arc/Google Password Manager) and Firefox exports are recognised by header signature; anything else gets a by-hand column mapping. Mirrors the desktop importer: (service, username) keys, same-password = duplicate (skipped), different password = conflict with a plain-language choice (keep mine / use the file's / keep both). The file is parsed locally and never uploaded; imported entries land encrypted in the vault. Other managers' formats (Bitwarden, 1Password, …) arrive through the generic mapping in this client; their dedicated parsers remain desktop-only for now. |
| Export to CSV (readable file) | Implemented, deliberately gated | Same columns as the desktop exporter (Service, Username, Password, URL, Notes). There is no one-tap path: a warning screen states in plain words that the file is unencrypted and readable by anyone, and the export button stays disabled until the user ticks the understanding checkbox. An empty vault exports nothing. |

## Passkeys

| Feature | Status | Notes |
|---|---|---|
| Passkey storage in the vault | Implemented | Entry kind "passkey": the WebAuthn record (private key included) sits in its own blob under DEK_passkey, sealed by a core hash; a missing/mismatched seal fails the open closed. Proven both directions by the interop gate (Python fixture → TS use → Python verifies the TS assertion signature). |
| Create a passkey (Android) | Implemented, device test pending | Via the Credential Manager provider: unlock = user verification, one plain confirmation screen in the app. Attestation is "none" (zero AAGUID) — honestly, no fake hardware attestation. ES256; EdDSA only where WebCrypto offers Ed25519. |
| Sign in with a passkey (Android) | Implemented, device test pending | RP ID mismatch is always refused (dot-boundary suffix rule for web origins; OS binding for native Android callers). sign_count increments and persists; assertion signatures verify against the stored public key (unit + cross-client proven). Credential Manager picker flows are CI-compile-verified only — see docs/DEVICE_TEST_PASSKEYS.md. |
| Clone warning | Implemented | Device-local sign_count high-water marks; a regression at unlock warns in plain words. Synced-vault count semantics are documented in docs/PASSKEYS.md — restored copies can legitimately trip RP-side clone detection. |
| Passkeys in agent bundles | Never | Passkey entries are excluded from bundle targets and DEK_passkey is never bundled, in both engines. Agent passkey use is a later, separately gated design — not built. |
| Passkeys in CSV export/import | Never (export) / protected (import) | Export skips passkey entries and says so on the export screen. Import never overwrites or merges into a passkey entry. |
| Desktop role | Read-only + delete | Creation/use is phone-first in v1; the desktop lists passkeys and can delete them. |
| Browser-extension bridging, CXP/CXF transfer, iOS provider | Deferred (out of scope v1) | Named here so the gap is explicit, per docs/PASSKEYS.md. |

## Portability & sync

| Feature | Status | Notes |
|---|---|---|
| Export the encrypted vault file | Implemented | Download on web, system share sheet on Android. |
| Import a vault file | Implemented | Replaces the device copy only after explicit confirmation when it is a different vault. |
| MKBAK backup — restore (recovery recipient) | Implemented | Full Python-path checks: source fingerprint recomputed + must match one the user supplies independently, Ed25519 signature verified, downgrade refused, older-than-last-restored warns. |
| MKBAK backup — two-factor recovery (v2) | Implemented | Newer packages (format v2) open outside the app only with the recovery phrase AND the backup code together — either one alone fails, a wrong code fails closed. Older v1 packages still restore with the phrase alone and are labelled LEGACY on screen. |
| MKBAK backup — create a package | Implemented | The client holds its own device identity (enrolled in the vault by the user), exports MKBAK v2 packages, and shows the backup code exactly once with store-it-apart guidance. The code is never stored. |
| MKBAK backup — device-recipient restore | Implemented | An enrolled device restores its own vault's packages directly — no phrase, no code (inside the trust boundary). |
| Key-value pairing | Implemented | Targets (device / cloud-folder / export) pair by payload + fingerprint confirmation; the registry lives inside the encrypted vault. Backup exports wrap only to active pairings holding the export scope; a sync folder tied to a pairing saves/loads only while that pairing is active with the matching permission. Revoked, disabled, or expired pairings get nothing new. |
| Sync via a folder (your own cloud drive) | Implemented (desktop Chromium) | File System Access API: pick a folder, the app reads/writes `vault.mykey` + timestamped snapshots. Permission is re-checked every use; nothing runs in the background. When the folder is tied to a pairing, the pairing gate above applies to every save and load. |
| Sync on Firefox / Safari | Platform-blocked, fallback offered | No File System Access API: use Download + Open-file. The app says this plainly and never pretends to folder-sync. |
| Sync in the Android app | Implemented as an explicit file flow (verified behaviour) | The Android WebView provides no directory picker, so folder sync is never offered there — the capability is detected at runtime and the decision is unit-tested (`folderSyncOffered`: native ⇒ never). Instead, Settings labels the real flow in plain words: "Download my vault file" saves the encrypted vault into the user's cloud app via the share sheet; "Load a vault file from my cloud app" brings a newer copy back (different-vault loads ask first, then the app locks and the user unlocks the loaded copy). The app cannot silently sync on Android and does not claim to. |
| WebDAV sync | Deferred | No client ships WebDAV yet: the desktop provider interface anticipates it but no WebDAV provider is implemented anywhere (see the desktop SYNC_BACKUP.md). Both clients ship folder flows only in v1. Any future network provider is HTTPS-only with certificate verification always on — the rule is gated in tests/transport.test.ts and the desktop tests/test_transport_gates.py. |
| Vault home (Android) | Implemented (compile-verified; device pass pending) | The vault's canonical copy lives OUTSIDE the app: `MyKey/vault.mykey` in a folder the user picks once (Storage Access Framework; the grant persists, no storage permission is declared). The app is the file's opener; the copy inside the app is a working cache. Every save also writes the home file. On open, the two copies are reconciled by digest bookkeeping (the sync anti-rollback discipline): the copy that moved since they last agreed wins; if both moved, that is a conflict — the user picks at unlock and the other copy is preserved in the folder as a dated `vault-conflict-*.mykey`, never deleted. A different vault's home file is never touched. Uninstalling the app cannot take the vault: a fresh install offers "Open the vault found in <folder>". Web/PWA has no home (browser storage rules) and never offers it. Failures surface in Settings and as a one-line notice at the next unlock; they never block the inside save. Decision logic unit-tested (`tests/homecopy.test.ts`); native bridge compile-verified in CI; phone pass in docs/DEVICE_TEST_VAULT_HOME.md. |
| Any server, account, telemetry | Never | There is no MyKey server. CSP `connect-src 'none'` makes the client incapable of network calls. |

## Licensing

| Feature | Status | Notes |
|---|---|---|
| Free tier | Implemented | Up to 50 passwords + 4 connections per vault. Only the counts are limited — encryption, TOTP, sync, two-factor backups, pairing, rotation, skins and export are never gated. Full plain-language terms: LICENCE.md. |
| Licence key (paste) | Implemented | `MKLIC1.` token, Ed25519-signed by the MyKey Licence Authority (fingerprint EE62F41972E84A9ABDEDF14A565D3A0C9B65B996), verified fully offline against the embedded public key. Stored in the vault's encrypted settings (travels with the vault) and in the device slot (new vaults here start licensed); either copy alone suffices. |
| Connections pool | Implemented (counting + seam) | One pool per vault: active devices + agents (in the vault registries) + paired browsers (settings list — the seam the browser-extension client registers through). This client has no enrollment mutations of its own (devices/agents are enrolled from the desktop), so it counts and reports; the desktop enforces at enrollment. Blob/export pairing targets are destinations, never counted. |
| Grandfather rule | Implemented | A vault over a limit opens, reads, edits and exports fully; only adding pauses. Imports fill to the limit and report exactly how many were held back. |
| Buy a licence | Implemented (platform seam) | Web/PWA: opens the brand-configured page on usemykey.com. Android: never links out to a web checkout for the digital unlock (Google Play policy) — it explains buying on the website from another device; Play Billing plugs into `src/platform/purchase.ts` at this seam once the Play listing exists. Licence-key paste works in every build. |
| Tip jar | Implemented | Settings entry, separate from the licence; tips unlock nothing. Same platform seam as Buy. |

## Platform

| Feature | Status | Notes |
|---|---|---|
| Installable PWA, full offline after first visit | Implemented | Service-worker precache of the whole client; e2e-proven offline. |
| Android app (Capacitor, same build) | Implemented | Debug APK + unsigned release AAB from CI (see README — signing section). No INTERNET permission; Android cloud backup of app data disabled. |
| Fingerprint / face unlock (Android) | Implemented | Opt-in wrapped slot: a random wrap key lives in Android Keystore-backed, biometric-gated storage and unwraps the vault through its normal cryptographic path. Not a plaintext backdoor; turning it off deletes slot + key. Verify on a real device: CI cannot exercise biometrics. |
| Autofill in other apps & browsers (Android) | Implemented — device test pending | A native AutofillService answers fill requests with a single no-value dataset; tapping it opens MyKey, and only after unlock + an explicit entry tap does the chosen username/password cross back. Browsers match by web domain; apps match by package name bound to the entry PLUS the app's signing-certificate SHA-256 — a re-signed clone never matches silently (it is flagged and needs a fresh confirm, once). Inline (keyboard) presentation + dropdown; Save-to-MyKey on Android's save prompt routes to an in-app confirm screen. Locked vault ⇒ the dataset says only "Unlock MyKey". FLAG_SECURE on the app + auth screens; the autofill module contains no logging (CI-gated). CI has no emulator, so on-device verification follows docs/DEVICE_TEST_AUTOFILL.md — that step is the owner's. |
| Biometric unlock in the pure web PWA | Not offered (security decision) | A wrap key in web storage would be script-readable — a quiet backdoor. Password/phrase only on the web. |
| iOS app | Deferred | The PWA works in Safari (with the download/upload flows); a Capacitor iOS build is a later wave. |
| Auto-lock (quiet timer + when hidden) | Implemented | Defaults: 5 minutes, and lock when hidden — both changeable. |
| Accessibility | Implemented | Labels, focus management, aria-live status, contrast-checked palette, large targets, reduced-motion support. |
| Device display defaults | Implemented | First run follows the device: OS light/dark (reacts live to OS changes), OS font scaling (all sizes relative; the Android shell sets no WebView text-zoom override, so the system font scale applies), reduced-motion honoured. Any skin choice overrides until "Use device settings" is picked again. |
| Skins (themes) | Implemented | Settings → Appearance: Device (auto), Daylight, Midnight, Ocean, Forest, Dune, Chakra, High Contrast. Token-based — every colour comes from the active palette; picking applies instantly (the picker is its own live preview) and persists on-device. Every skin passes the WCAG AA contrast gate in CI (tests/themes.test.ts). Palette rationale: docs/DESIGN.md. |
| Password strength meter | Implemented | Five segments in the theme's meter ramp plus a word (Very weak → Excellent) — never colour alone. The Chakra skin's ramp follows the seven-chakra spectrum. |

## Help & About

| Capability | Status | Notes |
| --- | --- | --- |
| Built-in help ("How MyKey works") | Implemented | Ships inside the app bundle; fully offline. Canonical text lives in the desktop repo (HELP.md); this copy is byte-identical and the PWA CI fails on drift. |
| Common questions (FAQ) | Implemented | Same canonical-text rule (FAQ.md). Reachable from the locked/welcome screen — before sign-in — and from Settings. |
| About screen | Implemented | Version (from package.json), seller 2351485 ALBERTA INC., support info@aimlds.org, linked attribution with referral code 101EEK, licence summary, changelog pointer. Licence/tip block slot reserved (free-tier ruling pending — no purchase content yet). |
