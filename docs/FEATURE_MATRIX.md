# Feature matrix — MyKey web client (PWA) + Android app

Exact status of every feature, as of the 1.2.0 blob wave plus
the password-rotation wave (2026-10-13). "Deferred" means deliberately not built yet, not
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
| Password age + rotation | Implemented | The day each password was set is stored inside the encrypted secret blob (never in plaintext, never in agent-visible listings) and shown in plain words ("Password set 13 Oct 2026 · change by 11 Apr 2027"). Changing the password restarts the clock; other edits never touch it; "Mark as changed today" covers website-side changes. Due after 180 days by default; Settings changes the vault default (or Never); the edit form sets a per-entry period or Never. Calm surfacing only: list badge, a count at unlock, and a Password rotation section. No notifications in this version (future work; no new permissions). Pre-feature vaults open with the creation date as the set date, else "date not recorded". Desktop-identical semantics, proven both directions through the fixture gate. |
| Notifications for due passwords | Deferred (future work) | Deliberately not in this wave: reminders are in-app only, and the app holds no notification permission. |
| Import from browsers (CSV) | Implemented | Chromium family (Chrome/Edge/Brave/Opera/Vivaldi/Arc/Google Password Manager) and Firefox exports are recognised by header signature; anything else gets a by-hand column mapping. Mirrors the desktop importer: (service, username) keys, same-password = duplicate (skipped), different password = conflict with a plain-language choice (keep mine / use the file's / keep both). The file is parsed locally and never uploaded; imported entries land encrypted in the vault. Other managers' formats (Bitwarden, 1Password, …) arrive through the generic mapping in this client; their dedicated parsers remain desktop-only for now. |
| Export to CSV (readable file) | Implemented, deliberately gated | Same columns as the desktop exporter (Service, Username, Password, URL, Notes). There is no one-tap path: a warning screen states in plain words that the file is unencrypted and readable by anyone, and the export button stays disabled until the user ticks the understanding checkbox. An empty vault exports nothing. |

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

| Capability | Status | Notes |
| --- | --- | --- |
| Built-in help ("How MyKey works") | Implemented | Ships inside the app bundle; fully offline. Canonical text lives in the desktop repo (HELP.md); this copy is byte-identical and the PWA CI fails on drift. |
| Common questions (FAQ) | Implemented | Same canonical-text rule (FAQ.md). Reachable from the locked/welcome screen — before sign-in — and from Settings. |
| About screen | Implemented | Version (from package.json), seller 2351485 ALBERTA INC., support info@aimlds.org, linked attribution with referral code 101EEK, licence summary, changelog pointer. Licence/tip block slot reserved (free-tier ruling pending — no purchase content yet). |

## Browser extension (sibling package, `extension/`)

| Feature | Status | Notes |
|---|---|---|
| Chromium (Chrome/Edge/Brave) + Firefox | Implemented | One TypeScript source, two manifests. Safari is out of scope for v1 (stated plainly in the extension README). Store-ready zips are CI artifacts. |
| Vault location | Desktop-only, by design | The extension holds no vault copy. It talks to the desktop app over native messaging; the vault never leaves the desktop process unencrypted. |
| Pairing | Implemented | House key-value pattern: extension id → X25519 public key + scopes (fill, save) + expiry + enabled. Human approves on the desktop after comparing fingerprints; revoked ids can never re-enroll; the extension pins the host key the same way. |
| Encryption in transit | Implemented | X25519 session agreement from the pairing keys, HKDF-SHA256 session keys per connection, AES-256-GCM per message, strict replay counters. Canonical-JSON byte compatibility with the Python host is pinned by shared known-answer vectors (CI regenerates + diffs). |
| Origin matching | Implemented, host-authoritative | Scheme + host + port exact. Subdomains only with the per-entry "also fill on subdomains" toggle (default off; the choice is stored in the desktop host store, not in the vault, so the Vault v3 format needed no new field). Lookalike hosts never match. |
| Fill behaviour | Implemented | Click-only (popup button or Ctrl+Shift+Y). Never on page load, never auto-submit, top frame only, iframes get nothing. TOTP fill is a separate explicit action. In-field icon: deferred to a later version (stated in the README). |
| Save-on-login capture | Implemented | Detects a successful login submit, prompts in-page (or in the popup after a cross-tab redirect), saves only on a click; updates report what changed. Payment forms are classified and never harvested; change-password capture is deferred in v1. |
| Generator | Implemented | Same alphabet and 16-character minimum as the desktop. |
| Clipboard rule | Implemented | Copy clears after the desktop-set time (60–300s, default 60), only when the clipboard still holds that copy (hash-checked, the value itself is never kept); cleared immediately on lock. Chromium clears via an offscreen document; Firefox in the background page. |
| Lock behaviour | Implemented | Desktop lock or auto-lock ends fills at once; the extension wipes matched-entry caches and any pending save. |
| Leak test suite | Implemented (merge gate) | Eight named gates (frames, origins, iframes, side channels, lock, revocation/expiry, form capture, zero-network + manifest audit) in `extension/tests/`, half of them also proven against the real Python host in-process and over real pipes. |
| In-page field icon | Deferred | v1 uses the popup/shortcut only; stated in the README. |
