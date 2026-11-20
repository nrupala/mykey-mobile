# Codetopo Profile — MyKey Mobile (nrupala/mykey-mobile)

**What this is.** The agent-facing map of this repository, generated with
Codetopo 0.9.1 (local engine, `~/.cargo/bin/codetopo`) so an arriving agent
can see the machine — topology, trust boundaries, money surface — before it
submits or changes anything. Read this first; the graph snapshot beside it
(`snapshot.json`, `stats.json`) is the measured evidence.

- **Repo:** nrupala/mykey-mobile (public)
- **Commit profiled:** `a5faf1408c5a634f96a0a54093965790ed06a02d` (main)
- **Engine:** codetopo 0.9.1 + full-language program (engine built from codetopo main `d71509d1` — all sixteen program extractors merged) · index run 2026-11-19
- **Graph:** 125 files walked · 0 failed · 3,977 nodes · 10,870 edges · audit chain valid (3 entries, head `0567bd09…d23c`)
- **Nodes by kind:** external 2,322 · variable 487 · function 377 · method 355 · file 125 · module 125 · class 89 · interface 77 · doc 18 · package 2
- **Edges by kind:** calls 4,785 · reads 2,701 · contains 1,653 · defines 1,138 · imports 348 · writes 210 · inherits 27 · implements 8

## Coverage honesty

**Re-profiled 2026-11-19** with the full-language engine (Codetopo extractor program, 2026-11-18 ruling): every language this repo is written in is now extracted at symbol level. First profile: 2026-11-18 (Codetopo 0.9.1).

Codetopo now extracts every language in the full-language program (Rust, TypeScript/JavaScript, Python, Kotlin, C, Java, Go, Shell, C++, Swift, Ruby, R, Julia, C#, PHP, Scala, Haskell, Elixir, Lua), plus Markdown as Doc nodes. The TypeScript client and Python fixture generators are extracted as before, and the Android native layer named as the residual in the first profile is now in the graph at full symbol level: the 20 Kotlin files under `android/app/src/main/java/com/usemykey/mykey/` (`MainActivity`, the autofill service and its helpers, the passkey credential-provider service, and their tests — Kotlin extractor, program PR #153) plus the one Java file (`SensitiveClipboardPlugin.java` — Java extractor, program PR #156). **Still not in the graph:** the Gradle build scripts (Groovy/Kotlin DSL — not a program language) and XML/JSON configuration; read them directly.
## Topology

One TypeScript client for MyKey, the zero-trust password manager,
serving two surfaces from a single source of truth (README): an
installable, fully offline PWA, and the Android app (Capacitor wrapping
the exact same build). There is no MyKey server.

- `src/vault/` — the proprietary Vault v3 core (a port of the desktop
  engine's file format): `vault.ts` (engine: slots, core, entries,
  bundles, CRUD), `crypto.ts` (AES-256-GCM, Argon2id, PBKDF2),
  `recovery.ts` (BIP-39 phrase keys + backup keypair), `totp.ts`
  (RFC 6238 TOTP), `backup.ts` (MKBAK backup packages), `pairings.ts`,
  `device.ts`, `licence.ts` (licence-key verification), `passkey.ts`,
  `autofill.ts`, `csvio.ts`, `encoding.ts`, `store.ts` (IndexedDB —
  ciphertext + local identity keys only).
- `src/platform/` — the Apache-2.0 platform shell: `biometric.ts`
  (Android Keystore-backed fingerprint unlock), `filesync.ts`,
  `clipboard.ts`, `autofill.ts`, `passkey.ts`, `purchase.ts` (the
  purchase seam — see Money surface).
- `src/ui/` — the interface: `app.ts` (the whole UI, plain DOM),
  `themes.ts`, `appearance.ts`, `help.ts`, `markdown.ts`.
  `src/brand.ts` is the only place brand/identity strings live.
- `extension/src/` — the browser extension: `background.ts` /
  `background-entry.ts`, `content.ts` / `content-entry.ts`,
  `channel.ts` (the extension↔host channel), `keys.ts`, `origin.ts`,
  `clipboard.ts`, `generator.ts`, `popup.ts`, `options.ts`, `api.ts`.
- `android/` — the Capacitor Android project (Kotlin residual, above):
  autofill service, passkey credential provider, vault-mirror and
  clipboard plugins. Hardened per README: no INTERNET permission, OS
  backup disabled.
- Tests: `tests/` (vault, licence, passkey, transport, interop and
  more), `extension/tests/`, `e2e/smoke.spec.ts` (Playwright).

## Trust boundaries

This repo **is** a trust boundary: a password manager's client. The
load-bearing facts, all from the README/source:

- **No network by construction:** the client makes no network calls at
  all — the Content Security Policy (`connect-src 'none'`) makes that a
  property of the code, not a promise. Every device holds only
  ciphertext; IndexedDB holds exactly the encrypted vault file bytes —
  no plaintext, no keys, no passwords in web storage, nothing in logs.
- **Crypto:** AES-256-GCM everywhere; master/recovery slots wrap the
  vault key under Argon2id with parameters read from the vault header,
  never downgraded; per-entry data keys; entry ciphertext hashes sealed
  in the core and verified before any entry decrypts. Primitives are
  WebCrypto, `@noble/*`, `@scure/bip39`, `hash-wasm` — no hand-rolled
  cryptography. Master-password and TOTP-secret material (field names
  only: `password`, `totp_secret`) exists only inside the encrypted
  vault.
- **Fingerprint unlock (Android, opt-in):** one extra wrapped vault slot
  whose random wrap key sits in Keystore-backed, biometric-gated
  credential storage (bridge names only: `NativeBiometric.getSecureCredentials`
  / `setCredentials` / `deleteCredentials`); biometrics alone never
  expose plaintext, and the pure web PWA does not offer this.
- **Licence verification:** signed licence keys verified client-side
  against the licence authority's public material (names only:
  `LICENCE_PUBLIC_KEY_B64`, `LICENCE_AUTHORITY_FINGERPRINT` in
  `src/vault/licence.ts`). The authority's private signing key is not
  in this repo.
- **Backup packages (MKBAK):** the source fingerprint is recomputed
  from the package's keys and must match a fingerprint the user
  supplies independently (a package cannot vouch for itself); the
  Ed25519 package signature must verify.
- **Build signing:** Android signing is referenced by environment
  variable **names** only (names only: `MYKEY_KEY_PASSWORD`,
  `MYKEY_STORE_PASSWORD`) — no values in the repo. Test fixtures use
  synthetic passwords/keys generated for tests; they protect nothing.
- **Blast radius:** `src/vault/vault.ts` and `src/vault/crypto.ts` are
  the hubs — a change there changes the on-disk format every device
  trusts. The extension `channel.ts`/`origin.ts` pair is the
  extension's trust seam (origin checks before any credential moves).

## Money surface

One deliberate seam, and no payment machinery in the client:

- `src/platform/purchase.ts` — `buyLicence()` and `tipJar()`. On the
  web/PWA build, Buy and Tip open the brand-configured pages on the
  product site (config names only, in `src/brand.ts`: `licenceBuyUrl`,
  `tipUrl`, `domain`). On the Android build they **never** open a web
  checkout (Google Play policy, stated in the module header): they
  explain that the licence is bought on the website from another device
  and the key pasted in; when a Play listing exists, Play Billing plugs
  into `buyLicence()` at exactly this seam.
- No Stripe/Paddle SDK, no checkout-session code, no webhook handler
  and no card handling exists anywhere in this repo (grep evidence
  below: `stripe`/`paddle`/`webhook` hit only docs prose and test
  fixtures using example domains). The money moves on the product
  website / (future) Play Billing, never through this client.

Greps used for this section and Trust boundaries (names only, no values
copied): `stripe|paddle|secret|token|api_key|auth|password|billing|checkout|webhook`
over the TS/Python/Markdown/JSON sources.

## How an agent should approach

1. Read `README.md` (architecture + security model), `LICENSING.md` and
   `docs/FEATURE_MATRIX.md`, then this profile, then the snapshot.
2. Use `codetopo` queries against `graph.db`/the snapshot (descendants,
   blast-radius, symbol) before editing — especially around
   `src/vault/` and the extension channel.
3. For the Android Kotlin layer, read the sources directly — the graph
   cannot see them yet (see Coverage honesty). Do not claim graph
   evidence for Kotlin behaviour.
4. Never add credential values, real vault data, account identifiers or
   key material to any file here — names and paths only. Never weaken
   the `connect-src 'none'` posture or the KDF/header rules to make a
   test pass.
5. Regenerate this profile (below) whenever the code changes.

## Regeneration

`docs/codetopo-profile/refresh.sh` (in this pack) re-downloads the repo
at a named ref, re-runs the index, and rewrites `snapshot.json`,
`stats.json` and the header block inputs of this profile. Regenerate at
every release / material change to the vault core or the purchase seam.
