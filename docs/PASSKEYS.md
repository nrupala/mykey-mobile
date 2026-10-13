# Passkeys in MyKey — design, scope, and honest limits

Passkey wave (2026-10-13). This document states exactly what v1
does, what it deliberately does not do, and where the limits are.
The desktop engine's companion summary is `PASSKEYS.md` in the
desktop repository; the format contract is identical in both.

## What a passkey is here

A WebAuthn credential stored as a Vault v3 entry of kind
`"passkey"`. The entry's WebAuthn record — relying party id, user
id/name/display name, credential id, algorithm, public key,
**credential private key**, sign_count, transports, creation
time, AAGUID, backup flags — is encrypted in its own `passkey`
blob under its own per-entry key class (DEK_passkey), exactly the
way passwords sit under DEK_pw and TOTP secrets under DEK_totp.
A SHA-256 hash of the passkey blob's ciphertext is sealed in the
vault core (`passkey_hashes`, kept separate from `entry_hashes`
so vaults written before passkey support verify byte-for-byte).
Opening a vault whose passkey blob is missing its sealed hash,
whose hash does not match, or whose DEK_passkey is absent fails
closed with a corruption error.

The entry presents as service = rp_id, username = user_name,
empty password. (service, username) uniqueness applies across
kinds. Passkeys are ordinary entries for counting: **they count
toward the 50-entry free tier exactly like logins** — the cap
counts entries, and no security feature is ever the thing capped.

## Security rules (enforced in code, covered by tests)

- **Private keys are secrets.** They exist only inside the
  encrypted passkey blob (at rest), inside an unlocked session's
  memory (in use), and inside encrypted vault backups as part of
  the vault file. They are never logged, never copied to the
  clipboard, never exported to CSV (CSV export skips passkey
  entries and says so), and never returned by any API outside the
  vault record.
- **Agent bundles never contain passkeys.** DEK_passkey is never
  placed in a bundle, and passkey-kind entries are excluded from
  bundle targets and service maps in both engines — belt and
  braces. An agent token with the vault file cannot decrypt,
  list-target, or use a passkey. **Agent passkey use is a later,
  separately gated design. It is not built, and no agent surface
  in v1 can touch a passkey.**
- **RP ID verification is the phishing defence and always runs.**
  For web origins, the requested rpId must equal the origin host
  or be a suffix of it at a dot boundary (`login.example.com`
  under rpId `example.com` is allowed; `evil-example.com` and
  rpId `ample.com` are refused). An rpId that is an IP literal,
  or carries a port/path, is refused. For native Android callers
  (origin `android:apk-key-hash:…`) the OS has already bound the
  rpId to the calling app (asset links / privileged caller), and
  that binding is what is relied on — stated here plainly because
  it is a platform trust, not something this code re-checks.
  The origin itself is computed in the Android provider service:
  for a browser caller (package names are OS-attested and cannot
  be spoofed) it is `https://` + the rpId from the request — the
  browser bound that rpId to the page before dispatching; for a
  native app caller it is `android:apk-key-hash:` + the base64
  SHA-256 of the calling app's signing certificate, read from
  the OS-provided calling-app info. Anything unverifiable yields
  an empty origin and the ceremony is refused — never asserted
  against a guessed origin.
  Determining that a web rpId is a *registrable* domain uses the
  suffix rule above; a full public-suffix-list check is an
  approximation gap recorded here honestly.
- **User verification is the vault unlock.** Every create and
  every assertion requires an unlocked vault, and the unlock that
  immediately precedes the ceremony (master password, recovery
  phrase, or the fingerprint device slot) is the user
  verification. There is no separate passkey PIN.
- **Attestation is "none", honestly.** fmt `none`, empty
  attStmt, zero AAGUID. MyKey is a software authenticator with no
  hardware attestation key, and it never fakes one. Sites that
  require attestation (some enterprise policies) will refuse
  MyKey passkeys — that is their right and our design.
- **Algorithms.** ES256 (ECDSA P-256, SHA-256) is always
  available; signatures are produced in P1363 form by WebCrypto
  and converted to DER for the WebAuthn response. EdDSA (-8) is
  offered only when the platform's WebCrypto genuinely provides
  Ed25519.

## Sign counts and clone detection — what sync means

sign_count starts at 0 at creation and increments on every
assertion, persisted in the vault before the signature is made
(a burned count is harmless; a reused count is a clone signal).

Because the vault file syncs, **the count is only as fresh as the
vault copy**. Two devices working from the same vault copy can
present the same next count; a relying party that tracks counts
will see a non-increasing count and may treat the credential as
cloned — that is the WebAuthn clone-detection contract working
as designed, and restored-from-backup sign-ins can trip it.
MyKey adds a local warning: each device keeps a high-water mark
of the highest count it has seen per credential (counts only, in
device-local storage). If a record's count is ever *below* the
high-water mark at unlock, the app warns plainly: an older vault
copy was restored, or a copy of the passkey exists elsewhere.
Neither mechanism is hidden; both are surfaced, not silent.

Backup flags BE/BS are set in authenticator data: the key *is*
backed up — inside the encrypted vault and its encrypted
backups. That is true, and it is why the flags are honest.

## Android use (Credential Manager provider)

The Android app registers as a Credential Manager provider
(API 34+):

- **Create:** a site/app "create a passkey" request offers one
  entry, "MyKey vault". Selecting it opens MyKey; after unlock,
  a plain screen names the site and user and asks once more;
  approval creates the credential in the vault and returns the
  WebAuthn registration response to the caller.
- **Sign in:** the provider offers warm entries (below) and an
  "Unlock MyKey" action. Selecting either opens MyKey; after
  unlock, the user picks the account in the app; the assertion
  is signed inside the vault session and returned.
- **Warm index:** while the vault has been unlocked at least
  once since app start, the provider process holds passkey
  *metadata* in memory (credential id, rpId, user names) so the
  system picker can name entries. No key material is ever in the
  index. Locking the vault clears it.
- One deliberate deviation to know about: when the request came
  in through the "Unlock MyKey" authentication action, v1
  completes it with the final assertion after the in-app pick,
  rather than returning a fresh begin-phase response for a
  second system picker round. The device test script
  (`DEVICE_TEST_PASSKEYS.md`) exercises this path first; if a
  device build refuses it, that is the first thing to change.

## Client roles in v1

- **Mobile (this client):** create, store, use, delete.
- **Desktop (Python):** store (the format is shared), list
  read-only, delete. Creation and use are phone/browser-first;
  the desktop does not act as an authenticator in v1.
- **Older clients:** a client from before this wave does not
  know the `passkey` blob and will drop passkey material if it
  re-saves the vault. Both current clients are required for
  vaults that hold passkeys — do not round-trip a passkey vault
  through a pre-passkey client.

## Out of scope in v1 (not built)

- Browser-extension WebAuthn bridging (the extension wave owns
  its own design; nothing here speaks for it).
- CXP/CXF passkey transfer import/export.
- iOS credential provider.
- Agent passkey use (see above — separately gated future design).
- Desktop as authenticator; Windows Hello / Touch ID platform
  authenticator integration of any kind.
- Password-credential provider role on Android (MyKey provides
  passkeys only; vault passwords stay in the app in v1).
