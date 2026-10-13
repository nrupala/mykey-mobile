# Transport security — MyKey web + Android client (summary)

The full inventory lives in the desktop repository:
`docs/TRANSPORT_SECURITY.md` in `nrupala/mykey`. This is the
summary for this client. The properties below are gated by
`tests/transport.test.ts` in this repo (and
`tests/test_transport_gates.py` on the desktop): a change that
weakens one fails CI until it is deliberate and documented.

## This client's posture

- **No network surface at all.** The client source contains no
  `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, or
  beacon call — gated by test. The page CSP is
  `default-src 'self'` with **`connect-src 'none'`**: the running
  app cannot make a network call, to us or anyone.
- **Android:** the manifest requests **no permissions** (no
  INTERNET) and sets `allowBackup="false"`. Web content is
  packaged in the app, never fetched.
- **Service worker:** precache of the app shell only,
  `runtimeCaching: []` — it never caches network data, because
  there is no network data. The one network moment in a PWA's
  life is the browser fetching an updated shell from wherever
  the user installed it; that channel's integrity is the host's
  HTTPS, and the shell contains no user data.
- **What leaves the device is ciphertext.** Export and the
  Android share sheet hand out exactly one kind of file: the
  encrypted vault container (`MKVLT` v3, AES-256-GCM under
  per-entry keys) or an MKBAK backup package. A test serializes
  a vault holding known secrets and asserts the bytes are the
  `MKVLT` container and contain no password, TOTP secret, or
  username in the clear.
- **Sync is a file flow, honestly labelled.** Folder sync (File
  System Access API, desktop Chromium) moves the same encrypted
  vault file; Android uses explicit save/open through the share
  sheet and file pickers because the WebView has no directory
  picker. The container is self-verifying (HMAC verifier +
  AES-256-GCM tags checked at open); a tampered file refuses to
  open. Desktop sync adds Ed25519-signed manifest chains on top
  (see the full document).
- **The one deliberate plaintext path is fenced.** CSV export
  sits behind an explicit warning + confirm checkbox that keeps
  the export button disabled until checked — gated by test.
  CSV import is read locally and lands only inside the
  encrypted vault.
- **Clipboard:** copied secrets are marked sensitive on Android
  and auto-clear after a short user-set delay and immediately
  on lock.
- **No telemetry, no analytics, no update checks.** The only
  external references in the client are the user-invoked
  allowlist, gated by test: the Apache licence text in headers,
  the attribution links (`nrupalakolkar.com`, `muse.ai/join`),
  and the support address (`info@aimlds.org`). Licence
  verification is fully offline.
- **No WebDAV (yet), anywhere.** No client ships a network sync
  provider. The standing rule for any future one: HTTPS only,
  plain HTTP refused except explicit localhost, and TLS
  certificate verification always on — no off switch, in any
  option.

## Residuals (same as the full document)

Your cloud/folder provider sees ciphertext plus metadata
(existence, sizes, timing) — content secrecy never depends on
the provider. Revocation cannot reach backup copies already
exported. Clipboard contents are visible to the OS and the
active keyboard during the clear window.
