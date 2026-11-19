# MyKey proper-update specification

Status: specification, 2026-11-19. Owner of record: 2351485 ALBERTA INC.
This document defines what "the proper update" of MyKey means and how
each part is proven. A claim in this file counts only when the evidence
column names a test, a CI run, or a reported artifact hash.

## 1. Purpose comes first

MyKey is a secrets repository. Every change in this update is judged
against one question: does it keep secrets safe, findable, and usable
offline? Features that do not serve that question wait for a later
release.

## 2. The core-freeze standard

The update is complete only when every row below is proven.

| Area | Requirement | Evidence that proves it |
|---|---|---|
| Secrets-storage breadth | Logins, secure notes, TOTP seeds, passkeys, payment cards and identity records each round-trip through Vault v3 without loss, and unknown core fields survive a save. | Vitest round-trip suite per record type; the Python cross-check (`scripts/crosscheck_python.py`) passes on TS-written vaults. |
| Corrections | Every open defect logged against client 1.4.x is fixed or explicitly deferred with a reason. | CHANGELOG lists each fix; each fix ships with a regression test in the same PR. |
| Performance | Unlock at the header's Argon2id parameters completes in 2 s or less on the reference device; search over 1,000 entries returns in 100 ms or less. | Timed test in `tests/` with the measured numbers recorded in the PR. |
| Autofill behaviour | Autofill fills only the matching origin or package, never logs targets or outcomes, and refuses fields it cannot classify. | `testDebugUnitTest` autofill heuristics; the CI no-logging gate in `android.yml`; `docs/DEVICE_TEST_AUTOFILL.md` run on a real device with results attached. |
| Vault-law compliance | No network calls (`connect-src 'none'`), no INTERNET permission, no plaintext in storage, key buffers zeroed on lock, KDF parameters never downgraded. | CSP check in the PWA build; manifest check in CI; the existing vault tests. |

## 3. The release artifact

1. CI builds a release APK signed with the permanent MyKey release key
   (Actions secrets only; custody stays with 2351485 ALBERTA INC.).
2. The SHA-256 of `app-release.apk` and the signing-certificate digest
   are reported in the release notes and to the gate.
3. The E2E stage starts only on that reported artifact.

## 4. Build route

The Android workflow runs on the self-hosted T15 runner
(`[self-hosted, x64, familyci, t15]`). A queued run is not a build.

- Primary route: the T15 runner, once the family-CI lane confirms it is
  online and picking up jobs.
- Alternate route: a GitHub-hosted `ubuntu-latest` runner with
  `android-actions/setup-android`, using the same secrets. This route
  needs an owner decision because it moves the signing step off owned
  hardware.

## 5. Gate

Nothing counts as shipped until the release gate and Guardian Mesh
approve it, the docs in this repository match the shipped behaviour in
the same change, and the OpenSSF Best Practices floor holds.

## 6. Open decisions for the owner

- Approve the alternate build route if the T15 runner stays offline.
- Confirm the performance thresholds in section 2.
