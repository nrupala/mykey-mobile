# Device test — passkeys (for Nrupal)

The Credential Manager flows in this wave are **compile-verified
in CI only**. No emulator or device run exists on our side:
Android's credential provider UI needs a real device profile,
and the sandbox has no Android SDK. This script is the
verification — please run it on your phone with the APK from
this wave.

You need: the new MyKey APK installed, and a browser or app that
offers passkeys (the demo below uses a public test site).

## 1. Turn MyKey on as a passkey provider

1. Open Android **Settings → Passwords, passkeys & autofill**
   (wording varies slightly by phone maker).
2. Under the preferred service / passkey providers list, enable
   **MyKey**. If MyKey is not listed at all, stop and report that
   — the provider registration did not take.

## 2. Create a passkey with MyKey

1. In your browser, go to **webauthn.io** and enter a username
   (any test name).
2. Tap **Register**. When the system asks where to save the
   passkey, choose **MyKey vault**.
3. MyKey opens. Unlock the vault (fingerprint or password — that
   unlock is the verification).
4. The passkey screen names the site and the user. Tap
   **Create passkey**.
5. Back in the browser, the site should say the registration
   succeeded.

## 3. Check it in the app

1. Open MyKey, unlock, and find the entry for **webauthn.io**
   with the **Passkey** badge.
2. Open it: it shows the site, the user, the date, and
   "Times used: 0". There are no password fields — that is
   correct.

## 4. Sign in with it

1. On webauthn.io, sign out if needed, enter the same username,
   and tap **Authenticate / Login**.
2. Choose the MyKey passkey (either the named entry or
   "Unlock MyKey", then pick the account in the app).
3. Unlock if asked, tap **Sign in as …**.
4. The site should sign you in.
5. Re-open the passkey in MyKey: **Times used** should now be 1
   (or one more than before).

## 5. Delete and confirm it stops working

1. In MyKey, open the passkey entry and tap **Delete** (twice —
   the second tap confirms).
2. On webauthn.io, try to authenticate again with that username:
   it must now fail (no passkey found), because the only copy
   was in your vault.
3. Optional cleanup: remove the credential on the site too if it
   keeps a stale listing.

## 6. Revoke the provider (optional)

- Settings → Passwords, passkeys & autofill → turn **MyKey**
  off as a provider. MyKey should disappear from passkey pickers
  everywhere.

## What to report back

- Any step where the system picker does not offer MyKey.
- Step 4 especially: whether choosing "Unlock MyKey" completed
  the sign-in, or the picker complained / looped (that path has
  a known v1 deviation — see docs/PASSKEYS.md — and your result
  decides the v1.1 fix).
- Anything that shows a password field, a private key, or other
  secret on a passkey screen: that would be a defect, full stop.
