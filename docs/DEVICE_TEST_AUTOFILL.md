# Device test — Android autofill

CI builds the APK and runs every test that can run off-device
(matching rules, binding validation, masking, lock gating, JVM
unit tests for the native heuristics). CI has **no emulator**, so
the autofill service itself can only be proven on a real phone.
That step is the owner's: install the debug APK from the latest
Android CI run and walk this script. Expected time: ~10 minutes.

## Before you start

- A vault on the phone with at least two passwords: one whose
  Website is a site you can open in Chrome (e.g. github.com),
  and one you will link to an app in step 3.
- Fingerprint unlock ON or OFF — both paths get exercised below.

## 1. Turn the service on

1. Open MyKey → Settings → "Autofill in other apps". It should
   say autofill is off.
2. Tap "Open Android autofill settings". Android should open the
   picker (Passwords & accounts → Autofill service). Choose
   **MyKey**.
3. Back in MyKey Settings, the status should now say ON.

Pass: status text is honest at each step and the button lands on
the Android picker, not a dead end.

## 2. Fill in Chrome (web domain matching)

1. Lock MyKey (Lock now), then open Chrome to the login page of
   the site from your vault.
2. Tap the username field. The keyboard strip / dropdown should
   offer **"Unlock MyKey"** — and nothing else. No site name, no
   username.
3. Tap it. MyKey opens on the locked screen with a note that an
   app asked for a fill. Unlock (fingerprint or password).
4. The chooser should list the matching site's password first.
   Tap it — Chrome comes back with username and password filled.
   Nothing should submit by itself.

Pass: locked ⇒ label only; after unlock ⇒ the right entry fills;
no auto-submit.

## 3. Fill in an app + link it (package + signing key)

1. Open an app you have a saved password for (not yet linked).
2. Tap its password field → "Fill with MyKey" (or "Unlock
   MyKey" first) → chooser.
3. The entry is under "Show all passwords". Tap it: MyKey asks
   to **link** this password to the app, explaining the signing
   key check. Choose "Link and fill".
4. The app should be filled. Open the entry in MyKey: an
   "Android app" row shows the link, with an Unlink button.
5. Repeat the fill: this time the entry appears first, directly
   under the app's name, with no link question.

Pass: first use asks; second use offers directly; the binding is
visible (and removable) in the entry details.

## 4. Save a new login ("Save to MyKey")

1. In an app or in Chrome, sign in with a username/password that
   is NOT in MyKey. Android shows its save prompt — pick MyKey
   if asked which service.
2. MyKey opens on "Save this password in MyKey?" with the name,
   username and password prefilled. Edit the name if you like,
   then "Save to MyKey".
3. The entry is now in the vault (for an app it is already
   linked). Repeat once and choose "Don't save" — nothing is
   added.

Pass: confirm screen shows before anything is stored; declining
stores nothing.

## 5. Lock behaviour

1. With the vault unlocked, start a fill (tap a field, see the
   "Fill with MyKey" offer), then let the auto-lock time pass
   (or lock from inside MyKey).
2. The offer must read "Unlock MyKey" again, and no fill can
   happen without unlocking.

Pass: an expired session cannot fill.

## 6. Screenshots

1. With MyKey open on the unlock or an entry screen, try a
   screenshot and open the app switcher: the screenshot is
   blocked / the recents thumbnail is blank.

Pass: FLAG_SECURE holds.

## Reporting back

Note the step number and what differed (a photo of the phone
screen taken with another device helps). Autofill behaviour
varies a little by Android version and keyboard — say which
keyboard (Gboard/Samsung/…) showed the offer.
