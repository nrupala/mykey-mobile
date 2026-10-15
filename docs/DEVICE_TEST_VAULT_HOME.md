# Device test — the vault's home (Android)

The vault's home keeps the canonical encrypted vault file outside
the app, in a folder you choose, so uninstalling MyKey can no
longer take your vault with it. The decision logic is unit-tested
and the native folder bridge is compile-verified in CI; this pass
proves the real folder picker, the real file, and the real
uninstall/reinstall cycle on your phone.

You need: the current MyKey APK installed, a master password you
know, and a folder you can also see in the Files app (a local
folder is fine; a cloud drive folder works too).

## 1. Give the vault a home

1. Open MyKey and unlock your vault (or create one).
2. Right after entering, MyKey offers "Give your vault a home".
   Tap **Choose a folder** and pick a folder you control.
   - Expected: you land in your vault as usual.
3. Go to **Settings → Your vault's home**.
   - Expected: a line naming your folder, with "updated …" and
     the time.
4. Open the Files app and look in the folder you picked.
   - Expected: a `MyKey` folder, and inside it one file:
     `vault.mykey`. It should be a few KB — it is your encrypted
     vault, the same file the app keeps inside itself.

## 2. Every save reaches the home

1. Back in MyKey, add a new password (any test entry) and save.
2. Lock the vault.
3. In the Files app, check `MyKey/vault.mykey` again.
   - Expected: its modified time is now (the save reached the
     home file).
4. Unlock and confirm the test entry is there.

## 3. Uninstall — the vault stays

1. Note your master password is the one from step 1 — you will
   need it; nothing else can open the file.
2. Uninstall MyKey from the phone (long-press → Uninstall).
3. In the Files app, check the folder again.
   - Expected: `MyKey/vault.mykey` is still there, unchanged.
     Uninstalling removed only the app.

## 4. Reinstall — the vault is found

1. Install the MyKey APK again and open it.
2. On the welcome screen, tap **I have a vault in a folder** and
   pick the same folder as before.
   - Expected: "Open the vault from its home", naming the
     folder.
3. Enter your master password and tap **Open this vault**.
   - Expected: your vault opens, with the test entry from
     step 2 in the list.
4. Check **Settings → Your vault's home**.
   - Expected: the same folder is shown as the home, and saves
     update it again (repeat step 2 quickly if you want proof).

## 5. Turning it off leaves the file alone

1. In **Settings → Your vault's home**, tap **Turn off**.
   - Expected: the line says the copy is no longer updated and
     stays in the folder until you delete it yourself.
2. Check the Files app: `vault.mykey` is still there. MyKey
   never deletes it — deleting it is your act, in the Files app.

## 6. Optional conflict drill (only if you want to see it)

This needs a second copy of the app (a second phone, or the same
vault opened on desktop with a home is not the same thing — skip
unless you have two Android devices signed into the same cloud
folder):

1. Give the same vault a home in the same cloud folder on both
   phones. Unlock on both, add a different entry on each, lock
   both.
2. Unlock either phone.
   - Expected: a "Two copies of your vault" card above the
     password field. Choose a copy to open; the other is kept in
     the folder as `vault-conflict-<date>-<time>.mykey` — check
     in the Files app that it exists.

## Report back

For each step: pass, or what the screen actually said. Steps 3–4
are the point of the feature — if the file is gone after
uninstall, or the reinstall offer does not find it, say exactly
which step and what the Files app showed.
