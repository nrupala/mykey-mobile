// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).

package com.usemykey.mykey.autofill

/** Intent contract between the autofill components and MainActivity.
 * The token is a random one-time id — never a secret; it only
 * correlates a request with its in-memory context in
 * AutofillPendingStore. */
object AutofillIntents {
    const val ACTION_FILL = "com.usemykey.mykey.AUTOFILL_FILL"
    const val ACTION_SAVE = "com.usemykey.mykey.AUTOFILL_SAVE"
    const val EXTRA_TOKEN = "com.usemykey.mykey.AUTOFILL_TOKEN"
}
