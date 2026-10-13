// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// One-shot routing of a fill outcome from the app (TypeScript
// side, via the Capacitor plugin) back to the component waiting
// to answer the Android autofill session (AutofillAuthActivity).
// A token registers exactly one waiter; complete/cancel fire it
// exactly once and forget it. Pure Kotlin; JVM-testable.

package com.usemykey.mykey.autofill

sealed interface FillOutcome {
    data class Filled(val username: String, val password: String) : FillOutcome
    data object Canceled : FillOutcome
}

class FillResultRouter {
    private val waiters = HashMap<String, (FillOutcome) -> Unit>()

    @Synchronized
    fun register(token: String, waiter: (FillOutcome) -> Unit) {
        waiters[token] = waiter
    }

    @Synchronized
    fun unregister(token: String) {
        waiters.remove(token)
    }

    fun hasWaiter(token: String): Boolean = synchronized(this) { waiters.containsKey(token) }

    /** Fire the waiter with the fill values. Returns false when no
     * waiter exists (unknown or already-consumed token). */
    fun complete(token: String, username: String, password: String): Boolean {
        val waiter = synchronized(this) { waiters.remove(token) } ?: return false
        waiter(FillOutcome.Filled(username, password))
        return true
    }

    fun cancel(token: String): Boolean {
        val waiter = synchronized(this) { waiters.remove(token) } ?: return false
        waiter(FillOutcome.Canceled)
        return true
    }
}

/** The autofill dataset label hint. Shows "Unlock MyKey" unless
 * the app has reported an unlocked session that has not expired.
 * This is a LABEL ONLY — the real gate is the vault session on the
 * TypeScript side, which re-checks before releasing any value. */
class SessionHint {
    @Volatile var unlocked: Boolean = false
    @Volatile var expiresAtMs: Long = 0L

    fun label(nowMs: Long): String =
        if (unlocked && (expiresAtMs == 0L || expiresAtMs > nowMs)) {
            "Fill with MyKey"
        } else {
            "Unlock MyKey"
        }

    fun subtitle(nowMs: Long): String =
        if (unlocked && (expiresAtMs == 0L || expiresAtMs > nowMs)) {
            "Tap to choose a password"
        } else {
            "Tap to unlock your vault"
        }
}
