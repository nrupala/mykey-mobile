// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// In-memory hand-off between the autofill service, the auth
// activity, and the Capacitor plugin (which talks to the vault in
// the TypeScript layer).
//
// HARD RULES:
//  - fill contexts hold only Android-side facts (target ids, app
//    identity, field ids) — never credential values;
//  - save contexts hold typed credentials ONLY because Android
//    hands them to the service in onSaveRequest; they live in
//    memory only, are never written to disk or logged, and are
//    dropped on acknowledge, on lock, or with the process;
//  - the session hint is two values in private preferences and
//    only chooses the dataset LABEL — it gates nothing.

package com.usemykey.mykey.autofill

import android.content.Context
import android.view.autofill.AutofillId
import java.util.UUID

data class FillContext(
    val token: String,
    val packageName: String?,
    val appLabel: String?,
    val webDomain: String?,
    /** SHA-256 (hex) of the requesting app's signing certificate.
     * Null for browser (web-domain) requests. */
    val certSha256: String?,
    val usernameIds: List<AutofillId>,
    val passwordIds: List<AutofillId>,
)

data class SaveContext(
    val token: String,
    val packageName: String?,
    val appLabel: String?,
    val webDomain: String?,
    val certSha256: String?,
    val username: String,
    val password: String,
)

/** What the TypeScript side needs to render its screens. Note the
 * fill descriptor carries no values at all, and the save
 * descriptor deliberately omits the credentials — those cross
 * only via takeSaveValues(), while the confirm screen is up. */
data class PendingDescriptor(
    val kind: String, // "fill" | "save"
    val token: String,
    val packageName: String?,
    val appLabel: String?,
    val webDomain: String?,
    val certSha256: String?,
)

object AutofillPendingStore {
    val router = FillResultRouter()
    val sessionHint = SessionHint()

    private val fills = LinkedHashMap<String, FillContext>()
    private val saves = LinkedHashMap<String, SaveContext>()

    fun newToken(): String = UUID.randomUUID().toString()

    @Synchronized
    fun putFill(ctx: FillContext) {
        fills[ctx.token] = ctx
    }

    @Synchronized
    fun fillContext(token: String): FillContext? = fills[token]

    @Synchronized
    fun dropFill(token: String) {
        fills.remove(token)
    }

    @Synchronized
    fun putSave(ctx: SaveContext) {
        saves[ctx.token] = ctx
    }

    @Synchronized
    fun saveValues(token: String): Pair<String, String>? =
        saves[token]?.let { it.username to it.password }

    @Synchronized
    fun dropSave(token: String) {
        saves.remove(token)
    }

    /** The newest outstanding request, fill or save. */
    @Synchronized
    fun pendingDescriptor(): PendingDescriptor? {
        val f = fills.values.lastOrNull()
        val s = saves.values.lastOrNull()
        // A save the user just made outranks nothing — order by
        // insertion: both maps are insertion-ordered; compare the
        // keys' positions by token creation order kept separately.
        return when {
            f != null && s == null -> f.toDescriptor()
            s != null && f == null -> s.toDescriptor()
            f != null && s != null -> {
                // Both pending: prefer the SAVE (it carries typed
                // credentials the user just entered; a fill can be
                // re-requested by tapping the field again).
                s.toDescriptor()
            }
            else -> null
        }
    }

    private fun FillContext.toDescriptor() = PendingDescriptor(
        "fill", token, packageName, appLabel, webDomain, certSha256,
    )

    private fun SaveContext.toDescriptor() = PendingDescriptor(
        "save", token, packageName, appLabel, webDomain, certSha256,
    )

    /** Complete a fill: fires the auth activity's waiter, which
     * builds the authenticated dataset. False = nobody waiting. */
    fun completeFill(token: String, username: String, password: String): Boolean {
        val fired = router.complete(token, username, password)
        if (fired) dropFill(token)
        return fired
    }

    fun cancelFill(token: String): Boolean {
        val fired = router.cancel(token)
        dropFill(token)
        return fired
    }

    // --- session hint persistence (label only) ---

    private const val PREFS = "mykey_autofill"
    private const val KEY_UNLOCKED = "session_unlocked"
    private const val KEY_EXPIRES = "session_expires_at_ms"

    fun loadSessionHint(context: Context) {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        sessionHint.unlocked = prefs.getBoolean(KEY_UNLOCKED, false)
        sessionHint.expiresAtMs = prefs.getLong(KEY_EXPIRES, 0L)
    }

    fun saveSessionHint(context: Context, unlocked: Boolean, expiresAtMs: Long) {
        sessionHint.unlocked = unlocked
        sessionHint.expiresAtMs = expiresAtMs
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_UNLOCKED, unlocked)
            .putLong(KEY_EXPIRES, expiresAtMs)
            .apply()
    }
}
