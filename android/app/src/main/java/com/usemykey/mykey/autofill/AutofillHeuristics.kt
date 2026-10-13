// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// Field classification for the autofill service. Pure Kotlin over
// a plain signal record — no Android types — so the rules are
// JVM-unit-testable. The service maps each ViewNode to a
// FieldSignals and asks here whether it is a username field, a
// password field, or neither.

package com.usemykey.mykey.autofill

enum class FieldKind { USERNAME, PASSWORD, NONE }

data class FieldSignals(
    /** android.view.View autofill hints, lowercased. */
    val hints: Set<String> = emptySet(),
    /** resource id entry (ViewNode.idEntry), lowercased. */
    val viewId: String = "",
    /** inputType bitmask (android.text.InputType). */
    val inputType: Int = 0,
    /** html attributes (web forms): name -> value, lowercased. */
    val htmlAttrs: Map<String, String> = emptyMap(),
    /** visible hint / label text, lowercased. */
    val labelText: String = "",
)

object AutofillHeuristics {

    // InputType masks (android.text.InputType).
    private const val TYPE_MASK_CLASS = 0x0000000f
    private const val TYPE_MASK_VARIATION = 0x00000ff0
    private const val TYPE_CLASS_TEXT = 0x00000001
    private const val VARIATION_PASSWORD = 0x00000080
    private const val VARIATION_VISIBLE_PASSWORD = 0x00000090
    private const val VARIATION_WEB_PASSWORD = 0x000000e0
    private const val VARIATION_EMAIL_ADDRESS = 0x00000020
    private const val VARIATION_WEB_EMAIL_ADDRESS = 0x000000d0

    fun classify(s: FieldSignals): FieldKind {
        // 1. Explicit autofill hints win — the app/browser told us.
        if (s.hints.contains("password") || s.hints.contains("newpassword") ||
            s.hints.contains("currentpassword")
        ) return FieldKind.PASSWORD
        if (s.hints.contains("username") || s.hints.contains("emailaddress")) {
            return FieldKind.USERNAME
        }

        // 2. Web form autocomplete attribute.
        when (s.htmlAttrs["autocomplete"]?.trim()) {
            "current-password", "new-password" -> return FieldKind.PASSWORD
            "username", "email" -> return FieldKind.USERNAME
        }
        val htmlType = s.htmlAttrs["type"]?.trim()
        if (htmlType == "password") return FieldKind.PASSWORD

        // 3. Text inputType variations.
        if ((s.inputType and TYPE_MASK_CLASS) == TYPE_CLASS_TEXT) {
            when (s.inputType and TYPE_MASK_VARIATION) {
                VARIATION_PASSWORD, VARIATION_VISIBLE_PASSWORD, VARIATION_WEB_PASSWORD ->
                    return FieldKind.PASSWORD
                VARIATION_EMAIL_ADDRESS, VARIATION_WEB_EMAIL_ADDRESS ->
                    return FieldKind.USERNAME
            }
        }

        // 4. Name/id/label keywords — password first so a field
        // like "user_password" classifies as the password.
        val words = s.viewId + " " + s.labelText + " " + (s.htmlAttrs["name"] ?: "")
        if (words.contains("password") || words.contains("passwd") ||
            words.contains("pwd")
        ) return FieldKind.PASSWORD
        if (words.contains("username") || words.contains("user_name") ||
            words.contains("email") || words.contains("login") ||
            words.contains("user id") || words.trim() == "user"
        ) return FieldKind.USERNAME
        return FieldKind.NONE
    }
}
