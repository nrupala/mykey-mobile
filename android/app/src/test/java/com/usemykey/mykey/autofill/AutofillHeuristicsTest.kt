// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
package com.usemykey.mykey.autofill

import org.junit.Assert.assertEquals
import org.junit.Test

class AutofillHeuristicsTest {

    // InputType constants (android.text.InputType), inlined so the
    // JVM tests do not need the Android runtime.
    private val textPassword = 0x00000001 or 0x00000080 // CLASS_TEXT | VARIATION_PASSWORD
    private val textWebPassword = 0x00000001 or 0x000000e0
    private val textVisiblePassword = 0x00000001 or 0x00000090
    private val textEmail = 0x00000001 or 0x00000020

    @Test fun explicitHintsWin() {
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(hints = setOf("password"))))
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(hints = setOf("newpassword"))))
        assertEquals(FieldKind.USERNAME, AutofillHeuristics.classify(FieldSignals(hints = setOf("username"))))
        assertEquals(FieldKind.USERNAME, AutofillHeuristics.classify(FieldSignals(hints = setOf("emailaddress"))))
    }

    @Test fun htmlAutocompleteAndType() {
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(htmlAttrs = mapOf("autocomplete" to "current-password"))))
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(htmlAttrs = mapOf("type" to "password"))))
        assertEquals(FieldKind.USERNAME, AutofillHeuristics.classify(FieldSignals(htmlAttrs = mapOf("autocomplete" to "username"))))
    }

    @Test fun inputTypeVariations() {
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(inputType = textPassword)))
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(inputType = textWebPassword)))
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(inputType = textVisiblePassword)))
        assertEquals(FieldKind.USERNAME, AutofillHeuristics.classify(FieldSignals(inputType = textEmail)))
    }

    @Test fun nameKeywords() {
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(FieldSignals(viewId = "user_password")))
        assertEquals(FieldKind.USERNAME, AutofillHeuristics.classify(FieldSignals(viewId = "username")))
        assertEquals(FieldKind.USERNAME, AutofillHeuristics.classify(FieldSignals(labelText = "email address")))
        assertEquals(FieldKind.NONE, AutofillHeuristics.classify(FieldSignals(viewId = "search_box")))
        assertEquals(FieldKind.NONE, AutofillHeuristics.classify(FieldSignals()))
    }

    @Test fun passwordHintBeatsUsernameId() {
        // A password field whose id mentions the user still fills
        // as a password.
        val s = FieldSignals(hints = setOf("password"), viewId = "username_password")
        assertEquals(FieldKind.PASSWORD, AutofillHeuristics.classify(s))
    }
}
