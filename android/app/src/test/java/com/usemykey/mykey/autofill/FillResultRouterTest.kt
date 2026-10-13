// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
package com.usemykey.mykey.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FillResultRouterTest {

    @Test fun completeFiresOnceWithValues() {
        val router = FillResultRouter()
        var got: FillOutcome? = null
        router.register("t1") { got = it }
        assertTrue(router.complete("t1", "alice", "s3cret"))
        assertEquals(FillOutcome.Filled("alice", "s3cret"), got)
        // Second completion: nobody waiting any more.
        assertFalse(router.complete("t1", "alice", "s3cret"))
    }

    @Test fun cancelFiresCanceled() {
        val router = FillResultRouter()
        var got: FillOutcome? = null
        router.register("t2") { got = it }
        assertTrue(router.cancel("t2"))
        assertEquals(FillOutcome.Canceled, got)
        assertFalse(router.cancel("t2"))
    }

    @Test fun unknownTokenIsIgnored() {
        val router = FillResultRouter()
        assertFalse(router.complete("nope", "a", "b"))
        assertFalse(router.cancel("nope"))
        assertFalse(router.hasWaiter("nope"))
    }

    @Test fun sessionHintLabels() {
        val hint = SessionHint()
        assertEquals("Unlock MyKey", hint.label(1_000L))
        hint.unlocked = true
        hint.expiresAtMs = 0L // no auto-lock configured
        assertEquals("Fill with MyKey", hint.label(1_000L))
        hint.expiresAtMs = 2_000L
        assertEquals("Fill with MyKey", hint.label(1_500L))
        // Auto-lock expiry mid-session revokes the unlocked label.
        assertEquals("Unlock MyKey", hint.label(2_500L))
        hint.unlocked = false
        hint.expiresAtMs = 0L
        assertEquals("Unlock MyKey", hint.label(1_000L))
    }
}
