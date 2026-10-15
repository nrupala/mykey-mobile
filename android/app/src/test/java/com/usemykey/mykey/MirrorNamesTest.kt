// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
package com.usemykey.mykey

import org.junit.Assert.assertEquals
import org.junit.Test

class MirrorNamesTest {
    @Test fun layoutConstants() {
        assertEquals("MyKey", MirrorNames.DIR_NAME)
        assertEquals("vault.mykey", MirrorNames.FILE_NAME)
    }

    @Test fun datedNamesPassThrough() {
        assertEquals(
            "vault-conflict-20261014-153022.mykey",
            MirrorNames.sanitizePreservedName("vault-conflict-20261014-153022.mykey"),
        )
    }

    @Test fun unsafeCharactersAreReplaced() {
        assertEquals(
            "vault_conflict_a_b.mykey",
            MirrorNames.sanitizePreservedName("vault conflict/a:b.mykey"),
        )
    }

    @Test fun blankFallsBack() {
        assertEquals("vault-conflict.mykey", MirrorNames.sanitizePreservedName(""))
    }
}
