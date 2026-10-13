// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
package com.usemykey.mykey.autofill

import org.junit.Assert.assertEquals
import org.junit.Test

class CertDigestTest {
    @Test fun sha256KnownVector() {
        // FIPS 180-4 example: SHA-256("abc").
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            CertDigest.sha256Hex("abc".toByteArray(Charsets.UTF_8)),
        )
    }

    @Test fun sha256EmptyAndFormat() {
        val hex = CertDigest.sha256Hex(ByteArray(0))
        assertEquals(64, hex.length)
        assertEquals(hex.lowercase(), hex)
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            hex,
        )
    }
}
