// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// SHA-256 of an app signing certificate, lowercase hex — the
// value stored in an entry's android_app binding and compared on
// every app fill request. Pure function; JVM-testable.

package com.usemykey.mykey.autofill

import java.security.MessageDigest

object CertDigest {
    fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
