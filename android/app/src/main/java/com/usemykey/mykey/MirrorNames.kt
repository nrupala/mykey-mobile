// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey

/** Names for the vault's home (see VaultMirrorPlugin). Pure and
 * Android-free so the rules are unit-testable on the JVM: the
 * home layout is <chosen folder>/MyKey/vault.mykey, and a
 * superseded copy is preserved next to it under a dated name
 * the app never deletes. */
object MirrorNames {
    const val DIR_NAME = "MyKey"
    const val FILE_NAME = "vault.mykey"

    /** Preserved-copy names cross from the web layer; keep only
     * characters every storage provider accepts. */
    fun sanitizePreservedName(name: String): String {
        val cleaned = buildString(name.length) {
            for (c in name) {
                append(if (c.isLetterOrDigit() || c == '.' || c == '-' || c == '_') c else '_')
            }
        }
        return cleaned.ifBlank { "vault-conflict.mykey" }
    }
}
