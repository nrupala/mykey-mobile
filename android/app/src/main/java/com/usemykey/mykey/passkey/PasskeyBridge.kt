// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey.passkey

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * In-process bridge between the Credential Manager provider
 * (service + PasskeyActivity, native) and the Capacitor plugin
 * (which the TypeScript vault app talks to).
 *
 * A pending request carries NO secret material: the system's
 * request JSON (challenge, rpId, user info for creation) plus the
 * origin. The credential private keys never pass through here —
 * they are created and used inside the encrypted vault by the
 * TypeScript authenticator after the vault is unlocked.
 *
 * The warm index carries passkey METADATA only (credential id,
 * rpId, user names) so the system picker can list entries while
 * the vault is locked — the same disclosure class as entry
 * metadata autofill already exposes. It is memory-only and is
 * cleared when the vault locks.
 */
object PasskeyBridge {

    data class WarmItem(
        val credentialId: String, // base64url
        val rpId: String,
        val username: String,
        val displayName: String,
    )

    data class Pending(
        val id: String,
        val kind: String, // "create" | "get"
        val origin: String,
        val requestJson: String,
        val callingPackage: String?,
    )

    @Volatile
    var warmIndex: List<WarmItem> = emptyList()

    private val pending = ConcurrentHashMap<String, Pending>()
    private val callbacks = ConcurrentHashMap<String, (responseJson: String?, failReason: String?) -> Unit>()

    /** Called by the plugin whenever a request is parked, so the
     * app can be notified even if it was already running. */
    @Volatile
    var onParked: ((Pending) -> Unit)? = null

    fun park(
        kind: String,
        origin: String,
        requestJson: String,
        callingPackage: String?,
        callback: (responseJson: String?, failReason: String?) -> Unit,
    ): Pending {
        val p = Pending(UUID.randomUUID().toString(), kind, origin, requestJson, callingPackage)
        pending[p.id] = p
        callbacks[p.id] = callback
        onParked?.invoke(p)
        return p
    }

    // The system mediates one credential flow at a time; in
    // practice there is at most one live pending request.
    fun latestPending(): Pending? = pending.values.firstOrNull()

    fun allPending(): List<Pending> = pending.values.toList()

    fun complete(id: String, responseJson: String): Boolean {
        val cb = callbacks.remove(id) ?: return false
        pending.remove(id)
        cb(responseJson, null)
        return true
    }

    fun fail(id: String, reason: String): Boolean {
        val cb = callbacks.remove(id) ?: return false
        pending.remove(id)
        cb(null, reason)
        return true
    }

    fun clearWarm() {
        warmIndex = emptyList()
    }
}
