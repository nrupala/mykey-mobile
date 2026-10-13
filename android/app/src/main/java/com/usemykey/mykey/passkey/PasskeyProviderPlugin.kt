// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey.passkey

import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin

/**
 * Capacitor surface for the passkey bridge ("MyKeyPasskey" in
 * src/platform/passkey.ts). Methods never touch key material:
 * they move the system's request JSON in, and the WebAuthn
 * response JSON out, plus metadata-only warm-index updates.
 */
@CapacitorPlugin(name = "MyKeyPasskey")
class PasskeyProviderPlugin : Plugin() {

    override fun load() {
        super.load()
        PasskeyBridge.onParked = { pending ->
            val data = JSObject()
            data.put("bridgeId", pending.id)
            data.put("kind", pending.kind)
            data.put("origin", pending.origin)
            data.put("requestJson", pending.requestJson)
            pending.callingPackage?.let { data.put("callingPackage", it) }
            notifyListeners("passkeyRequest", data, true)
        }
    }

    @PluginMethod
    fun getPendingRequest(call: PluginCall) {
        val ret = JSObject()
        val p = PasskeyBridge.latestPending()
        if (p == null) {
            ret.put("pending", org.json.JSONObject.NULL)
        } else {
            val obj = JSObject()
            obj.put("bridgeId", p.id)
            obj.put("kind", p.kind)
            obj.put("origin", p.origin)
            obj.put("requestJson", p.requestJson)
            p.callingPackage?.let { obj.put("callingPackage", it) }
            ret.put("pending", obj)
        }
        call.resolve(ret)
    }

    @PluginMethod
    fun completeRequest(call: PluginCall) {
        val bridgeId = call.getString("bridgeId")
        val responseJson = call.getString("responseJson")
        if (bridgeId == null || responseJson == null) {
            call.reject("bridgeId and responseJson are required")
            return
        }
        if (PasskeyBridge.complete(bridgeId, responseJson)) call.resolve()
        else call.reject("no pending passkey request with that id")
    }

    @PluginMethod
    fun failRequest(call: PluginCall) {
        val bridgeId = call.getString("bridgeId")
        val reason = call.getString("reason") ?: "cancelled"
        if (bridgeId == null) {
            call.reject("bridgeId is required")
            return
        }
        PasskeyBridge.fail(bridgeId, reason)
        call.resolve()
    }

    @PluginMethod
    fun setWarmIndex(call: PluginCall) {
        val items: JSArray = call.getArray("items") ?: JSArray()
        val parsed = ArrayList<PasskeyBridge.WarmItem>()
        for (i in 0 until items.length()) {
            val o = items.getJSONObject(i)
            parsed.add(
                PasskeyBridge.WarmItem(
                    credentialId = o.optString("credentialId"),
                    rpId = o.optString("rpId"),
                    username = o.optString("username"),
                    displayName = o.optString("displayName"),
                )
            )
        }
        PasskeyBridge.warmIndex = parsed
        call.resolve()
    }

    @PluginMethod
    fun clearWarmIndex(call: PluginCall) {
        PasskeyBridge.clearWarm()
        call.resolve()
    }
}
