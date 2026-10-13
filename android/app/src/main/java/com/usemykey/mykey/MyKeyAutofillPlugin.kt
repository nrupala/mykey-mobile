// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// Bridge between the vault UI (TypeScript) and the autofill
// machinery. The vault side asks what's pending, the user unlocks
// and chooses there, and the chosen values cross back here exactly
// once (completeFill) to answer the waiting autofill session.
// Nothing is logged; descriptors carry no credential values.

package com.usemykey.mykey

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.autofill.AutofillManager
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import com.usemykey.mykey.autofill.AutofillIntents
import com.usemykey.mykey.autofill.AutofillPendingStore

@CapacitorPlugin(name = "MyKeyAutofill")
class MyKeyAutofillPlugin : Plugin() {

    override fun load() {
        super.load()
        handleIntent(activity?.intent)
    }

    override fun handleOnNewIntent(intent: Intent) {
        super.handleOnNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        if (intent?.action == AutofillIntents.ACTION_FILL ||
            intent?.action == AutofillIntents.ACTION_SAVE
        ) {
            notifyListeners("autofillRequest", JSObject())
        }
    }

    @PluginMethod
    fun getPendingRequest(call: PluginCall) {
        val d = AutofillPendingStore.pendingDescriptor()
        if (d == null) {
            call.resolve(null)
            return
        }
        val obj = JSObject()
        obj.put("kind", d.kind)
        obj.put("token", d.token)
        d.packageName?.let { obj.put("packageName", it) }
        d.appLabel?.let { obj.put("appLabel", it) }
        d.webDomain?.let { obj.put("webDomain", it) }
        d.certSha256?.let { obj.put("certSha256", it) }
        call.resolve(obj)
    }

    @PluginMethod
    fun getPendingSaveValues(call: PluginCall) {
        val token = call.getString("token")
        val values = token?.let { AutofillPendingStore.saveValues(it) }
        if (values == null) {
            call.resolve(null)
            return
        }
        val obj = JSObject()
        obj.put("username", values.first)
        obj.put("password", values.second)
        call.resolve(obj)
    }

    @PluginMethod
    fun completeFill(call: PluginCall) {
        val token = call.getString("token")
        val username = call.getString("username") ?: ""
        val password = call.getString("password") ?: ""
        val done = token != null &&
            AutofillPendingStore.completeFill(token, username, password)
        val obj = JSObject()
        obj.put("completed", done)
        call.resolve(obj)
    }

    @PluginMethod
    fun cancelRequest(call: PluginCall) {
        call.getString("token")?.let { AutofillPendingStore.cancelFill(it) }
        call.resolve(JSObject())
    }

    @PluginMethod
    fun acknowledgeSave(call: PluginCall) {
        call.getString("token")?.let { AutofillPendingStore.dropSave(it) }
        call.resolve(JSObject())
    }

    @PluginMethod
    fun setSessionState(call: PluginCall) {
        val unlocked = call.getBoolean("unlocked") ?: false
        val expiresAtMs = (call.getDouble("expiresAtMs") ?: 0.0).toLong()
        context?.let {
            AutofillPendingStore.saveSessionHint(it, unlocked, expiresAtMs)
        }
        call.resolve(JSObject())
    }

    @PluginMethod
    fun serviceState(call: PluginCall) {
        val obj = JSObject()
        val supported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
        var enabled = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val manager = context?.getSystemService(AutofillManager::class.java)
            enabled = manager != null && manager.isAutofillSupported &&
                manager.hasEnabledAutofillServices()
        }
        obj.put("supported", supported)
        obj.put("enabled", enabled)
        call.resolve(obj)
    }

    @PluginMethod
    fun openAutofillSettings(call: PluginCall) {
        val activity = activity
        if (activity != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val manager = context?.getSystemService(AutofillManager::class.java)
            if (manager != null && manager.isAutofillSupported) {
                val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                    .setData(Uri.parse("package:" + activity.packageName))
                activity.startActivity(intent)
                call.resolve(JSObject())
                return
            }
        }
        // Fallback: the general settings home; the in-app text
        // tells the user the path from there.
        activity?.startActivity(Intent(Settings.ACTION_SETTINGS))
        call.resolve(JSObject())
    }
}
