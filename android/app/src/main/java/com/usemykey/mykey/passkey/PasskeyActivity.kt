// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey.passkey

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.annotation.RequiresApi
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import com.usemykey.mykey.MainActivity

/**
 * Selection-phase activity for the Credential Manager flows.
 *
 * It retrieves the provider request the system attached to the
 * entry's PendingIntent, parks it in PasskeyBridge, and opens the
 * main app. Unlocking the vault there is the user verification;
 * the app's passkey screen performs the ceremony and completes
 * (or fails) the bridge request. This activity then translates
 * the bridge outcome into the PendingIntentHandler result the
 * system expects and finishes.
 *
 * A plain framework Activity with a framework theme on purpose:
 * there is no AppCompat content here, just a status line and a
 * cancel button while the main app handles the real UI.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyActivity : Activity() {

    private var bridgeId: String? = null
    private var kind: String = "get"
    private var finished = false
    private val timeoutHandler = Handler(Looper.getMainLooper())
    private val timeout = Runnable { finishWithFailure("timeout") }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.gravity = Gravity.CENTER
        root.setPadding(48, 48, 48, 48)
        val label = TextView(this)
        label.text = "Continue in MyKey to finish with your passkey…"
        label.textSize = 16f
        root.addView(label)
        val cancel = Button(this)
        cancel.text = "Cancel"
        cancel.setOnClickListener { finishWithFailure("cancelled") }
        root.addView(cancel)
        setContentView(root)

        var requestJson: String? = null
        var origin = ""
        var callingPackage: String? = null

        val createReq = try {
            PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        } catch (e: Exception) {
            null
        }
        if (createReq != null) {
            kind = "create"
            val calling = createReq.callingRequest
            if (calling is androidx.credentials.CreatePublicKeyCredentialRequest) {
                requestJson = calling.requestJson
            }
            origin = MyKeyCredentialProviderService.webAuthnOrigin(createReq.callingAppInfo, requestJson)
            callingPackage = createReq.callingAppInfo?.packageName
        } else {
            val getReq = try {
                PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            } catch (e: Exception) {
                null
            }
            val option = getReq?.credentialOptions?.firstOrNull()
            if (option is androidx.credentials.GetPublicKeyCredentialOption) {
                requestJson = option.requestJson
            }
            origin = MyKeyCredentialProviderService.webAuthnOrigin(getReq?.callingAppInfo, requestJson)
            callingPackage = getReq?.callingAppInfo?.packageName
            kind = "get"
        }

        if (requestJson == null) {
            finishWithFailure("unreadable-request")
            return
        }

        val selectedCredential =
            intent.getStringExtra(MyKeyCredentialProviderService.EXTRA_CREDENTIAL_ID)
        // When a specific warm entry was tapped, tell the app which
        // credential was chosen (base64url id) via the request JSON
        // wrapper the app understands.
        val effectiveJson =
            if (kind == "get" && selectedCredential != null) {
                wrapWithSelection(requestJson, selectedCredential)
            } else {
                requestJson
            }

        val pending = PasskeyBridge.park(
            kind = kind,
            origin = origin,
            requestJson = effectiveJson,
            callingPackage = callingPackage,
        ) { responseJson, failReason ->
            runOnUiThread {
                if (responseJson != null) finishWithSuccess(responseJson)
                else finishWithFailure(failReason ?: "cancelled")
            }
        }
        bridgeId = pending.id

        val main = Intent(this, MainActivity::class.java)
        main.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        main.putExtra("passkey_bridge_id", pending.id)
        startActivity(main)

        timeoutHandler.postDelayed(timeout, TIMEOUT_MS)
    }

    private fun wrapWithSelection(requestJson: String, credentialIdB64Url: String): String {
        return try {
            val obj = org.json.JSONObject(requestJson)
            obj.put("mykey_selected_credential", credentialIdB64Url)
            obj.toString()
        } catch (e: Exception) {
            requestJson
        }
    }

    private fun finishWithSuccess(responseJson: String) {
        if (finished) return
        finished = true
        timeoutHandler.removeCallbacks(timeout)
        val result = Intent()
        try {
            if (kind == "create") {
                PendingIntentHandler.setCreateCredentialResponse(
                    result,
                    CreatePublicKeyCredentialResponse(responseJson),
                )
            } else {
                PendingIntentHandler.setGetCredentialResponse(
                    result,
                    GetCredentialResponse(PublicKeyCredential(responseJson)),
                )
            }
            setResult(RESULT_OK, result)
        } catch (e: Exception) {
            setResult(RESULT_CANCELED)
        }
        finish()
    }

    private fun finishWithFailure(reason: String) {
        if (finished) return
        finished = true
        timeoutHandler.removeCallbacks(timeout)
        bridgeId?.let { PasskeyBridge.fail(it, reason) }
        setResult(RESULT_CANCELED)
        finish()
    }

    override fun onDestroy() {
        timeoutHandler.removeCallbacks(timeout)
        super.onDestroy()
    }

    companion object {
        const val TIMEOUT_MS = 5 * 60 * 1000L
    }
}
