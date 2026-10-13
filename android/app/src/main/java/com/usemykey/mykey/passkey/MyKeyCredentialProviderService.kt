// Proprietary — Copyright (c) 2026 2351485 ALBERTA INC. All rights reserved.

package com.usemykey.mykey.passkey

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.usemykey.mykey.R
import org.json.JSONObject

/**
 * The Credential Manager provider service (query phase).
 *
 * Create: one entry — "MyKey vault". Get: passkey entries from
 * the in-memory warm index (metadata only, present only while
 * the vault has been unlocked at least once since app start),
 * plus an "Unlock MyKey" authentication action that works from
 * any state. All entries fire PasskeyActivity, which hands the
 * full request to the vault app; the actual WebAuthn ceremony
 * runs in the TypeScript authenticator on the unlocked vault.
 *
 * The Credential Manager provider APIs require API 34+.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class MyKeyCredentialProviderService : CredentialProviderService() {

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request is BeginCreatePublicKeyCredentialRequest) {
            val entry = CreateEntry(
                "MyKey vault",
                pendingIntent(ACTION_CREATE, requestCode = 41001),
            )
            callback.onResult(BeginCreateCredentialResponse(listOf(entry)))
        } else {
            callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        var handled = false
        val builder = BeginGetCredentialResponse.Builder()
        for (option in request.beginGetCredentialOptions) {
            if (option !is BeginGetPublicKeyCredentialOption) continue
            handled = true
            val rpId = try {
                JSONObject(option.requestJson).optString("rpId")
            } catch (e: Exception) {
                ""
            }
            if (rpId.isNotEmpty()) {
                for (item in PasskeyBridge.warmIndex.filter { it.rpId == rpId }) {
                    builder.addCredentialEntry(
                        PublicKeyCredentialEntry.Builder(
                            applicationContext,
                            item.username,
                            pendingIntent(
                                ACTION_GET,
                                requestCode = 42000 + (item.credentialId.hashCode() and 0x3ff),
                                credentialId = item.credentialId,
                            ),
                            option,
                        )
                            .setDisplayName(item.displayName.ifEmpty { item.username })
                            .setIcon(android.graphics.drawable.Icon.createWithResource(applicationContext, R.mipmap.ic_launcher))
                            .build()
                    )
                }
            }
        }
        if (!handled) {
            callback.onError(GetCredentialUnknownException())
            return
        }
        builder.addAuthenticationAction(
            AuthenticationAction(
                "Unlock MyKey",
                pendingIntent(ACTION_GET, requestCode = 42001),
            )
        )
        callback.onResult(builder.build())
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // No sticky selection state is kept; nothing to clear.
        callback.onResult(null)
    }

    private fun pendingIntent(action: String, requestCode: Int, credentialId: String? = null): PendingIntent {
        val intent = Intent(action).setPackage(packageName)
        intent.setClass(this, PasskeyActivity::class.java)
        if (credentialId != null) intent.putExtra(EXTRA_CREDENTIAL_ID, credentialId)
        return PendingIntent.getActivity(
            applicationContext,
            requestCode,
            intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    companion object {
        const val ACTION_CREATE = "com.usemykey.mykey.passkey.CREATE"
        const val ACTION_GET = "com.usemykey.mykey.passkey.GET"
        const val EXTRA_CREDENTIAL_ID = "mykey_credential_id"

        /** Browsers whose WebAuthn calls are relayed with an
         * https origin. Package names come from the OS (Binder),
         * so a caller cannot spoof one. */
        private val BROWSER_PACKAGES = setOf(
            "com.android.chrome", "com.chrome.beta", "com.chrome.dev",
            "com.chrome.canary", "org.mozilla.firefox",
            "org.mozilla.firefox_beta", "com.brave.browser",
            "com.sec.android.app.sbrowser", "com.microsoft.emmx",
            "com.opera.browser", "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
        )

        /** The WebAuthn origin for a ceremony, computed honestly:
         *  - browser caller: "https://" + rpId from the request
         *    (the browser itself bound that rpId to the page origin
         *    before dispatching; package names are OS-attested);
         *  - native app caller: "android:apk-key-hash:" + base64
         *    SHA-256 of the calling app's signing certificate —
         *    the standard Android WebAuthn origin;
         *  - anything unverifiable: "" and the app refuses the
         *    ceremony (fail closed). */
        fun webAuthnOrigin(callingAppInfo: CallingAppInfo?, requestJson: String?): String {
            if (callingAppInfo == null) return ""
            if (callingAppInfo.packageName in BROWSER_PACKAGES) {
                val rpId = rpIdOf(requestJson)
                return if (rpId.isNotEmpty()) "https://$rpId" else ""
            }
            return try {
                val signers = callingAppInfo.signingInfo.apkContentsSigners
                if (signers.isEmpty()) {
                    ""
                } else {
                    val digest = java.security.MessageDigest
                        .getInstance("SHA-256")
                        .digest(signers[0].toByteArray())
                    "android:apk-key-hash:" +
                        android.util.Base64.encodeToString(
                            digest, android.util.Base64.NO_WRAP)
                }
            } catch (e: Exception) {
                ""
            }
        }

        /** rpId out of a WebAuthn request JSON, tolerating the
         * wrapped ({"publicKey": ...}) and bare shapes. */
        private fun rpIdOf(requestJson: String?): String {
            if (requestJson.isNullOrEmpty()) return ""
            return try {
                val root = org.json.JSONObject(requestJson)
                val pk = root.optJSONObject("publicKey") ?: root
                pk.optJSONObject("rp")?.optString("id")?.takeIf { it.isNotEmpty() }
                    ?: pk.optString("rpId", "")
            } catch (e: Exception) {
                ""
            }
        }
    }
}
