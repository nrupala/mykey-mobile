// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// MyKey's Android AutofillService.
//
// Security shape (read before changing):
//  - The service NEVER sees decrypted vault data. It answers every
//    fill request with ONE dataset that carries NO values and an
//    authentication intent. Tapping it opens the app, which —
//    after the vault is unlocked and the user picks an entry —
//    returns the real dataset through the authentication result.
//    Nothing is filled without that tap, and nothing auto-submits.
//  - The dataset label is the only thing that varies with lock
//    state ("Unlock MyKey" vs "Fill with MyKey"). A locked vault
//    means the label is all there is: no entry names, no
//    usernames, no hints of what the vault holds.
//  - No logging anywhere in this module: nothing about a fill —
//    not the target, not the fields, not the outcome — is written
//    to logcat (CI greps this module for any logging call).
//  - The requesting app is identified by package name AND the
//    SHA-256 of its signing certificate; for browsers, by the web
//    domain Android reports for the page. Matching itself happens
//    in the app (TypeScript, unit-tested); this service supplies
//    the facts and carries out the user's choice.

package com.usemykey.mykey.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.widget.RemoteViews
import androidx.annotation.RequiresApi
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import com.usemykey.mykey.MainActivity
import com.usemykey.mykey.R

@RequiresApi(Build.VERSION_CODES.O)
class MyKeyAutofillService : AutofillService() {

    override fun onCreate() {
        super.onCreate()
        AutofillPendingStore.loadSessionHint(this)
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null) {
            callback.onSuccess(null)
            return
        }
        val parsed = StructureParser.parse(structure)
        if (parsed.usernameIds.isEmpty() && parsed.passwordIds.isEmpty()) {
            // Not a login form — stay out of the way, but still
            // offer nothing at all.
            callback.onSuccess(null)
            return
        }

        val requestPackage = structure.activityComponent?.packageName
        val isWeb = parsed.webDomain != null
        val pm = packageManager
        val appLabel = requestPackage?.let { StructureParser.appLabel(pm, it) }
        val cert = if (!isWeb && requestPackage != null) {
            StructureParser.signingCertSha256(pm, requestPackage)
        } else {
            null
        }

        val token = AutofillPendingStore.newToken()
        AutofillPendingStore.putFill(
            FillContext(
                token = token,
                packageName = if (isWeb) null else requestPackage,
                appLabel = appLabel,
                webDomain = parsed.webDomain,
                certSha256 = cert,
                usernameIds = parsed.usernameIds,
                passwordIds = parsed.passwordIds,
            ),
        )

        val presentation = datasetPresentation()
        val authIntent = Intent(this, AutofillAuthActivity::class.java)
            .putExtra(AutofillIntents.EXTRA_TOKEN, token)
        val authSender = PendingIntent.getActivity(
            this,
            token.hashCode(),
            authIntent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        ).intentSender

        val dataset = Dataset.Builder(presentation).apply {
            // Authenticated dataset: values stay null; the real
            // values arrive only via the authentication result.
            setAuthentication(authSender)
            for (id in parsed.usernameIds + parsed.passwordIds) {
                setValue(id, null, presentation)
            }
        }

        // Inline presentation (keyboard strip), Android 11+.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val inlineRequest = request.inlineSuggestionsRequest
            val spec = inlineRequest?.inlinePresentationSpecs?.firstOrNull()
            if (inlineRequest != null && spec != null &&
                inlineRequest.maxSuggestionCount > 0
            ) {
                buildInlinePresentation(spec, authIntent, token)?.let { inline ->
                    dataset.setInlinePresentation(inline)
                }
            }
        }

        val response = FillResponse.Builder().apply {
            addDataset(dataset.build())
            if (parsed.passwordIds.isNotEmpty()) {
                val saveInfo = SaveInfo.Builder(
                    SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                    parsed.passwordIds.toTypedArray(),
                )
                if (parsed.usernameIds.isNotEmpty()) {
                    saveInfo.setOptionalIds(parsed.usernameIds.toTypedArray())
                }
                setSaveInfo(saveInfo.build())
            }
        }
        callback.onSuccess(response.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        val parsed = structure?.let { StructureParser.parse(it) }
        val password = parsed?.passwordText
        if (structure != null && parsed != null && !password.isNullOrEmpty()) {
            val requestPackage = structure.activityComponent?.packageName
            val isWeb = parsed.webDomain != null
            val pm = packageManager
            val token = AutofillPendingStore.newToken()
            AutofillPendingStore.putSave(
                SaveContext(
                    token = token,
                    packageName = if (isWeb) null else requestPackage,
                    appLabel = requestPackage?.let { StructureParser.appLabel(pm, it) },
                    webDomain = parsed.webDomain,
                    certSha256 = if (!isWeb && requestPackage != null) {
                        StructureParser.signingCertSha256(pm, requestPackage)
                    } else {
                        null
                    },
                    username = parsed.usernameText ?: "",
                    password = password,
                ),
            )
            // Route into the app for the user's confirmation. The
            // values stay here (memory only) until the app asks.
            val intent = Intent(this, MainActivity::class.java).apply {
                action = AutofillIntents.ACTION_SAVE
                putExtra(AutofillIntents.EXTRA_TOKEN, token)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        }
        // Always success: Android considers the credentials saved
        // by us. If the user declines in the app, nothing is kept —
        // the in-memory context is dropped on their tap.
        callback.onSuccess()
    }

    /** The dropdown presentation. Icon + two text lines, never
     * any entry data: title is the lock-state label, subtitle the
     * instruction. */
    private fun datasetPresentation(): RemoteViews {
        val now = System.currentTimeMillis()
        val views = RemoteViews(packageName, R.layout.autofill_dataset)
        views.setTextViewText(R.id.autofill_title, AutofillPendingStore.sessionHint.label(now))
        views.setTextViewText(R.id.autofill_subtitle, AutofillPendingStore.sessionHint.subtitle(now))
        return views
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun buildInlinePresentation(
        spec: android.widget.inline.InlinePresentationSpec,
        authIntent: Intent,
        token: String,
    ): InlinePresentation? {
        if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) {
            return null
        }
        val now = System.currentTimeMillis()
        val attribution = PendingIntent.getActivity(
            this,
            token.hashCode(),
            authIntent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val content = InlineSuggestionUi.newContentBuilder(attribution)
            .setTitle(AutofillPendingStore.sessionHint.label(now))
            .setSubtitle(AutofillPendingStore.sessionHint.subtitle(now))
            .setContentDescription("MyKey autofill")
            .build()
        val slice = content.slice ?: return null
        return InlinePresentation(slice, spec, false)
    }
}
