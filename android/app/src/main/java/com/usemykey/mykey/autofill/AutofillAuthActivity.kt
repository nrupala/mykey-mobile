// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// The dataset-authentication activity. Android starts it when the
// user taps MyKey's dataset. It shows nothing itself (translucent):
// it registers the one-shot result waiter, brings the app forward
// so the user can unlock and choose, and delivers the outcome as
// the authentication result — a real dataset on fill, a cancel
// otherwise. FLAG_SECURE: no screenshots, no recents thumbnail.
//
// If the app never answers (process death, user walks away), the
// waiter simply never fires and Android dismisses the session —
// the fail direction is always "nothing is filled".

package com.usemykey.mykey.autofill

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.service.autofill.Dataset
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.usemykey.mykey.MainActivity
import com.usemykey.mykey.R

class AutofillAuthActivity : Activity() {

    private var token: String? = null
    private var delivered = false
    private val handler = Handler(Looper.getMainLooper())
    private val timeout = Runnable {
        // Five minutes unanswered: cancel the waiter so a later
        // stray completion cannot fill a dead session.
        token?.let { AutofillPendingStore.cancelFill(it) }
        finishCanceled()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        val t = intent.getStringExtra(AutofillIntents.EXTRA_TOKEN)
        val ctx = t?.let { AutofillPendingStore.fillContext(it) }
        if (t == null || ctx == null) {
            finishCanceled()
            return
        }
        token = t

        AutofillPendingStore.router.register(t) { outcome ->
            handler.post { deliver(outcome, ctx) }
        }
        handler.postDelayed(timeout, 5 * 60 * 1000L)

        // Bring the app forward for unlock + entry choice.
        val open = Intent(this, MainActivity::class.java).apply {
            action = AutofillIntents.ACTION_FILL
            putExtra(AutofillIntents.EXTRA_TOKEN, t)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        startActivity(open)
    }

    private fun deliver(outcome: FillOutcome, ctx: FillContext) {
        if (delivered) return
        delivered = true
        handler.removeCallbacks(timeout)
        when (outcome) {
            is FillOutcome.Filled -> {
                val presentation = RemoteViews(packageName, R.layout.autofill_dataset)
                presentation.setTextViewText(R.id.autofill_title, "MyKey")
                presentation.setTextViewText(R.id.autofill_subtitle, ctx.appLabel ?: "")
                val dataset = Dataset.Builder(presentation).apply {
                    for (id in ctx.usernameIds) {
                        setValue(id, AutofillValue.forText(outcome.username), presentation)
                    }
                    for (id in ctx.passwordIds) {
                        setValue(id, AutofillValue.forText(outcome.password), presentation)
                    }
                }.build()
                val result = Intent().putExtra(
                    AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset,
                )
                setResult(RESULT_OK, result)
                finish()
            }
            FillOutcome.Canceled -> finishCanceled()
        }
    }

    private fun finishCanceled() {
        if (delivered) return
        delivered = true
        handler.removeCallbacks(timeout)
        setResult(RESULT_CANCELED)
        finish()
    }

    override fun onDestroy() {
        handler.removeCallbacks(timeout)
        if (!delivered) {
            // We are going away without an answer: free the waiter.
            token?.let { AutofillPendingStore.router.unregister(it) }
        }
        super.onDestroy()
    }
}
