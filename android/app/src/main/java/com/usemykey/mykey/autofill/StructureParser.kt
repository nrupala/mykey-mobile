// Copyright (c) 2026 2351485 ALBERTA INC. — Apache License 2.0
// (UI/platform shell; see LICENSING.md in the repository root).
//
// Walks an AssistStructure once and extracts everything the
// autofill service needs: the web domain (browser requests), the
// username/password field ids, and — for save requests — the text
// currently in those fields. Classification itself lives in
// AutofillHeuristics (pure, unit-tested).

package com.usemykey.mykey.autofill

import android.app.assist.AssistStructure
import android.view.autofill.AutofillId

data class ParsedForm(
    val webDomain: String?,
    val usernameIds: List<AutofillId>,
    val passwordIds: List<AutofillId>,
    /** Field texts by kind, first non-empty per kind (save flow). */
    val usernameText: String?,
    val passwordText: String?,
)

object StructureParser {

    fun parse(structure: AssistStructure): ParsedForm {
        var webDomain: String? = null
        val usernames = ArrayList<AutofillId>()
        val passwords = ArrayList<AutofillId>()
        var usernameText: String? = null
        var passwordText: String? = null

        fun visit(node: AssistStructure.ViewNode) {
            if (webDomain == null) {
                webDomain = node.webDomain?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
            }
            val id = node.autofillId
            if (id != null) {
                val kind = AutofillHeuristics.classify(signalsOf(node))
                val text = node.text?.toString()?.takeIf { it.isNotEmpty() }
                when (kind) {
                    FieldKind.USERNAME -> {
                        usernames.add(id)
                        if (usernameText == null) usernameText = text
                    }
                    FieldKind.PASSWORD -> {
                        passwords.add(id)
                        if (passwordText == null) passwordText = text
                    }
                    FieldKind.NONE -> Unit
                }
            }
            for (i in 0 until node.childCount) visit(node.getChildAt(i))
        }

        for (w in 0 until structure.windowNodeCount) {
            structure.getWindowNodeAt(w).rootViewNode?.let { visit(it) }
        }
        return ParsedForm(webDomain, usernames, passwords, usernameText, passwordText)
    }

    private fun signalsOf(node: AssistStructure.ViewNode): FieldSignals {
        val hints = HashSet<String>()
        node.autofillHints?.forEach { h -> hints.add(h.lowercase()) }
        // Also scan the autofill type / options? Hints are the
        // contract; html info adds web-form attributes.
        val attrs = HashMap<String, String>()
        val html = node.htmlInfo
        if (html != null && html.tag.equals("input", ignoreCase = true)) {
            html.attributes?.forEach { pair ->
                val name = pair.first?.lowercase() ?: return@forEach
                val value = pair.second?.lowercase() ?: return@forEach
                attrs[name] = value
            }
        }
        val label = listOfNotNull(
            node.hint?.toString(),
            node.contentDescription?.toString(),
        ).joinToString(" ").lowercase()
        return FieldSignals(
            hints = hints,
            viewId = node.idEntry?.lowercase() ?: "",
            inputType = node.inputType,
            htmlAttrs = attrs,
            labelText = label,
        )
    }

    /** The label the user sees for an app package ("Chrome"). */
    fun appLabel(packageManager: android.content.pm.PackageManager, packageName: String): String? =
        try {
            val info = packageManager.getApplicationInfo(packageName, 0)
            packageManager.getApplicationLabel(info).toString()
        } catch (e: Exception) {
            null
        }

    /** SHA-256 (hex) of the app's (first) signing certificate. */
    fun signingCertSha256(
        packageManager: android.content.pm.PackageManager,
        packageName: String,
    ): String? = try {
        @Suppress("DEPRECATION")
        val flags = if (android.os.Build.VERSION.SDK_INT >= 28) {
            android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            android.content.pm.PackageManager.GET_SIGNATURES
        }
        @Suppress("DEPRECATION")
        val info = packageManager.getPackageInfo(packageName, flags)
        val signatures: Array<android.content.pm.Signature>? =
            if (android.os.Build.VERSION.SDK_INT >= 28) {
                info.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION") info.signatures
            }
        signatures?.firstOrNull()?.let { CertDigest.sha256Hex(it.toByteArray()) }
    } catch (e: Exception) {
        null
    }
}
